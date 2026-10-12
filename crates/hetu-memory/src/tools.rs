//! MCP 工具面:三个工具的定义与执行。
//!
//! 寄生纪律:只提供 codex 记忆没有的——语义/词法混合检索(它的 search
//! 是朴素子串且语料被归并压小)、情景检索(按时间+关键词找会话)、全景
//! 洞察。新鲜度:工具调用前比对语料指纹,变更即重建词法层(毫秒级)。

use crate::corpus;
use crate::embed::{blend, cosine, text_hash, EmbedClient, VectorCache};
use crate::index::{chunks_from_markdown, chunks_from_session, Chunk, Index};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// 检索面缺省 Top-K。
const DEFAULT_TOP_K: usize = 8;
/// 混合评分的词法召回池大小。
const CANDIDATE_POOL: usize = 50;
/// 单条嵌入输入上限(字符)。
const EMBED_INPUT_MAX_CHARS: usize = 1000;

pub struct MemoryService {
    corpus_root: PathBuf,
    embed_client: Option<EmbedClient>,
    state: Mutex<ServiceState>,
}

struct ServiceState {
    index: Index,
    overview_sources: Vec<SourceStat>,
    fingerprint: u64,
    vectors: VectorCache,
}

struct SourceStat {
    label: String,
    chunks: usize,
    bytes: usize,
}

impl MemoryService {
    /// 从 corpus root 构建(启动时一次;其后按指纹惰性重建)。
    pub fn build(corpus_root: &Path) -> Self {
        let vectors_path = vector_cache_path(corpus_root);
        let mut state = ServiceState {
            index: Index::build(Vec::new()),
            overview_sources: Vec::new(),
            fingerprint: u64::MAX, // 下面立即做首次刷新
            vectors: VectorCache::load(vectors_path),
        };
        let (index, overview_sources) = build_index_and_stats(corpus_root, &mut state.vectors);
        state.index = index;
        state.overview_sources = overview_sources;
        state.fingerprint = corpus_fingerprint(corpus_root);
        Self {
            corpus_root: corpus_root.to_path_buf(),
            embed_client: EmbedClient::from_env(corpus_root),
            state: Mutex::new(state),
        }
    }

    /// 索引块计数(启动横幅)。注意:不触发刷新,反映的是当前已建层。
    pub fn total_chunks(&self) -> usize {
        self.state.lock().map(|s| s.index.len()).unwrap_or(0)
    }

    pub fn tool_definitions(&self) -> Value {
        json!([
            {
                "name": "memory_overview",
                "description": "Inventory of the hetu long-memory store: sources, chunk counts, sizes, date coverage. Use to see what memory exists before searching.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "semantic_search",
                "description": "Hybrid (semantic + lexical) search over ALL local codex sessions and memory artifacts, incl. session details never consolidated into codex memories. Chinese and English both work. Returns chunks with source id and date.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Keywords or a natural-language phrase" },
                        "top_k": { "type": "integer", "description": "Max results (default 8)" }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "memory_context",
                "description": "Read the persistent long-memory (MEMORY = project/agent notes; USER = user profile). Call this at session start before answering anything that may benefit from prior context.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "memory_write",
                "description": "Persist a durable fact to long-memory. op=add (new entry), replace (old_text + content), remove (old_text). target=memory (agent notes) or user (user profile). Content is threat-scanned; files are budget-limited.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": { "type": "string", "enum": ["memory", "user"] },
                        "op": { "type": "string", "enum": ["add", "replace", "remove"] },
                        "content": { "type": "string" },
                        "old_text": { "type": "string", "description": "unique substring of the entry to replace/remove" }
                    },
                    "required": ["target", "op"]
                }
            },
            {
                "name": "episodic_search",
                "description": "Find past codex sessions by time window plus optional keywords. Returns session-level summaries (id, date, cwd, first user message).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "days_back": { "type": "integer", "description": "Only sessions within this many days (default: all)" },
                        "keywords": { "type": "string", "description": "Optional keywords to filter sessions" }
                    }
                }
            }
        ])
    }

    pub fn call_tool(&self, name: &str, args: &Value) -> Result<Value, String> {
        match name {
            "memory_overview" => self.with_fresh(|state| Ok(overview_of(state))),
            "semantic_search" => self.with_fresh(|state| semantic_search_of(state, &self.embed_client, args)),
            "episodic_search" => episodic_search(&self.corpus_root, args),
            other => Err(format!("unknown tool: {other}")),
        }
    }

    /// 指纹门:语料变了才重建词法层,随后执行工具体。
    fn with_fresh<T>(
        &self,
        body: impl FnOnce(&mut ServiceState) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| "hetu-memory: state mutex poisoned".to_string())?;
        let fingerprint = corpus_fingerprint(&self.corpus_root);
        if fingerprint != guard.fingerprint {
            guard.index = Index::build(Vec::new());
            let fresh = build_index_and_stats(&self.corpus_root, &mut guard.vectors);
            guard.index = fresh.0;
            guard.overview_sources = fresh.1;
            guard.fingerprint = fingerprint;
        }
        body(&mut guard)
    }
}

fn overview_of(state: &ServiceState) -> Value {
    let sources: Vec<Value> = state
        .overview_sources
        .iter()
        .map(|s| json!({ "source": s.label, "chunks": s.chunks, "bytes": s.bytes }))
        .collect();
    json!({
        "total_chunks": state.index.len(),
        "vectors_cached": state.vectors.len(),
        "sources": sources,
        "note": "hybrid lexical+semantic index",
    })
}

fn semantic_search_of(
    state: &mut ServiceState,
    embed_client: &Option<EmbedClient>,
    args: &Value,
) -> Result<Value, String> {
    let query = args
        .get("query")
        .and_then(|q| q.as_str())
        .ok_or("missing required argument: query")?;
    let top_k = args
        .get("top_k")
        .and_then(|k| k.as_u64())
        .map(|k| k as usize)
        .unwrap_or(DEFAULT_TOP_K)
        .clamp(1, 50);

    // 词法召回(保底)。
    let lexical_hits = state.index.search(query, CANDIDATE_POOL);
    let lexical_max = lexical_hits
        .first()
        .map(|(_, s)| *s)
        .filter(|s| *s > 0.0)
        .unwrap_or(1.0);
    let mut candidates: HashMap<usize, (f64, f64)> = HashMap::new(); // ix -> (semantic, lexical_norm)
    for (ix, score) in &lexical_hits {
        candidates.insert(*ix, (0.0, score / lexical_max));
    }

    // 语义召回(换词命中的关键);任何失败 fail-open 退词法。
    if let Some(client) = embed_client {
        ensure_vectors(state, client);
        let query_input = truncate_for_embed(query);
        match client.embed(std::slice::from_ref(&query_input)) {
            Ok(query_vectors) => {
                if let Some(query_vector) = query_vectors.first() {
                    for ix in 0..state.index.len() {
                        let text = state.index.chunk(ix).text.clone();
                        if let Some(vector) = state.vectors.get(&text) {
                            let semantic = cosine(query_vector, vector) as f64;
                            candidates.entry(ix).or_insert((0.0, 0.0)).0 = semantic;
                        }
                    }
                }
            }
            Err(error) => {
                eprintln!("hetu-memory: query embedding failed, lexical-only ({error})")
            }
        }
    }

    let mut ranked: Vec<(usize, f64)> = candidates
        .into_iter()
        .map(|(ix, (semantic, lexical))| (ix, blend(semantic, lexical)))
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    ranked.truncate(top_k);

    let results: Vec<Value> = ranked
        .iter()
        .map(|(ix, score)| {
            let chunk = state.index.chunk(*ix);
            json!({
                "score": (score * 1000.0).round() / 1000.0,
                "source_id": chunk.source_id,
                "label": chunk.label,
                "date": chunk.ts,
                "text": chunk.text,
            })
        })
        .collect();
    Ok(json!({ "query": query, "matches": results.len(), "results": results }))
}

/// 情景检索:会话级直读(不经过块索引;窗口+关键词双闸)。
fn episodic_search(corpus_root: &Path, args: &Value) -> Result<Value, String> {
    let days_back = args.get("days_back").and_then(|d| d.as_u64());
    let keywords = args
        .get("keywords")
        .and_then(|k| k.as_str())
        .unwrap_or_default();
    let mut sessions = corpus::read_all_sessions(corpus_root);
    sessions.sort_by(|a, b| b.ts.cmp(&a.ts));
    let mut results = Vec::new();
    for session in sessions {
        if let Some(days) = days_back && !within_days(&session.ts, days) {
            continue;
        }
        let full = session.full_text();
        if !keywords.trim().is_empty() && !contains_all(&full, keywords) {
            continue;
        }
        let first_user = session
            .entries
            .iter()
            .find(|e| e.kind == crate::corpus::EntryKind::User)
            .map(|e| truncate_for_embed(e.text.trim()))
            .unwrap_or_default();
        results.push(json!({
            "session_id": session.id,
            "date": session.ts,
            "cwd": session.cwd,
            "entries": session.entries.len(),
            "first_user_message": first_user,
            "file": session.source_file.display().to_string(),
        }));
        if results.len() >= 20 {
            break;
        }
    }
    Ok(json!({ "matches": results.len(), "sessions": results }))
}

/// 补嵌缺失向量(嵌入失败 = 静默退词法,eprintln 留观测)。
fn ensure_vectors(state: &mut ServiceState, client: &EmbedClient) {
    let missing: Vec<String> = (0..state.index.len())
        .filter(|ix| {
            let text = state.index.chunk(*ix).text.clone();
            !state.vectors.has(&text)
        })
        .map(|ix| truncate_for_embed(&state.index.chunk(ix).text.clone()))
        .collect();
    if missing.is_empty() {
        return;
    }
    match client.embed(&missing) {
        Ok(vectors) => {
            for (text, vector) in missing.iter().zip(vectors) {
                state.vectors.put(text, vector);
            }
            state.vectors.flush();
        }
        Err(error) => eprintln!("hetu-memory: embedding unavailable, lexical-only ({error})"),
    }
}

fn truncate_for_embed(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= EMBED_INPUT_MAX_CHARS {
        trimmed.to_string()
    } else {
        trimmed.chars().take(EMBED_INPUT_MAX_CHARS).collect()
    }
}

fn contains_all(haystack: &str, keywords: &str) -> bool {
    keywords
        .split_whitespace()
        .all(|kw| haystack.to_lowercase().contains(&kw.to_lowercase()))
}

/// days_back 的窗口判定:极简 YYYY-MM-DD → 近似天数(仅窗口比较用,
/// 同刻度自洽)。
fn within_days(ts: &str, days: u64) -> bool {
    let Some(date_part) = ts.get(0..10) else {
        return true;
    };
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(now) => {
            let today_days = (now.as_secs() / 86_400) as i64;
            let ts_days = parse_date_to_days(date_part).unwrap_or(today_days);
            (today_days - ts_days).abs() <= days as i64
        }
        Err(_) => true,
    }
}

fn parse_date_to_days(date: &str) -> Option<i64> {
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    Some(days_from_civil(year, month, day))
}

/// Howard Hinnant 的 days_from_civil(公历 → 自 1970-01-01 天数),无历
/// 法依赖、无近似。
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// 语料指纹:rollouts + memories md + history 的 (路径, mtime, len) 哈希。
pub fn corpus_fingerprint(root: &Path) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    let mut paths = vec![root.join("history.jsonl"), root.join("memories")];
    paths.extend(corpus::collect_rollouts(root));
    for path in paths {
        hash = hash.wrapping_mul(0x100000001b3);
        hash ^= text_hash(&path.display().to_string());
        if let Ok(meta) = std::fs::metadata(&path) {
            if let Ok(modified) = meta.modified() {
                if let Ok(since) = modified.duration_since(std::time::UNIX_EPOCH) {
                    hash ^= since.as_millis() as u64;
                }
            }
            hash ^= meta.len();
        }
    }
    hash
}

/// (重)建词法层索引与源清单;向量缓存跨重建保留(按文本哈希)。
fn build_index_and_stats(corpus_root: &Path, vectors: &mut VectorCache) -> (Index, Vec<SourceStat>) {
    let _ = vectors; // 缓存所有权留在 ServiceState,此处只读路径提示
    let mut chunks: Vec<Chunk> = Vec::new();
    let mut overview_sources: Vec<SourceStat> = Vec::new();
    for session in corpus::read_all_sessions(corpus_root) {
        let session_chunks = chunks_from_session(&session);
        if !session_chunks.is_empty() {
            overview_sources.push(SourceStat {
                label: format!("session {} ({})", session.id, short_ts(&session.ts)),
                chunks: session_chunks.len(),
                bytes: session.full_text().len(),
            });
            chunks.extend(session_chunks);
        }
    }
    for (label, text) in corpus::read_memory_markdowns(&corpus_root.join("memories")) {
        let md_chunks = chunks_from_markdown(&label, &text);
        if !md_chunks.is_empty() {
            overview_sources.push(SourceStat {
                label: format!("memory md {label}"),
                chunks: md_chunks.len(),
                bytes: text.len(),
            });
            chunks.extend(md_chunks);
        }
    }
    let history_path = corpus_root.join("history.jsonl");
    if let Ok(history) = std::fs::read_to_string(&history_path) {
        let mut history_chunks = Vec::new();
        for line in history.lines() {
            let Ok(value) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let text = value
                .get("text")
                .and_then(|t| t.as_str())
                .unwrap_or_default();
            let ts = value.get("ts").and_then(|t| t.as_str()).unwrap_or_default();
            if text.trim().is_empty() {
                continue;
            }
            history_chunks.push(Chunk {
                source_id: "history.jsonl".to_string(),
                label: format!("user prompt ({})", short_ts(ts)),
                ts: ts.to_string(),
                cwd: String::new(),
                text: crate::corpus::redact(text),
            });
        }
        if !history_chunks.is_empty() {
            overview_sources.push(SourceStat {
                label: "history.jsonl (user prompts)".to_string(),
                chunks: history_chunks.len(),
                bytes: history.len(),
            });
            chunks.extend(history_chunks);
        }
    }
    overview_sources.sort_by(|a, b| b.chunks.cmp(&a.chunks));
    (Index::build(chunks), overview_sources)
}

fn vector_cache_path(corpus_root: &Path) -> PathBuf {
    corpus_root.join("hetu-memory").join("vectors.json")
}

#[cfg(test)]
fn now_epoch_days_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86_400) as i64)
        .unwrap_or_default()
}

/// Hinnant civil_from_days(days_from_civil 的逆,测试夹具生成日期用)。
#[cfg(test)]
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn short_ts(ts: &str) -> &str {
    ts.get(0..10).unwrap_or(ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_changes_when_corpus_grows() {
        let dir = std::env::temp_dir().join(format!("hetu-fp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let before = corpus_fingerprint(&dir);
        std::fs::write(
            dir.join("sessions"),
            "",
        )
        .ok();
        let sessions = dir.join("s/rollout-x.jsonl");
        std::fs::create_dir_all(sessions.parent().unwrap()).unwrap();
        std::fs::write(&sessions, "{}\n").unwrap();
        let after = corpus_fingerprint(&dir);
        assert_ne!(before, after);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn episodic_filters_by_days_and_keywords() {
        // 真日期无关:A = 昨天,B = 60 天前(夹具按运行时刻生成 RFC3339)。
        let dir = std::env::temp_dir().join(format!("hetu-ep-{}", std::process::id()));
        let now_days = now_epoch_days_i64();
        let rfc3339 = |days: i64| {
            let (y, m, d) = civil_from_days(days);
            format!("{y:04}-{m:02}-{d:02}T00:00:00Z")
        };
        let recent_ts = rfc3339(now_days - 1);
        let old_ts = rfc3339(now_days - 60);
        let write_session = |sub: &str, id: &str, ts: &str, text: &str| {
            let path = dir.join(sub);
            std::fs::create_dir_all(&path).unwrap();
            let meta = json!({
                "type": "session_meta",
                "payload": { "session_id": id, "timestamp": ts, "cwd": "/p" }
            });
            let item = json!({
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{ "text": text }]
                }
            });
            std::fs::write(
                path.join(format!("rollout-{id}.jsonl")),
                format!("{meta}\n{item}\n"),
            )
            .unwrap();
        };
        write_session("sessions/a", "net", &recent_ts, "网络问题");
        write_session("sessions/b", "db", &old_ts, "数据库迁移");
        let r3 = episodic_search(&dir, &json!({ "days_back": 3 })).unwrap();
        assert_eq!(r3["matches"], 1, "3 天窗只含 A(B 是 60 天前)");
        assert_eq!(r3["sessions"][0]["session_id"], "net");
        let r3k = episodic_search(&dir, &json!({ "days_back": 365, "keywords": "网络" }))
            .unwrap();
        assert_eq!(r3k["matches"], 1, "关键词过滤只留 A");
        let r0 = episodic_search(&dir, &json!({ "days_back": 0 })).unwrap();
        assert_eq!(r0["matches"], 0, "0 天窗连昨天也不含");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
