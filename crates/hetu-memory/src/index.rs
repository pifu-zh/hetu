//! 分块 + 词法检索索引。
//!
//! v0 评分:IDF 加权的词法重叠(ASCII 按词、CJK 按字二元),按块取 Top-K。
//! 结构上为向量检索留位(Chunk 与 Scorer 分离,替换 Scorer 即可换语义
//! 评分,不动语料层)。

use crate::corpus::{EntryKind, Session};
use std::collections::HashMap;

/// 一个可检索单元。
#[derive(Debug, Clone, PartialEq)]
pub struct Chunk {
    /// 会话 id 或 markdown 相对标签。
    pub source_id: String,
    /// 人读出处:会话 = 首行角色;md = 文件标签+行号起点。
    pub label: String,
    /// RFC3339 或空(md 工件无时间)。
    pub ts: String,
    pub cwd: String,
    pub text: String,
}

/// 块上限(字符):超长条目切多条,检索粒度稳定。
const CHUNK_MAX_CHARS: usize = 1200;

/// 从会话建块:每条目一块,超长按段落二切(简单贪心)。
pub fn chunks_from_session(session: &Session) -> Vec<Chunk> {
    let mut out = Vec::new();
    for entry in &session.entries {
        let role_label = match entry.kind {
            EntryKind::User => "user",
            EntryKind::Assistant => "assistant",
            EntryKind::ToolCall => "tool",
        };
        for piece in split_long(&entry.text) {
            out.push(Chunk {
                source_id: session.id.clone(),
                label: format!("{}({})", role_label, short_date(&session.ts)),
                ts: session.ts.clone(),
                cwd: session.cwd.clone(),
                text: piece,
            });
        }
    }
    out
}

/// 从 markdown 工件建块(按空行分段,保留标签与近似行号)。
pub fn chunks_from_markdown(label: &str, text: &str) -> Vec<Chunk> {
    let mut out = Vec::new();
    let mut line_no = 1usize;
    for para in text.split("\n\n") {
        let trimmed = para.trim();
        if trimmed.is_empty() || is_meta_placeholder(trimmed) || is_heading_only(trimmed) {
            line_no += para.lines().count() + 1;
            continue;
        }
        for piece in split_long(trimmed) {
            out.push(Chunk {
                source_id: label.to_string(),
                label: format!("{label}:{line_no}"),
                ts: String::new(),
                cwd: String::new(),
                text: piece,
            });
        }
        line_no += para.lines().count() + 1;
    }
    out
}

/// codex 空语料的诚实占位("No raw memories yet.")不索引——独立句或
/// 标题带句两种形态;纯标题段落(无正文)同为噪音不索引。
fn is_meta_placeholder(text: &str) -> bool {
    let lowered = text.to_lowercase();
    lowered.contains("no raw memories yet")
        || (lowered.starts_with('#') && lowered.contains("no ") && lowered.contains("yet"))
}

fn is_heading_only(text: &str) -> bool {
    text.starts_with('#') && text.lines().count() == 1
}

fn split_long(text: &str) -> Vec<String> {
    let trimmed = text.trim();
    if trimmed.chars().count() <= CHUNK_MAX_CHARS {
        return if trimmed.is_empty() {
            Vec::new()
        } else {
            vec![trimmed.to_string()]
        };
    }
    let mut out = Vec::new();
    let mut current = String::new();
    for para in trimmed.split_inclusive('\n') {
        if current.chars().count() + para.chars().count() > CHUNK_MAX_CHARS && !current.is_empty()
        {
            out.push(current.trim().to_string());
            current.clear();
        }
        current.push_str(para);
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }
    out
}

fn short_date(ts: &str) -> &str {
    ts.get(0..10).unwrap_or(ts)
}

/// 分词:ASCII 词小写;CJK 连续段按字 + 相邻字二元(保语义粒度)。
pub fn tokenize(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut ascii_word = String::new();
    let mut cjk_run: Vec<char> = Vec::new();
    macro_rules! flush_ascii {
        () => {
            if !ascii_word.is_empty() {
                tokens.push(ascii_word.to_lowercase());
                ascii_word.clear();
            }
        };
    }
    macro_rules! flush_cjk {
        () => {
            if cjk_run.len() == 1 {
                tokens.push(cjk_run[0].to_string());
            } else {
                for window in cjk_run.windows(2) {
                    tokens.push(window.iter().collect::<String>());
                }
            }
            cjk_run.clear();
        };
    }
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            flush_cjk!();
            ascii_word.push(ch);
        } else if is_cjk(ch) {
            flush_ascii!();
            cjk_run.push(ch);
        } else {
            flush_ascii!();
            flush_cjk!();
        }
    }
    flush_ascii!();
    flush_cjk!();
    tokens
}

fn is_cjk(ch: char) -> bool {
    matches!(ch as u32,
        0x4E00..=0x9FFF | 0x3400..=0x4DBF | 0xF900..=0xFAFF | 0x3000..=0x303F)
}

/// 倒排索引 + IDF 评分。构建 O(语料),查询 O(命中块)。
pub struct Index {
    chunks: Vec<Chunk>,
    /// token -> 出现过的块下标集合。
    postings: HashMap<String, Vec<usize>>,
}

impl Index {
    pub fn build(chunks: Vec<Chunk>) -> Self {
        let mut postings: HashMap<String, Vec<usize>> = HashMap::new();
        for (ix, chunk) in chunks.iter().enumerate() {
            for token in unique_tokens(&tokenize(&chunk.text)) {
                postings.entry(token).or_default().push(ix);
            }
        }
        Self { chunks, postings }
    }

    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Top-K 检索。评分 = 查询词 IDF 之和 × 覆盖率;零命中返回空。
    pub fn search(&self, query: &str, top_k: usize) -> Vec<(usize, f64)> {
        let query_tokens = unique_tokens(&tokenize(query));
        if query_tokens.is_empty() || self.chunks.is_empty() {
            return Vec::new();
        }
        let total = self.chunks.len() as f64;
        let mut scores: HashMap<usize, f64> = HashMap::new();
        for token in &query_tokens {
            let Some(posting) = self.postings.get(token) else {
                continue;
            };
            // IDF:log(总块数/命中块数),全语料都有的词权重趋零。
            let idf = (total / posting.len() as f64).ln().max(0.05);
            for &ix in posting {
                *scores.entry(ix).or_default() += idf;
            }
        }
        let mut ranked: Vec<(usize, f64)> = scores
            .into_iter()
            .map(|(ix, score)| {
                let coverage = {
                    let chunk_tokens = unique_tokens(&tokenize(&self.chunks[ix].text));
                    let hit = query_tokens
                        .iter()
                        .filter(|q| chunk_tokens.contains(q))
                        .count();
                    hit as f64 / query_tokens.len() as f64
                };
                (ix, score * (0.5 + coverage))
            })
            .collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked.truncate(top_k);
        ranked
    }

    pub fn chunk(&self, ix: usize) -> &Chunk {
        &self.chunks[ix]
    }
}

fn unique_tokens(tokens: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for token in tokens {
        if seen.insert(token.clone()) {
            out.push(token.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_mixes_ascii_words_and_cjk_bigrams() {
        let tokens = tokenize("修复 DNS 解析");
        assert!(tokens.contains(&"dns".to_string()));
        assert!(tokens.contains(&"修复".to_string()));
        assert!(tokens.contains(&"解析".to_string()));
        // 单字不成对时保字。
        let single = tokenize("网");
        assert_eq!(single, vec!["网".to_string()]);
    }

    #[test]
    fn search_ranks_relevant_chunk_first_and_handles_cjk_query() {
        let chunks = vec![
            Chunk {
                source_id: "s1".into(),
                label: "user(2026-10-07)".into(),
                ts: "2026-10-07".into(),
                cwd: "/x".into(),
                text: "请帮我分析本地糟糕的网络问题".into(),
            },
            Chunk {
                source_id: "s2".into(),
                label: "assistant(2026-10-01)".into(),
                ts: "2026-10-01".into(),
                cwd: "/x".into(),
                text: "记忆系统的向量检索采用分层索引".into(),
            },
        ];
        let index = Index::build(chunks);
        let hits = index.search("本地 网络问题 DNS", 2);
        assert!(!hits.is_empty());
        assert_eq!(index.chunk(hits[0].0).source_id, "s1");
        // 无关查询不强行返回:语义无关块的覆盖率惩罚后仍可能垫底,但
        // 完全零词命中必为空。
        let misses = index.search("量子计算机", 2);
        assert!(misses.is_empty());
    }

    #[test]
    fn markdown_chunks_skip_placeholder_and_carry_line_numbers() {
        let chunks = chunks_from_markdown(
            "raw_memories.md",
            "# Raw Memories\n\nNo raw memories yet.\n\n## 2026-10-07\n\n修好了 build 脚本",
        );
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].text, "修好了 build 脚本");
        assert!(chunks[0].label.starts_with("raw_memories.md:"));
    }

    #[test]
    fn long_text_splits_into_bounded_chunks() {
        let long = "内容\n".repeat(800);
        let chunks = split_long(long.trim());
        assert!(chunks.len() >= 2);
        assert!(chunks.iter().all(|c| c.chars().count() <= 1200));
    }
}
