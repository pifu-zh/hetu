//! 语料读取器:把 codex 的本地工件(rollout jsonl、history.jsonl、
//! memories/*.md)读成统一的会话/条目记录。
//!
//! 纪律:只读;样板过滤(environment_context/app-context 等)在此层做,
//! 索引层拿到的即是干净语料。

use std::fs;
use std::path::{Path, PathBuf};

/// 秘密擦除(读入口,索引永不接触原始秘密)。形态表:
/// - sk- 前缀 API key、Bearer 令牌、hex 长串(含 zhipu 的 id.secret 形)
/// - api_key/token/secret/password/authorization 赋值行(保键名,抹值)
/// 误报代价:正常句子里 32+ 位 hex 被抹——罕见且无检索损失。
pub fn redact(text: &str) -> String {
    use regex::Regex;
    static PATTERNS: std::sync::OnceLock<Vec<Regex>> = std::sync::OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        [
            r"(?i)\bsk-[A-Za-z0-9_-]{16,}",
            r"\bBearer\s+[A-Za-z0-9._/-]{16,}",
            r"(?i)\b[0-9a-f]{24,}\.[A-Za-z0-9]{8,}",
            r"(?i)\b[0-9a-f]{32,}\b",
            r#"(?i)((?:api[_-]?key|secret|password|token|experimental_bearer_token|authorization)\s*[=:]\s*)(["']?)[A-Za-z0-9._/+\-]{12,}(["']?)"#,
        ]
        .into_iter()
        .map(|p| Regex::new(p).expect("redact pattern must compile"))
        .collect()
    });
    let mut out = text.to_string();
    for pattern in patterns {
        out = pattern
            .replace_all(&out, "${1}[REDACTED]")
            .to_string();
    }
    out
}

/// 一条语料条目(已滤样板)。
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub kind: EntryKind,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    User,
    Assistant,
    ToolCall,
}

/// 一个会话(一次 rollout)的投影。
#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    pub id: String,
    /// RFC3339 时间戳(取 session_meta)。
    pub ts: String,
    pub cwd: String,
    pub source_file: PathBuf,
    pub entries: Vec<Entry>,
}

impl Session {
    /// 拼接全文(索引分块的输入)。
    pub fn full_text(&self) -> String {
        self.entries
            .iter()
            .map(|e| e.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// 样板前缀:开发者/环境注入,非用户语料。
const BOILERPLATE_PREFIXES: [&str; 4] = [
    "<environment_context>",
    "<app-context>",
    "<codex_apps_client_time_context>",
    "<user_instructions>",
];

fn is_boilerplate(text: &str) -> bool {
    let trimmed = text.trim_start();
    BOILERPLATE_PREFIXES
        .iter()
        .any(|p| trimmed.starts_with(p))
}

/// 从一个 rollout jsonl 文件读会话。解析失败的行跳过(jsonl 容错纪律)。
pub fn read_rollout(path: &Path) -> Option<Session> {
    let raw = fs::read_to_string(path).ok()?;
    let mut id = String::new();
    let mut ts = String::new();
    let mut cwd = String::new();
    let mut entries = Vec::new();
    for line in raw.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        match value.get("type").and_then(|t| t.as_str()) {
            Some("session_meta") => {
                let payload = value.get("payload").cloned().unwrap_or_default();
                id = str_field(&payload, &["session_id"]).unwrap_or_default();
                ts = str_field(&payload, &["timestamp"]).unwrap_or_default();
                cwd = str_field(&payload, &["cwd"]).unwrap_or_default();
            }
            Some("response_item") => {
                if let Some(item) = read_response_item(value.get("payload")) {
                    entries.push(item);
                }
            }
            _ => {}
        }
    }
    if id.is_empty() {
        return None;
    }
    Some(Session {
        id,
        ts,
        cwd,
        source_file: path.to_path_buf(),
        entries,
    })
}

fn read_response_item(payload: Option<&serde_json::Value>) -> Option<Entry> {
    let payload = payload?;
    match payload.get("type").and_then(|t| t.as_str())? {
        "message" => {
            let role = payload.get("role").and_then(|r| r.as_str())?;
            let text = content_text(payload);
            if text.trim().is_empty() || is_boilerplate(&text) {
                return None;
            }
            let kind = match role {
                "user" => EntryKind::User,
                "assistant" => EntryKind::Assistant,
                _ => return None,
            };
            Some(Entry { kind, text: redact(&text) })
        }
        "function_call" => {
            let name = payload
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or_default();
            if name.is_empty() {
                return None;
            }
            Some(Entry {
                kind: EntryKind::ToolCall,
                text: format!("tool call: {name}"),
            })
        }
        _ => None,
    }
}

fn content_text(payload: &serde_json::Value) -> String {
    let mut out = String::new();
    if let Some(content) = payload.get("content").and_then(|c| c.as_array()) {
        for piece in content {
            if let Some(text) = piece.get("text").and_then(|t| t.as_str()) {
                out.push_str(text);
            }
        }
    }
    out
}

fn str_field(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| value.get(*k).and_then(|v| v.as_str()))
        .map(|s| s.to_string())
}

/// 递归收集 corpus root 下的全部 rollout 文件(sessions/YYYY/MM/DD 与
/// archived_sessions 平级对待)。
pub fn collect_rollouts(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rollouts_dir(root, &mut out, 0);
    out.sort();
    out
}

fn collect_rollouts_dir(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 6 {
        return;
    }
    let Ok(read_dir) = fs::read_dir(dir) else {
        return;
    };
    for item in read_dir.flatten() {
        let path = item.path();
        if path.is_dir() {
            collect_rollouts_dir(&path, out, depth + 1);
        } else if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("rollout-") && n.ends_with(".jsonl"))
        {
            out.push(path);
        }
    }
}

/// 读全部会话(失败/缺 id 的文件静默跳过——观测面 fail-open)。
pub fn read_all_sessions(root: &Path) -> Vec<Session> {
    collect_rollouts(root)
        .iter()
        .filter_map(|p| read_rollout(p))
        .collect()
}

/// memories/ 下的 Markdown 工件(raw_memories.md、memory_summary.md、
/// MEMORY.md、rollout_summaries/*、ad_hoc_notes/*)——codex 归并管线的
/// 正式产物。返回 (相对标签, 全文)。
pub fn read_memory_markdowns(memories_dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    collect_markdowns(memories_dir, "", &mut out, 0);
    out.sort();
    out
}

fn collect_markdowns(dir: &Path, prefix: &str, out: &mut Vec<(String, String)>, depth: usize) {
    if depth > 4 {
        return;
    }
    let Ok(read_dir) = fs::read_dir(dir) else {
        return;
    };
    for item in read_dir.flatten() {
        let path = item.path();
        let name = item
            .file_name()
            .to_string_lossy()
            .trim()
            .to_string();
        if path.is_dir() {
            let sub = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            collect_markdowns(&path, &sub, out, depth + 1);
        } else if name.ends_with(".md")
            && let Ok(text) = fs::read_to_string(&path)
        {
            let label = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            out.push((label, text));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn rollout_parser_extracts_messages_and_filters_boilerplate() {
        let dir = std::env::temp_dir().join(format!("hetu-mem-test-{}", std::process::id()));
        let path = dir.join("rollout-2026-10-07T00-00-00-aaa.jsonl");
        write(
            &path,
            concat!(
                r#"{"type":"session_meta","payload":{"session_id":"s-1","timestamp":"2026-10-07T01:00:00Z","cwd":"/tmp/proj"}}"#,
                "\n",
                r#"{"type":"response_item","payload":{"type":"message","role":"user","content":[{"text":"<environment_context><cwd>/x</cwd></environment_context>"}]}}"#,
                "\n",
                r#"{"type":"response_item","payload":{"type":"message","role":"user","content":[{"text":"帮我修 DNS"}]}}"#,
                "\n",
                r#"{"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"text":"DNS 配置为空"}]}}"#,
                "\n",
                r#"{"type":"response_item","payload":{"type":"function_call","name":"exec_command"}}"#,
                "\n",
                "not json\n",
                r#"{"type":"event_msg","payload":{}}"#,
                "\n",
            ),
        );
        let session = read_rollout(&path).expect("session parsed");
        assert_eq!(session.id, "s-1");
        assert_eq!(session.cwd, "/tmp/proj");
        assert_eq!(session.entries.len(), 3);
        assert_eq!(session.entries[0].kind, EntryKind::User);
        assert_eq!(session.entries[0].text, "帮我修 DNS");
        assert_eq!(session.entries[1].kind, EntryKind::Assistant);
        assert_eq!(session.entries[2].kind, EntryKind::ToolCall);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn redact_kills_known_secret_shapes_but_keeps_prose() {
        let zhipu_style = "token 是 deadbeefcafe0123456789abcdef0123456789ab.samplesecretNOTREAL 请收好";
        let redacted = redact(zhipu_style);
        assert!(!redacted.contains("deadbeefcafe"));
        assert!(redacted.contains("[REDACTED]"));
        assert!(redact("sk-abcdefghijklmnop123456").contains("[REDACTED]"));
        let config_line = redact("experimental_bearer_token = \"SAMPLE0secretVALUE123\"");
        assert!(!config_line.contains("SAMPLE0secretVALUE123"));
        // 普通 prose 不误伤。
        let prose = "我们讨论了 memory 的设计,2026 年 10 月定稿";
        assert_eq!(redact(prose), prose);
    }

    #[test]
    fn rollout_without_meta_is_skipped() {
        let dir = std::env::temp_dir().join(format!("hetu-mem-test2-{}", std::process::id()));
        let path = dir.join("rollout-bad.jsonl");
        write(&path, "{\"type\":\"response_item\",\"payload\":{}}\n");
        assert!(read_rollout(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collect_finds_rollouts_recursively_and_memory_markdowns() {
        let dir = std::env::temp_dir().join(format!("hetu-mem-test3-{}", std::process::id()));
        write(
            &dir.join("sessions/2026/10/07/rollout-a.jsonl"),
            r#"{"type":"session_meta","payload":{"session_id":"a"}}"#,
        );
        write(
            &dir.join("archived_sessions/rollout-b.jsonl"),
            r#"{"type":"session_meta","payload":{"session_id":"b"}}"#,
        );
        write(&dir.join("memories/raw_memories.md"), "# Raw Memories\n");
        write(&dir.join("memories/rollout_summaries/s1.md"), "summary");
        write(&dir.join("memories/notes.txt"), "ignored");
        let rollouts = collect_rollouts(&dir);
        assert_eq!(rollouts.len(), 2);
        let mds = read_memory_markdowns(&dir.join("memories"));
        let labels: Vec<&str> = mds.iter().map(|(l, _)| l.as_str()).collect();
        assert!(labels.contains(&"raw_memories.md"));
        assert!(labels.contains(&"rollout_summaries/s1.md"));
        assert_eq!(mds.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
