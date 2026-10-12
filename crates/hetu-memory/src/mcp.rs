//! MCP stdio server:JSON-RPC 2.0,按行分帧(newline-delimited JSON,
//! MCP stdio transport)。
//!
//! 方法面 v0:initialize / notifications/initialized / ping / tools/list
//! / tools/call。同步阻塞循环——codex 按需拉起的子进程,无常驻线程。

use crate::store::MemoryStore;
use crate::tools::MemoryService;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

const PROTOCOL_VERSION: &str = "2025-06-18";
const SERVER_NAME: &str = "hetu-memory";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// 服务入口:阻塞读 stdin,逐行分发,响应写 stdout。
pub fn serve(service: &MemoryService, store: &MemoryStore) -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Some(response) = handle_line(&line, service, store) else {
            continue; // notification:无响应
        };
        writeln!(stdout, "{response}")?;
        stdout.flush()?;
    }
    Ok(())
}

/// 单行分发。返回 None = notification(不回帧)。
fn handle_line(line: &str, service: &MemoryService, store: &MemoryStore) -> Option<String> {
    let value: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(error) => {
            return Some(json_error(Value::Null, -32700, &format!("parse error: {error}")));
        }
    };
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let method = value.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
        })),
        "notifications/initialized" | "initialized" => return None,
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": service.tool_definitions() })),
        "tools/call" => {
            let params = value.get("params").cloned().unwrap_or_default();
            let name = params
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or_default()
                .to_string();
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let result = match name.as_str() {
                "memory_context" => Ok(serde_json::json!({
                    "context": store.context(),
                    "hint": "persistent long-memory (hermes-style). Use memory_write to add/replace/remove entries."
                })),
                "memory_write" => {
                    let target = args.get("target").and_then(|t| t.as_str()).unwrap_or_default();
                    let op_name = args.get("op").and_then(|o| o.as_str()).unwrap_or_default();
                    let content = args.get("content").and_then(|c| c.as_str()).unwrap_or_default();
                    let old_text = args.get("old_text").and_then(|o| o.as_str()).unwrap_or_default();
                    crate::store::apply_args(store, target, op_name, content, old_text)
                }
                _ => service.call_tool(&name, &args),
            };
            match result {
                Ok(content) => Ok(json!({
                    "content": [{ "type": "text", "text": content.to_string() }],
                    "isError": false,
                })),
                Err(message) => Ok(json!({
                    "content": [{ "type": "text", "text": message }],
                    "isError": true,
                })),
            }
        }
        other => Err(format!("method not found: {other}")),
    };
    let response = match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(message) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": message },
        }),
    };
    Some(response.to_string())
}

fn json_error(id: Value, code: i64, message: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
    .to_string()
}

#[path = "mcp_tests.rs"]
#[cfg(test)]
mod mcp_tests;

