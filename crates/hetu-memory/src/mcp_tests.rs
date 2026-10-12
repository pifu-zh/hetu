//! mcp.rs 的帧协议测试(进程内握手 + 工具调用全链路)。

use super::*;
use crate::tools::MemoryService;
use serde_json::json;
use std::path::Path;

fn fixture_service() -> (MemoryService, crate::store::MemoryStore, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("hetu-mcp-test-{}", std::process::id()));
    let sessions = dir.join("sessions/2026/10/07");
    std::fs::create_dir_all(&sessions).unwrap();
    std::fs::write(
        sessions.join("rollout-2026-10-07T00-00-00-aaa.jsonl"),
        concat!(
            r#"{"type":"session_meta","payload":{"session_id":"s-1","timestamp":"2026-10-07T01:00:00Z","cwd":"/tmp/proj"}}"#,
            "\n",
            r#"{"type":"response_item","payload":{"type":"message","role":"user","content":[{"text":"帮我分析本地网络问题"}]}}"#,
            "\n",
            r#"{"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"text":"系统 DNS 配置为空"}]}}"#,
            "\n",
        ),
    )
    .unwrap();
    let service = MemoryService::build(&dir);
    let store = crate::store::MemoryStore::new(dir.join("hetu-memory-state"));
    (service, store, dir)
}

#[test]
fn initialize_handshake_and_tools_list() {
    let (service, store, dir) = fixture_service();
    let init = handle_line(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        &service,
        &store,
    )
    .unwrap();
    let value: Value = serde_json::from_str(&init).unwrap();
    assert_eq!(value["result"]["serverInfo"]["name"], "hetu-memory");
    assert!(value["result"]["protocolVersion"].is_string());

    // notification 不回帧。
    assert!(handle_line(
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        &service,
        &store
    )
    .is_none());

    let list = handle_line(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        &service,
        &store,
    )
    .unwrap();
    let value: Value = serde_json::from_str(&list).unwrap();
    let tools = value["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 5);
    let names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"memory_overview"));
    assert!(names.contains(&"semantic_search"));
    assert!(names.contains(&"episodic_search"));
    assert!(names.contains(&"memory_context"));
    assert!(names.contains(&"memory_write"));
}

#[test]
fn tools_call_semantic_search_finds_session_content() {
    let (service, store, dir) = fixture_service();
    let line = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "semantic_search",
            "arguments": { "query": "网络问题 DNS" }
        }
    })
    .to_string();
    let response = handle_line(&line, &service, &store).unwrap();
    let value: Value = serde_json::from_str(&response).unwrap();
    assert!(value["result"]["isError"].as_bool().unwrap() == false);
    let text = value["result"]["content"][0]["text"].as_str().unwrap();
    let payload: Value = serde_json::from_str(text).unwrap();
    assert!(payload["matches"].as_u64().unwrap() >= 1);
    let first = &payload["results"][0];
    assert_eq!(first["source_id"], "s-1");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tools_call_overview_and_unknown_tool_error() {
    let (service, store, dir) = fixture_service();
    let line = json!({
        "jsonrpc": "2.0", "id": 4,
        "method": "tools/call",
        "params": { "name": "memory_overview", "arguments": {} }
    })
    .to_string();
    let response = handle_line(&line, &service, &store).unwrap();
    let value: Value = serde_json::from_str(&response).unwrap();
    let payload: Value =
        serde_json::from_str(value["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(payload["total_chunks"].as_u64().unwrap() >= 1);

    let bad = json!({
        "jsonrpc": "2.0", "id": 5,
        "method": "tools/call",
        "params": { "name": "nope", "arguments": {} }
    })
    .to_string();
    let response = handle_line(&bad, &service, &store).unwrap();
    let value: Value = serde_json::from_str(&response).unwrap();
    assert!(value["result"]["isError"].as_bool().unwrap());
    assert!(value["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("unknown tool"));

    let unknown_method = handle_line(
        r#"{"jsonrpc":"2.0","id":6,"method":"resources/list"}"#,
        &service,
        &store,
    )
    .unwrap();
    let value: Value = serde_json::from_str(&unknown_method).unwrap();
    assert_eq!(value["error"]["code"], -32601);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parse_error_returns_minus_32700() {
    let service = MemoryService::build(Path::new("/nonexistent-hetu-test"));
    let store = crate::store::MemoryStore::new(std::env::temp_dir().join("hetu-mcp-store"));
    let response = handle_line("not json", &service, &store).unwrap();
    let value: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(value["error"]["code"], -32700);
}
