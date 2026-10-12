//! hetu-memory — codex 的长记忆插件(v0:词法检索 MCP server)。
//!
//! 定性见仓库 README;宪法三纪律:寄生/轻量/透明。

mod corpus;
mod embed;
mod index;
mod mcp;
mod store;
mod threat;
mod tools;

use std::path::PathBuf;
use tools::MemoryService;

fn main() {
    let corpus_root = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HETU_MEMORY_CORPUS").map(PathBuf::from))
        .or_else(|| home_dir().map(|h| h.join(".codex")))
        .unwrap_or_else(|| PathBuf::from("."));
    let state_dir = std::env::var_os("HETU_MEMORY_STATE_DIR")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|h| h.join(".hetu-memory")))
        .unwrap_or_else(|| PathBuf::from(".hetu-memory"));
    let store = store::MemoryStore::new(state_dir);
    let service = MemoryService::build(&corpus_root);
    eprintln!(
        "hetu-memory: {} chunks indexed from {}",
        service.total_chunks(),
        corpus_root.display()
    );
    if let Err(error) = mcp::serve(&service, &store) {
        eprintln!("hetu-memory: server error: {error}");
        std::process::exit(1);
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}
