//! embedding 客户端 + 向量缓存。
//!
//! 供给方:智谱 embedding-3(key 读环境变量或 codex config.toml 的
//! provider token);本地缓存按文本哈希持久化,索引期批量补嵌,检索期
//! 只嵌查询一句。任何网络/凭据失败 = 返回 None,调用方 fail-open 退
//! 词法(透明纪律:检索永不因向量层故障而失效)。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// 单条嵌入输入上限(字符):embedding-3 上下文内,截断保预算。
const EMBED_INPUT_MAX_CHARS: usize = 1000;
/// 单批条数上限。
const BATCH_SIZE: usize = 16;

pub struct EmbedClient {
    endpoint: String,
    key: String,
    model: String,
    http: ureq::Agent,
}

impl EmbedClient {
    /// key 来源优先级:HETU_MEMORY_EMBED_KEY 环境变量 → codex
    /// config.toml 的 model_providers.<default>.experimental_bearer_token。
    pub fn from_env(codex_root: &Path) -> Option<Self> {
        let key = std::env::var("HETU_MEMORY_EMBED_KEY")
            .ok()
            .filter(|k| !k.trim().is_empty())
            .or_else(|| read_codex_token(codex_root))?;
        Some(Self {
            endpoint: "https://open.bigmodel.cn/api/paas/v4/embeddings".to_string(),
            key,
            model: "embedding-3".to_string(),
            http: ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .timeout_global(Some(std::time::Duration::from_secs(25)))
                .build(),
        ),
        })
    }

    /// 批量嵌入。失败 = Err(供日志),调用方 fail-open。
    pub fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        let mut out = Vec::with_capacity(texts.len());
        for batch in texts.chunks(BATCH_SIZE) {
            let body = serde_json::json!({
                "model": self.model,
                "input": batch,
            });
            let mut response = self
                .http
                .post(&self.endpoint)
                .header("Authorization", format!("Bearer {}", self.key))
                .send_json(&body)
                .map_err(|e| format!("embed request failed: {e}"))?;
            let value: serde_json::Value = response
                .body_mut()
                .read_json()
                .map_err(|e| format!("embed response parse failed: {e}"))?;
            let mut data: Vec<(usize, Vec<f32>)> = value
                .get("data")
                .and_then(|d| d.as_array())
                .ok_or_else(|| "embed response missing data".to_string())?
                .iter()
                .filter_map(|item| {
                    let index = item.get("index")?.as_u64()? as usize;
                    let embedding = item.get("embedding")?.as_array()?;
                    let vector: Vec<f32> = embedding
                        .iter()
                        .filter_map(|v| v.as_f64().map(|f| f as f32))
                        .collect();
                    Some((index, vector))
                })
                .collect();
            data.sort_by_key(|(index, _)| *index);
            if data.len() != batch.len() {
                return Err("embed response count mismatch".to_string());
            }
            out.extend(data.into_iter().map(|(_, vector)| vector));
        }
        Ok(out)
    }
}

fn read_codex_token(codex_root: &Path) -> Option<String> {
    let config = std::fs::read_to_string(codex_root.join("config.toml")).ok()?;
    // 最小解析:找 [model_providers.*] 段内的 experimental_bearer_token。
    // 不引 toml 依赖——键名固定,行扫描足够(v0)。
    let mut in_provider_section = false;
    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_provider_section = trimmed.starts_with("[model_providers.");
            continue;
        }
        if in_provider_section && let Some(token) = trimmed.strip_prefix("experimental_bearer_token")
        {
            let token = token.trim().trim_start_matches('=').trim().trim_matches('"');
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
}

/// 向量缓存:text 哈希 → 向量。按需落盘。
pub struct VectorCache {
    path: PathBuf,
    map: HashMap<u64, Vec<f32>>,
    dirty: bool,
}

impl VectorCache {
    pub fn load(path: PathBuf) -> Self {
        let map = std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();
        Self {
            path,
            map,
            dirty: false,
        }
    }

    pub fn get(&self, text: &str) -> Option<&Vec<f32>> {
        self.map.get(&text_hash(text))
    }

    pub fn put(&mut self, text: &str, vector: Vec<f32>) {
        self.map.insert(text_hash(text), vector);
        self.dirty = true;
    }

    /// 缓存中已有向量的文本哈希集合(补嵌前求差集用)。
    pub fn has(&self, text: &str) -> bool {
        self.map.contains_key(&text_hash(text))
    }

    pub fn flush(&mut self) {
        if self.dirty {
            if let Some(parent) = self.path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(raw) = serde_json::to_string(&self.map) {
                let tmp = self.path.with_extension("json.tmp");
                if std::fs::write(&tmp, raw).is_ok() {
                    let _ = std::fs::rename(&tmp, &self.path);
                    self.dirty = false;
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
}

/// FNV-1a 64:稳定跨进程,无需外部依赖。
pub fn text_hash(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in text.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// 余弦相似度(零向量返回 0)。
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0;
    let mut norm_a = 0.0;
    let mut norm_b = 0.0;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += (x * y) as f64;
        norm_a += (x * x) as f64;
        norm_b += (y * y) as f64;
    }
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    (dot / (norm_a.sqrt() * norm_b.sqrt())) as f32
}

/// 混合评分:语义与词法各自归一后加权(词法是召回保底,语义是换词
/// 命中的关键)。
pub fn blend(semantic: f64, lexical: f64) -> f64 {
    0.65 * semantic + 0.35 * lexical
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_hash_is_stable_and_text_sensitive() {
        assert_eq!(text_hash("abc"), text_hash("abc"));
        assert_ne!(text_hash("abc"), text_hash("abd"));
    }

    #[test]
    fn cosine_detects_alignment_and_rejects_zero() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        let c = vec![0.0, 1.0, 0.0];
        assert!(cosine(&a, &b) > 0.99);
        assert!(cosine(&a, &c).abs() < 0.01);
        assert_eq!(cosine(&a, &[]), 0.0);
    }

    #[test]
    fn vector_cache_roundtrips_and_reports_missing() {
        let path = std::env::temp_dir().join(format!("hetu-vec-{}.json", std::process::id()));
        {
            let mut cache = VectorCache::load(path.clone());
            assert!(!cache.has("hello"));
            cache.put("hello", vec![0.1, 0.2]);
            cache.flush();
        }
        let cache = VectorCache::load(path.clone());
        assert!(cache.has("hello"));
        assert_eq!(cache.get("hello").unwrap(), &vec![0.1, 0.2]);
        assert!(!cache.has("world"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn blend_weights_semantic_over_lexical() {
        let semantic_only = blend(1.0, 0.0);
        let lexical_only = blend(0.0, 1.0);
        assert!(semantic_only > lexical_only * 1.5);
        assert!((blend(1.0, 1.0) - 1.0).abs() < 1e-9);
    }
}
