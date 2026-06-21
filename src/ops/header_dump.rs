//! Header Dump — barcha javob header'larini chiqarish.
//!
//! Parasite `header_dump.rs`'dan olingan: security-relevant header'lar ajratiladi.

use crate::models::HeaderDumpResult;
use anyhow::Result;
use std::time::Duration;

/// Security-relevant header nomlari.
const SECURITY_HEADERS: &[&str] = &[
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
    "x-content-security-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
];

/// Berilgan URL uchun header dump.
pub async fn run(url: &str) -> Result<HeaderDumpResult> {
    let client = crate::pipeline::http_client(Duration::from_secs(10))?;

    let mut headers = Vec::new();
    let mut security_headers = Vec::new();

    if let Ok(resp) = client.get(url).send().await {
        for (name, value) in resp.headers().iter() {
            let n = name.as_str().to_lowercase();
            let v = value.to_str().unwrap_or("").to_string();
            if SECURITY_HEADERS.contains(&n.as_str()) {
                security_headers.push(n.clone());
            }
            headers.push((n, v));
        }
    }

    Ok(HeaderDumpResult {
        url: url.to_string(),
        headers,
        security_headers,
    })
}
