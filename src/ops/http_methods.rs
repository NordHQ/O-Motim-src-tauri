//! HTTP Methods — 9 ta HTTP metodni tekshirish.
//!
//! Parasite `http_methods.rs`'dan olingan: OPTIONS + 9 metodni to'g'ridan-to'g'ri test.

use crate::models::HttpMethodResult;
use anyhow::Result;
use std::time::Duration;

/// 9 ta HTTP metod. Xavflilari belgilangan.
const METHODS: &[(&str, bool)] = &[
    ("GET", false),
    ("POST", false),
    ("PUT", true),    // Fayl yuklash
    ("DELETE", true), // O'chirish
    ("PATCH", false),
    ("HEAD", false),
    ("OPTIONS", false),
    ("TRACE", true),    // XST hujumi
    ("CONNECT", true),  // Tunnel
];

/// Berilgan URL uchun HTTP metodlarni tekshirish.
pub async fn run(url: &str) -> Result<Vec<HttpMethodResult>> {
    let client = crate::pipeline::http_client(Duration::from_secs(10))?;
    let mut results = Vec::new();

    for (method, dangerous) in METHODS {
        // reqwest metod nomini o'zgartirib jo'natamiz.
        let req = client.request(reqwest::Method::from_bytes(method.as_bytes())?, url);
        if let Ok(resp) = req.send().await {
            results.push(HttpMethodResult {
                method: method.to_string(),
                status_code: resp.status().as_u16(),
                dangerous: *dangerous,
            });
        }
    }

    Ok(results)
}
