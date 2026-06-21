//! CORS Probe — CORS misconfiguration tekshirish.
//!
//! Parasite `cors_probe.rs`'dan olingan: 3 ta evil origin bilan test.

use crate::models::CorsResult;
use anyhow::Result;
use std::time::Duration;

/// 3 ta zararli Origin bilan CORS test qilamiz.
const EVIL_ORIGINS: &[&str] = &[
    "https://evil.parasite.com",
    "null",
    "https://localhost",
];

/// Berilgan URL uchun CORS misconfiguration tekshiruvi.
pub async fn run(url: &str) -> Result<Vec<CorsResult>> {
    let client = crate::pipeline::http_client(Duration::from_secs(10))?;
    let mut results = Vec::new();

    for origin in EVIL_ORIGINS {
        let req = client
            .get(url)
            .header("Origin", *origin)
            .header("Access-Control-Request-Method", "GET");

        if let Ok(resp) = req.send().await {
            let hdrs = resp.headers();
            let allow_origin = hdrs
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let allow_credentials = hdrs
                .get("access-control-allow-credentials")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);

            // Vulnerability balingchi:
            // 1. ACAO injected origin'ga teng VA credentials true
            // 2. ACAO "*" (wildcard)
            // 3. ACAO injected origin'ga teng (credentials siz)
            let vulnerable = (allow_origin == *origin && allow_credentials)
                || allow_origin == "*"
                || (allow_origin == *origin);

            if vulnerable || !allow_origin.is_empty() {
                results.push(CorsResult {
                    origin: origin.to_string(),
                    allow_origin,
                    allow_credentials,
                    vulnerable,
                });
            }
        }
    }

    Ok(results)
}
