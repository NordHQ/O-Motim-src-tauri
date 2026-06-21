//! Host Analyze — host biopsy (status, title, server, tech, score).
//!
//! Parasite `analyze.rs`'dan olingan.

use crate::models::AnalyzeResult;
use anyhow::Result;
use std::time::Duration;

/// Berilgan URL uchun host biopsy.
pub async fn run(url: &str) -> Result<AnalyzeResult> {
    let client = crate::pipeline::http_client(Duration::from_secs(10))?;
    let mut result = AnalyzeResult {
        url: url.to_string(),
        status: 0,
        title: String::new(),
        server: None,
        tech: Vec::new(),
        links_count: 0,
        has_csp: false,
        has_hsts: false,
        score: 0,
    };

    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return Ok(result),
    };

    result.status = resp.status().as_u16();
    result.server = resp
        .headers()
        .get("server")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    result.has_csp = resp.headers().contains_key("content-security-policy");
    result.has_hsts = resp
        .headers()
        .contains_key("strict-transport-security");

    let final_url = resp.url().to_string();
    let html = resp.text().await.unwrap_or_default();

    // Title.
    result.title = extract_title(&html).unwrap_or_default();

    // Tech — server header'idan.
    if let Some(srv) = &result.server {
        let s = srv.to_lowercase();
        if s.contains("nginx") {
            result.tech.push("Nginx".into());
        }
        if s.contains("apache") {
            result.tech.push("Apache".into());
        }
        if s.contains("cloudflare") {
            result.tech.push("Cloudflare".into());
        }
        if s.contains("iis") {
            result.tech.push("IIS".into());
        }
    }

    // Links count.
    let doc = scraper::Html::parse_document(&html);
    if let Ok(a_sel) = scraper::Selector::parse("a[href]") {
        result.links_count = doc.select(&a_sel).count();
    }

    // Score — oddiy heuristik.
    let mut score = 0;
    if result.status >= 200 && result.status < 300 {
        score += 30;
    }
    if result.has_csp {
        score += 25;
    }
    if result.has_hsts {
        score += 25;
    }
    if !result.title.is_empty() {
        score += 10;
    }
    if result.links_count > 10 {
        score += 10;
    }
    result.score = score.min(100);
    let _ = final_url;

    Ok(result)
}

fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let start = lower.find("<title")?;
    let after = &html[start..];
    let open_end = after.find('>')?;
    let close = after.find("</title>")?;
    Some(after[open_end + 1..close].trim().to_string())
}
