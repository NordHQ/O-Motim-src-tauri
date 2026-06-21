//! Resource Enum — sahifadagi resurslarni topish (images, scripts, styles, fonts).
//!
//! Parasite `leech.rs`'dan olingan.

use crate::models::ResourceResult;
use anyhow::Result;
use std::time::Duration;

/// Berilgan URL uchun resurslar.
pub async fn run(url: &str) -> Result<Vec<ResourceResult>> {
    let client = crate::pipeline::http_client(Duration::from_secs(12))?;
    let resp = client.get(url).send().await?;
    let html = resp.text().await?;

    let doc = scraper::Html::parse_document(&html);
    let base = url.split('/').take(3).collect::<Vec<_>>().join("/");

    let mut results = Vec::new();

    // img[src]
    if let Ok(sel) = scraper::Selector::parse("img[src]") {
        for el in doc.select(&sel) {
            if let Some(src) = el.value().attr("src") {
                if let Some(u) = abs_url(src, &base, url) {
                    results.push(ResourceResult {
                        url: u,
                        resource_type: "image".into(),
                        size: None,
                    });
                }
            }
        }
    }
    // script[src]
    if let Ok(sel) = scraper::Selector::parse("script[src]") {
        for el in doc.select(&sel) {
            if let Some(src) = el.value().attr("src") {
                if let Some(u) = abs_url(src, &base, url) {
                    results.push(ResourceResult {
                        url: u,
                        resource_type: "script".into(),
                        size: None,
                    });
                }
            }
        }
    }
    // link[href] — stylesheet, font, icon
    if let Ok(sel) = scraper::Selector::parse("link[href]") {
        for el in doc.select(&sel) {
            if let Some(href) = el.value().attr("href") {
                let rel = el.value().attr("rel").unwrap_or("");
                let rtype = if rel.contains("stylesheet") {
                    "style"
                } else if rel.contains("font") {
                    "font"
                } else if rel.contains("icon") {
                    "image"
                } else {
                    continue;
                };
                if let Some(u) = abs_url(href, &base, url) {
                    results.push(ResourceResult {
                        url: u,
                        resource_type: rtype.into(),
                        size: None,
                    });
                }
            }
        }
    }
    // source[src], video[src], audio[src]
    if let Ok(sel) = scraper::Selector::parse("video[src], audio[src], source[src]") {
        for el in doc.select(&sel) {
            if let Some(src) = el.value().attr("src") {
                if let Some(u) = abs_url(src, &base, url) {
                    let tag = el.value().name();
                    let rtype = if tag == "video" {
                        "video"
                    } else if tag == "audio" {
                        "audio"
                    } else {
                        "media"
                    };
                    results.push(ResourceResult {
                        url: u,
                        resource_type: rtype.into(),
                        size: None,
                    });
                }
            }
        }
    }

    Ok(results)
}

fn abs_url(src: &str, base: &str, page: &str) -> Option<String> {
    if src.starts_with("data:") || src.starts_with("javascript:") {
        return None;
    }
    if src.starts_with("http") {
        Some(src.to_string())
    } else if src.starts_with("//") {
        Some(format!("https:{src}"))
    } else if src.starts_with('/') {
        Some(format!("{base}{src}"))
    } else {
        Some(format!("{}/{}", page.trim_end_matches('/'), src))
    }
}
