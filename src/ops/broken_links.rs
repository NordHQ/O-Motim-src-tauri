//! Broken Links — o'lik tashqi domenlarni topish (hijacking imkoni).
//!
//! Parasite `necrosis_check.rs`'dan olingan: BFS crawl → external link → HEAD check.

use crate::models::BrokenLinkResult;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// Berilgan URL uchun o'lik tashqi linklarni topish.
pub async fn run(url: &str, max_pages: usize) -> Result<Vec<BrokenLinkResult>> {
    let client = crate::pipeline::http_client(Duration::from_secs(8))?;
    let base_host = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();

    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: Vec<String> = vec![url.to_string()];
    let mut external: HashMap<String, Vec<String>> = HashMap::new(); // domain → [page urls]

    // Phase 1: BFS crawl — ichki sahifalardan tashqi linklarni yig'amiz.
    while let Some(page_url) = queue.pop() {
        if visited.len() >= max_pages || visited.contains(&page_url) {
            continue;
        }
        visited.insert(page_url.clone());

        let resp = match client.get(&page_url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let html = match resp.text().await {
            Ok(t) => t,
            Err(_) => continue,
        };

        let doc = scraper::Html::parse_document(&html);
        let a_sel = scraper::Selector::parse("a[href]").unwrap();
        for a in doc.select(&a_sel) {
            if let Some(href) = a.value().attr("href") {
                let abs = if href.starts_with("http") {
                    href.to_string()
                } else if href.starts_with('/') {
                    let base = url.split('/').take(3).collect::<Vec<_>>().join("/");
                    format!("{base}{href}")
                } else {
                    continue;
                };

                let host = abs
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .to_string();

                if host.is_empty() {
                    continue;
                }
                if host == base_host {
                    // Ichki — navbatga qo'shamiz.
                    if !visited.contains(&abs) {
                        queue.push(abs);
                    }
                } else {
                    // Tashqi — yig'amiz.
                    external.entry(host).or_default().push(page_url.clone());
                }
            }
        }
    }

    // Phase 2: Tashqi domenlar liveness check (parallel HEAD).
    let domains: Vec<String> = external.keys().cloned().collect();
    let mut tasks = Vec::new();
    for d in domains {
        let client = reqwest::Client::builder()
            .user_agent("O'MOTIM/0.1")
            .timeout(Duration::from_secs(6))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()?;
        tasks.push(async move {
            let test_url = format!("https://{d}/");
            let alive = match client.head(&test_url).send().await {
                Ok(r) => r.status().as_u16() < 500,
                Err(_) => false,
            };
            (d, if alive { "alive" } else { "dead" }.to_string())
        });
    }
    let statuses = futures::future::join_all(tasks).await;

    // Phase 3: Natijalar — faqat dead domenlar (hijacking potensiali).
    let mut results = Vec::new();
    for (domain, status) in statuses {
        if status == "dead" {
            if let Some(pages) = external.get(&domain) {
                results.push(BrokenLinkResult {
                    domain,
                    status,
                    pages: pages.iter().take(3).cloned().collect(),
                });
            }
        }
    }

    Ok(results)
}
