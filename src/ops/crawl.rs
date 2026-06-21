//! Crawl — stealth crawl (parasite shadow_crawl + infect).
//!
//! Parasite'dagi 15 ta rotating User-Agent va 7 ta Accept-Language bilan.
//! Endi `futures::stream` orqali, kam concurrency (stealth).

use crate::models::CrawlResult;
use anyhow::Result;
use std::collections::HashSet;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// 15 ta rotating User-Agent (parasite'dan).
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Twitterbot/1.0",
    "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
    "curl/8.4.0",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Wget/1.21.3",
];

/// 7 ta rotating Accept-Language.
const ACCEPT_LANGS: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "ru-RU,ru;q=0.9",
    "de-DE,de;q=0.9",
    "fr-FR,fr;q=0.9",
    "zh-CN,zh;q=0.9",
    "ja-JP,ja;q=0.9",
];

/// Berilgan URL uchun stealth crawl.
pub async fn run(
    url: &str,
    max_pages: usize,
    cancel: &CancellationToken,
) -> Result<Vec<CrawlResult>> {
    let client = crate::pipeline::http_client(Duration::from_secs(10))?;
    let base_host = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();

    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: Vec<(String, u32)> = vec![(url.to_string(), 0)];
    let mut results = Vec::new();
    let mut idx: usize = 0;

    while let Some((page_url, depth)) = queue.pop() {
        if cancel.is_cancelled() || visited.len() >= max_pages || depth > 3 {
            continue;
        }
        if visited.contains(&page_url) {
            continue;
        }
        visited.insert(page_url.clone());

        // Rotating UA va Accept-Language.
        let ua = USER_AGENTS[idx % USER_AGENTS.len()];
        let lang = ACCEPT_LANGS[idx % ACCEPT_LANGS.len()];
        idx += 1;

        let resp = match client
            .get(&page_url)
            .header("User-Agent", ua)
            .header("Accept-Language", lang)
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let final_url = resp.url().to_string();
        let html = resp.text().await.unwrap_or_default();

        // Title extraction.
        let title = extract_title(&html).unwrap_or_default();

        results.push(CrawlResult {
            url: final_url.clone(),
            title,
            status_code: status,
            content_type: content_type.clone(),
            depth,
        });

        // HTML bo'lsa — ichki linklarni navbatga qo'shamiz.
        if content_type.contains("html") || content_type.contains("text") {
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
                        .unwrap_or("");
                    if host == base_host && !visited.contains(&abs) {
                        queue.push((abs, depth + 1));
                    }
                }
            }
        }
    }

    Ok(results)
}

fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let start = lower.find("<title")?;
    let after = &html[start..];
    let open_end = after.find('>')?;
    let close = after.find("</title>")?;
    Some(after[open_end + 1..close].trim().to_string())
}
