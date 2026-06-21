//! API Discovery — JavaScript'dan API endpoint topish.
//!
//! Parasite `api_parasite.rs`'dan olingan: HTML script'lar + 6 regex pattern.

use crate::models::ApiEndpointResult;
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::time::Duration;

/// 6 ta regex pattern — fetch, axios, XHR, jQuery, base_url, api path.
fn patterns() -> Vec<Regex> {
    vec![
        Regex::new(r#"fetch\(['"]([^'"]+)['"]"#).unwrap(),
        Regex::new(r#"axios\.(?:get|post|put|delete|patch)\(['"]([^'"]+)['"]"#).unwrap(),
        Regex::new(r#"\.open\(['"](?:GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"]([^'"]+)['"]"#).unwrap(),
        Regex::new(r#"\$\.(?:get|post|ajax|getJSON)\(['"]([^'"]+)['"]"#).unwrap(),
        Regex::new(r#"base[_]?[Uu]rl[:=]\s*['"]([^'"]+)['"]"#).unwrap(),
        Regex::new(r#"['"](/api/v\d+/[^'"]+)['"]"#).unwrap(),
    ]
}

/// Path API'ga o'xshaydimi? (.js/.css/.png'larni istisno qilamiz).
fn looks_like_api(path: &str) -> bool {
    if path.ends_with(".js") || path.ends_with(".css") || path.ends_with(".png") {
        return false;
    }
    path.starts_with('/')
        || path.starts_with("http")
        || path.contains("/api")
        || path.contains("/v1")
        || path.contains("/v2")
}

/// Berilgan URL uchun API endpoint topish.
pub async fn run(url: &str) -> Result<Vec<ApiEndpointResult>> {
    let client = crate::pipeline::http_client(Duration::from_secs(15))?;
    let resp = client.get(url).send().await?;
    let html = resp.text().await?;

    let mut all_js = String::new();

    // 1. Tashqi script URL'larini scraper bilan topamiz — alohida scope'da,
    //    chunki scraper::Html Send emas va .await oldidan drop bo'lishi kerak.
    let ext_urls: Vec<String> = {
        let doc = scraper::Html::parse_document(&html);
        let script_sel = scraper::Selector::parse("script[src]").unwrap();
        doc.select(&script_sel)
            .filter_map(|el| el.value().attr("src"))
            .map(|src| {
                if src.starts_with("http") {
                    src.to_string()
                } else if src.starts_with('/') {
                    let base = url.split('/').take(3).collect::<Vec<_>>().join("/");
                    format!("{base}{src}")
                } else {
                    format!("{}/{}", url.trim_end_matches('/'), src)
                }
            })
            .collect()
    };

    // 2. Inline script'lar va butun HTML'ni all_js'ga qo'shamiz.
    all_js.push_str(&html);

    // 3. Tashqi JS'larni yuklab olamiz (bir nechtasi — tezlik uchun cheklangan).
    for js_url in ext_urls.iter().take(20) {
        if let Ok(resp) = client.get(js_url).send().await {
            if let Ok(text) = resp.text().await {
                all_js.push_str(&text);
            }
        }
    }

    // 4. Regex pattern'larni qo'llaymiz.
    let mut found: HashSet<String> = HashSet::new();
    let mut results = Vec::new();
    for re in patterns() {
        for caps in re.captures_iter(&all_js) {
            if let Some(m) = caps.get(1) {
                let path = m.as_str().to_string();
                if looks_like_api(&path) && found.insert(path.clone()) {
                    results.push(ApiEndpointResult {
                        method: "GET".to_string(),
                        path,
                        params: Vec::new(),
                        found_in: "JS".to_string(),
                    });
                }
            }
        }
    }

    Ok(results)
}
