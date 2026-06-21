//! Form Analysis — HTML formalarni topish va fuzzing payload tayyorlash.
//!
//! Parasite `form_injector.rs`'dan olingan: form parsing + payload generation.

use crate::models::{FormFieldResult, FormResult};
use anyhow::Result;
use std::time::Duration;

/// Forma turini taxmin qilamiz.
fn guess_form_type(fields: &[FormFieldResult]) -> &'static str {
    if fields.iter().any(|f| f.has_password) {
        return "login/auth";
    }
    if fields.iter().any(|f| {
        let n = f.name.to_lowercase();
        n.contains("search") || n.contains("query") || n == "q"
    }) {
        return "search";
    }
    if fields
        .iter()
        .any(|f| f.name.to_lowercase().contains("email") || f.name.to_lowercase().contains("mail"))
    {
        return "contact/subscribe";
    }
    if fields.iter().any(|f| {
        let n = f.name.to_lowercase();
        n.contains("comment") || n.contains("message") || n.contains("body")
    }) {
        return "comment";
    }
    "generic"
}

/// Berilgan URL uchun form topish va tahlil qilish.
pub async fn run(url: &str) -> Result<Vec<FormResult>> {
    let client = crate::pipeline::http_client(Duration::from_secs(10))?;
    let resp = client.get(url).send().await?;
    let html = resp.text().await?;
    let base_url = url.to_string();

    let doc = scraper::Html::parse_document(&html);
    let form_sel = scraper::Selector::parse("form").unwrap();
    let input_sel = scraper::Selector::parse("input, textarea, select").unwrap();

    let mut results = Vec::new();

    for form in doc.select(&form_sel) {
        let action = form.value().attr("action").unwrap_or("").to_string();
        let form_method = form.value().attr("method").unwrap_or("GET").to_uppercase();

        // Action'ni mutlaq URL'ga aylantiramiz.
        let abs_action = if action.is_empty() {
            base_url.clone()
        } else if action.starts_with("http") {
            action.clone()
        } else if action.starts_with('/') {
            let base = url.split('/').take(3).collect::<Vec<_>>().join("/");
            format!("{base}{action}")
        } else {
            format!("{}/{}", url.trim_end_matches('/'), action)
        };

        let mut fields = Vec::new();
        for input in form.select(&input_sel) {
            let name = input.value().attr("name").unwrap_or("").to_string();
            let ftype = input.value().attr("type").unwrap_or("text").to_lowercase();
            let has_password = ftype == "password";
            fields.push(FormFieldResult {
                name,
                field_type: ftype,
                has_password,
            });
        }

        if !abs_action.is_empty() {
            results.push(FormResult {
                action: abs_action,
                form_method,
                form_type: guess_form_type(&fields).to_string(),
                fields,
            });
        }
    }

    Ok(results)
}
