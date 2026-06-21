//! SSL Inspector — SSL/TLS va HTTPS tekshirish.
//!
//! Parasite `ssl_inspect.rs`'dan olingan: HTTPS, redirect, HSTS, security header'lar.

use crate::models::SslResult;
use anyhow::Result;
use std::time::Duration;

/// Berilgan URL uchun SSL/TLS va HTTPS tekshiruvi.
pub async fn run(url: &str) -> Result<SslResult> {
    let client = crate::pipeline::http_client(Duration::from_secs(10))?;
    let host = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();

    // 1. HTTPS bilan asosiy so'rov.
    let https_url = if url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{host}")
    };

    let mut result = SslResult {
        url: url.to_string(),
        https_active: false,
        http_to_https_redirect: false,
        hsts: false,
        hsts_value: None,
        has_csp: false,
        has_x_frame_options: false,
        has_x_content_type_options: false,
        has_referrer_policy: false,
    };

    if let Ok(resp) = client.get(&https_url).send().await {
        result.https_active = resp.url().as_str().starts_with("https://");
        let hdrs = resp.headers();

        if let Some(hsts) = hdrs.get("strict-transport-security").and_then(|v| v.to_str().ok()) {
            result.hsts = true;
            result.hsts_value = Some(if hsts.len() > 44 { format!("{}…", &hsts[..44]) } else { hsts.to_string() });
        }
        result.has_csp = hdrs.contains_key("content-security-policy");
        result.has_x_frame_options = hdrs.contains_key("x-frame-options");
        result.has_x_content_type_options = hdrs.contains_key("x-content-type-options");
        result.has_referrer_policy = hdrs.contains_key("referrer-policy");
    }

    // 2. HTTP → HTTPS redirect tekshiruvi ( alohida client, redirect kuzatmasdan).
    let http_url = format!("http://{host}/");
    let no_redirect_client = reqwest::Client::builder()
        .user_agent("O'MOTIM/0.1")
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    if let Ok(resp) = no_redirect_client.get(&http_url).send().await {
        if let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
            result.http_to_https_redirect = loc.starts_with("https://");
        }
    }

    Ok(result)
}
