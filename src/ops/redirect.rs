//! Open Redirect — ochiq redirect zaifligini tekshirish.
//!
//! Parasite `open_redirect.rs`'dan olingan: 30 param × 6 payload = 180 test.

use crate::models::OpenRedirectResult;
use anyhow::Result;
use std::time::Duration;

/// 30 ta redirect parametri.
const REDIRECT_PARAMS: &[&str] = &[
    "url", "redirect", "return", "returnUrl", "returnTo", "return_url", "return_to",
    "next", "goto", "target", "dest", "destination", "redir", "redirect_uri",
    "redirect_url", "callback", "continue", "forward", "location", "go",
    "path", "jump", "ref", "back", "backUrl", "back_url", "from", "fromUrl", "to", "toUrl",
];

/// 6 ta payload (value, bypass turi).
const PAYLOADS: &[(&str, &str)] = &[
    ("https://evil.parasite.com", "absolute url"),
    ("//evil.parasite.com", "protocol-relative"),
    ("/\\evil.parasite.com", "backslash bypass"),
    ("https:evil.parasite.com", "colon bypass"),
    ("%2F%2Fevil.parasite.com", "double url-encoded"),
    ("https://evil.parasite.com%23", "fragment bypass"),
];

/// Berilgan URL uchun ochiq redirect test.
pub async fn run(url: &str) -> Result<Vec<OpenRedirectResult>> {
    // Redirect kuzatmasdan — biz Location header'ni o'zimiz ko'ramiz.
    let client = reqwest::Client::builder()
        .user_agent("O'MOTIM/0.1")
        .timeout(Duration::from_secs(6))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let mut results = Vec::new();

    for param in REDIRECT_PARAMS {
        for (payload, ptype) in PAYLOADS {
            let test_url = if url.contains('?') {
                format!("{url}&{param}={payload}")
            } else {
                format!("{url}?{param}={payload}")
            };

            if let Ok(resp) = client.get(&test_url).send().await {
                let status = resp.status().as_u16();
                if status >= 300 && status < 400 {
                    if let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
                        if loc.contains("evil.parasite.com") {
                            results.push(OpenRedirectResult {
                                parameter: param.to_string(),
                                payload_type: ptype.to_string(),
                                payload: payload.to_string(),
                                redirect_location: Some(loc.to_string()),
                                vulnerable: true,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(results)
}
