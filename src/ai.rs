//! AI moduli — bulutli LLM API'lar bilan ishlash.
//!
//! Lethal(1-beta)'dagi 15+ provayder katalog'idan ilhomlangan.
//! Foydalanuvchi o'z API kalitini environment orqali beradi:
//!   OMOTIM_AI_PROVIDER = openai | anthropic | gemini | groq | deepseek | ...
//!   OMOTIM_AI_KEY      = sk-...
//!   OMOTIM_AI_MODEL    = gpt-4o-mini
//!   OMOTIM_AI_BASE_URL = https://api.openai.com/v1  (ixtiyoriy)
//!
//! Uchta wire protocol qo'llab-quvvatlanadi:
//!   - OpenAI-compatible  (OpenAI, Groq, DeepSeek, Mistral, OpenRouter, ...)
//!   - Anthropic          (Claude)
//!   - Gemini             (Google)

use crate::models::ScanContext;
use anyhow::{anyhow, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use serde_json::{json, Value};

/// AI konfiguratsiyasi — lib.rs'dagi struct bilan bir xil (qayta e'lon qilinmagan).
/// Bu yerga kalit/provider to'g'ridan-to'g'ri uzatiladi.
pub struct AiConfig {
    pub provider: String,
    pub api_key: String,
    pub model: String,
    pub base_url: String,
}

impl AiConfig {
    /// Berilgan parametlar bilan config yaratish (frontend tomonidan).
    pub fn new(provider: String, api_key: String, model: String) -> Self {
        let p = provider.to_lowercase();
        let default_url = default_base_url(&p);
        Self {
            provider: p,
            api_key,
            model,
            base_url: default_url,
        }
    }

    /// Environment o'zgaruvchilardan o'qiydi — hech qanday kodga kalit kiritilmagan.
    pub fn from_env() -> Self {
        let provider = std::env::var("OMOTIM_AI_PROVIDER").unwrap_or_else(|_| "openai".into());
        let p = provider.to_lowercase();
        let default_url = default_base_url(&p);
        Self {
            provider,
            api_key: std::env::var("OMOTIM_AI_KEY").unwrap_or_default(),
            model: std::env::var("OMOTIM_AI_MODEL").unwrap_or_else(|_| "gpt-4o-mini".into()),
            base_url: std::env::var("OMOTIM_AI_BASE_URL").unwrap_or_else(|_| default_url),
        }
    }
}

/// Provayder nomidan standart API URL manzilini qaytaradi.
fn default_base_url(provider: &str) -> String {
    match provider {
        "anthropic" | "claude" => "https://api.anthropic.com/v1".to_string(),
        "gemini" | "google" => "https://generativelanguage.googleapis.com/v1beta".to_string(),
        "groq" => "https://api.groq.com/openai/v1".to_string(),
        "deepseek" => "https://api.deepseek.com/v1".to_string(),
        "mistral" => "https://api.mistral.ai/v1".to_string(),
        "openrouter" => "https://openrouter.ai/api/v1".to_string(),
        "ollama" => "http://localhost:11434/v1".to_string(),
        _ => "https://api.openai.com/v1".to_string(),
    }
}

/// AI bilan bir marta chat — to'liq javobni qaytaradi (streaming emas).
pub async fn chat(cfg: &AiConfig, message: &str, ctx: Option<&ScanContext>) -> Result<String> {
    let provider = cfg.provider.to_lowercase();

    // Ollama lokal — kalit talab qilmaydi. Boshqa provayderlar kalit talab qiladi.
    let needs_key = provider != "ollama";
    if needs_key && cfg.api_key.trim().is_empty() {
        return Err(anyhow!(
            "AI API key not set for provider '{}'.\n\
             Set it in the AI panel (top-right dropdown) or via env:\n  \
             export OMOTIM_AI_KEY=sk-...  export OMOTIM_AI_PROVIDER={}",
            cfg.provider, cfg.provider
        ));
    }

    let system = build_system_prompt(ctx);

    match provider.as_str() {
        "anthropic" | "claude" => chat_anthropic(cfg, &system, message).await,
        "gemini" | "google" => chat_gemini(cfg, &system, message).await,
        // Ollama va boshqa barchasi OpenAI-compat
        _ => chat_openai_compat(cfg, &system, message).await,
    }
}

/// Tizim prompt'i — skanlash kontekstini qo'shadi (Lethal'dagi prompt.rs kabi).
fn build_system_prompt(ctx: Option<&ScanContext>) -> String {
    let mut p = String::from(
        "You are the AI assistant inside O'MOTIM, a modular reconnaissance pipeline tool \
         for authorized security testing. Be concise, actionable, and technical. \
         When suggesting next steps, be specific (commands, tools, priorities). \
         Always remind the user to only test targets they have permission to test.",
    );

    if let Some(c) = ctx {
        p.push_str("\n\n--- Current Scan Context ---\n");
        p.push_str(&format!("Target: {}\n", c.domain));
        p.push_str(&format!("Subdomains: {}\n", c.subdomains.len()));
        p.push_str(&format!("Alive hosts: {}\n", c.summary.alive_hosts));
        p.push_str(&format!("Technologies: {}\n", c.technologies.len()));
        if !c.technologies.is_empty() {
            let techs: Vec<String> = c.technologies.iter().take(10).map(|t| {
                format!("{} {}", t.name, t.version.as_deref().unwrap_or(""))
            }).collect();
            p.push_str(&format!("  - {}\n", techs.join(", ")));
        }
        p.push_str(&format!("CVEs: {} (critical: {}, high: {})\n",
            c.cves.len(), c.summary.critical_count, c.summary.high_count));
        p.push_str(&format!("Secrets found: {}\n", c.secrets.len()));
        p.push_str(&format!("Header issues: {}\n", c.headers_analysis.len()));
        if !c.cves.is_empty() {
            let top: Vec<String> = c.cves.iter().take(5)
                .map(|cve| format!("{} ({}, CVSS {:.1})", cve.cve_id, cve.severity.as_str(), cve.cvss_score))
                .collect();
            p.push_str(&format!("Top CVEs: {}\n", top.join("; ")));
        }
        p.push_str("--- End Context ---\n");
    }

    p
}

/// OpenAI-compatible API (OpenAI, Groq, DeepSeek, Mistral, OpenRouter, Together, ...)
async fn chat_openai_compat(cfg: &AiConfig, system: &str, message: &str) -> Result<String> {
    let url = format!("{}/chat/completions", cfg.base_url.trim_end_matches('/'));

    let body = json!({
        "model": cfg.model,
        "messages": [
            { "role": "system", "content": system },
            { "role": "user",   "content": message },
        ],
        "temperature": 0.4,
        "max_tokens": 1024,
    });

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {}", cfg.api_key))?,
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let resp = client.post(&url).headers(headers).json(&body).send().await?;
    let status = resp.status();

    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        let short = if text.len() > 400 { format!("{}…", &text[..400]) } else { text };
        return Err(anyhow!("HTTP {status}: {short}"));
    }

    let v: Value = resp.json().await?;
    let content = v
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| anyhow!("malformed OpenAI response"))?;

    Ok(content.to_string())
}

/// Anthropic native API (Claude)
async fn chat_anthropic(cfg: &AiConfig, system: &str, message: &str) -> Result<String> {
    let url = format!("{}/messages", cfg.base_url.trim_end_matches('/'));

    let body = json!({
        "model": cfg.model,
        "max_tokens": 1024,
        "system": system,
        "messages": [
            { "role": "user", "content": message }
        ]
    });

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        HeaderName::from_static("x-api-key"),
        HeaderValue::from_str(&cfg.api_key)?,
    );
    headers.insert(
        HeaderName::from_static("anthropic-version"),
        HeaderValue::from_static("2023-06-01"),
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let resp = client.post(&url).headers(headers).json(&body).send().await?;
    let status = resp.status();

    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        let short = if text.len() > 400 { format!("{}…", &text[..400]) } else { text };
        return Err(anyhow!("HTTP {status}: {short}"));
    }

    let v: Value = resp.json().await?;
    // content = [{ "type": "text", "text": "..." }]
    let content = v
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|b| b.get("text"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow!("malformed Anthropic response"))?;

    Ok(content.to_string())
}

/// Google Gemini native API
async fn chat_gemini(cfg: &AiConfig, system: &str, message: &str) -> Result<String> {
    let url = format!(
        "{}/models/{}:generateContent?key={}",
        cfg.base_url.trim_end_matches('/'),
        cfg.model,
        cfg.api_key
    );

    let body = json!({
        "systemInstruction": { "parts": [{ "text": system }] },
        "contents": [
            { "role": "user", "parts": [{ "text": message }] }
        ],
        "generationConfig": { "temperature": 0.4, "maxOutputTokens": 1024 }
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let resp = client.post(&url).json(&body).send().await?;
    let status = resp.status();

    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        let short = if text.len() > 400 { format!("{}…", &text[..400]) } else { text };
        return Err(anyhow!("HTTP {status}: {short}"));
    }

    let v: Value = resp.json().await?;
    let content = v
        .get("candidates")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())
        .and_then(|arr| arr.first())
        .and_then(|p| p.get("text"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow!("malformed Gemini response"))?;

    Ok(content.to_string())
}
