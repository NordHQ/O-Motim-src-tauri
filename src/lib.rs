//! O'MOTIM — modular reconnaissance pipeline (Rust backend).
//!
//! Frontend (React) bu backend'ga Tauri IPC orqali murojaat qiladi:
//!   - `start_scan(domain)`    → pipeline ishga tushadi
//!   - `stop_scan()`           → pipeline to'xtaydi
//!   - `ai_chat(message, ctx)` → bulutli AI modeliga so'rov
//!   - `check_ollama()`        → (backwards-compat) AI holatini tekshirish
//!   - `get_system_stats()`    → CPU / RAM / threads
//!
//! Pipeline 8 bosqichdan iborat va real vaqtda eventlar yuboradi:
//!   "pipeline-event"  (bosqich holati)
//!   "scan-complete"   (yakuniy kontekst)
//!
//! Lethal(1-beta) toolkidagi kuchli OSINT/recon yondashuvlaridan
//! ilhomlangan — reqwest + hickory-dns + scraper stack'i.

#![allow(dead_code)]

pub mod ai;
pub mod eye;
pub mod graph;
pub mod models;
pub mod ops;
pub mod pipeline;
pub mod stats;

use std::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// Joriy skanlashni bekor qilish uchun token (Mutex orqali himoyalangan).
struct ScanState {
    cancel: Option<CancellationToken>,
}

/// AI konfiguratsiyasi (ai moduliga eksport qilamiz).
pub use ai::AiConfig;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(Mutex::new(ScanState { cancel: None }))
        .invoke_handler(tauri::generate_handler![
            commands::start_scan,
            commands::stop_scan,
            commands::ai_chat,
            commands::check_ollama,
            commands::get_system_stats,
            commands::rescan_item,
            commands::run_single_stage,
        ])
        .run(tauri::generate_context!())
        .expect("error while running O'MOTIM");
}

/// Tauri-ga eksport qilingan komandalar (modul ichida).
mod commands {
    use super::*;
    use crate::models::{ScanContext, SystemStats};
    use tauri::{AppHandle, Emitter, State};

    /// Pipeline'ni boshlaydi. Frontend: `invoke("start_scan", { domain })`.
    #[tauri::command]
    pub async fn start_scan(
        app: AppHandle,
        state: State<'_, Mutex<ScanState>>,
        domain: String,
    ) -> Result<(), String> {
        let domain = domain.trim().to_string();
        if domain.is_empty() {
            return Err("domain is required".into());
        }

        // Avvalgi skanlash bo'lsa, to'xtatamiz.
        {
            let mut s = state.lock().map_err(|e| e.to_string())?;
            if let Some(c) = s.cancel.take() {
                c.cancel();
            }
        }

        let cancel = CancellationToken::new();
        {
            let mut s = state.lock().map_err(|e| e.to_string())?;
            s.cancel = Some(cancel.clone());
        }

        // Pipeline'ni alohida task'da ishga tushiramiz — command darhol qaytadi.
        let app2 = app.clone();
        tokio::spawn(async move {
            if let Err(e) = pipeline::run(&app2, &domain, cancel).await {
                tracing::error!("pipeline error: {e:?}");
                let _ = app2.emit(
                    "pipeline-event",
                    models::PipelineEvent {
                        stage: "Report".into(),
                        status: "error".into(),
                        message: format!("pipeline failed: {e}"),
                        count: 0,
                        progress: 1.0,
                    },
                );
            }
        });

        Ok(())
    }

    /// Joriy pipeline'ni to'xtatadi.
    #[tauri::command]
    pub async fn stop_scan(state: State<'_, Mutex<ScanState>>) -> Result<(), String> {
        let mut s = state.lock().map_err(|e| e.to_string())?;
        if let Some(c) = s.cancel.take() {
            c.cancel();
        }
        Ok(())
    }

    /// AI bilan chat. Frontend: `invoke("ai_chat", { message, context, provider, model, apiKey })`.
    #[tauri::command]
    pub async fn ai_chat(
        message: String,
        context: Option<ScanContext>,
        provider: Option<String>,
        model: Option<String>,
        api_key: Option<String>,
    ) -> Result<String, String> {
        // Frontend'dan kelgan parametlar, yo'qsa env'dan o'qiladi.
        let env_cfg = AiConfig::from_env();
        let cfg = match provider {
            Some(p) => AiConfig::new(
                p,
                api_key.unwrap_or(env_cfg.api_key),
                model.unwrap_or(env_cfg.model),
            ),
            None => env_cfg,
        };
        ai::chat(&cfg, &message, context.as_ref())
            .await
            .map_err(|e| e.to_string())
    }

    /// Frontend bu nomni chaqiradi (AI paneli holati uchun).
    /// Bulutli rejimda "doim tayyor" deb qaytaramiz — agar kalit bo'lmasa, xato
    /// ai_chat ichida aniq ko'rsatiladi.
    #[tauri::command]
    pub async fn check_ollama() -> Result<bool, String> {
        let cfg = AiConfig::from_env();
        Ok(!cfg.api_key.trim().is_empty())
    }

    /// Tizim statistikasi — StatusBar uchun.
    #[tauri::command]
    pub async fn get_system_stats() -> Result<SystemStats, String> {
        Ok(stats::snapshot())
    }

    /// Re-scan — yangi WebviewWindow ochadi va berilgan target'ni skan qiladi.
    /// Frontend: `invoke("rescan_item", { target })`.
    #[tauri::command]
    pub async fn rescan_item(app: AppHandle, target: String) -> Result<(), String> {
        let target = target.trim().to_string();
        if target.is_empty() {
            return Err("target is required".into());
        }

        use tauri::WebviewUrl;
        use tauri::WebviewWindowBuilder;

        // URL param orqali target'ni o'tkazamiz: index.html?target=sub.example.com
        let url = format!("index.html?target={}", urlencoding::encode(&target));

        let label = format!("rescan-{}", &target.replace(['.', ':', '/'], "-"));

        WebviewWindowBuilder::new(
            &app,
            &label,
            WebviewUrl::App(url.into()),
        )
        .title(format!("O'MOTIM — Re-scan: {}", &target))
        .inner_size(1200.0, 800.0)
        .min_inner_size(900.0, 600.0)
        .build()
        .map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Yagona pipeline bosqichni mustaqil ishga tushiradi.
    /// Frontend: `invoke("run_single_stage", { domain, stageName })`.
    #[tauri::command]
    pub async fn run_single_stage(
        app: AppHandle,
        domain: String,
        stage_name: String,
    ) -> Result<(), String> {
        let domain = domain.trim().to_string();
        let stage = stage_name.trim().to_string();
        if domain.is_empty() {
            return Err("domain is required".into());
        }
        if stage.is_empty() {
            return Err("stage_name is required".into());
        }

        // Bosqich nomini tekshiramiz — faqat mavjud bosqichlarni qabul qilamiz.
        let valid_stages = [
            "Subdomain Discovery", "DNS Resolver", "HTTP Probe", "Fingerprint",
            "Headers Analysis", "Secrets Scanner", "CVE Match", "Backdoor Hunter",
            "CORS Probe", "Directory Brute", "HTTP Methods", "SSL Inspector",
            "Header Dump", "Open Redirect", "API Discovery", "API Brute Force",
            "Form Analysis", "Broken Links", "Stealth Crawl", "Resource Enum",
            "WS Scanner", "Host Analyze", "Security Probe", "Final Report",
        ];
        if !valid_stages.contains(&stage.as_str()) {
            return Err(format!("Unknown stage: {}", stage));
        }

        // Pipeline'ni faqat shu bosqich uchun ishga tushiramiz.
        let cancel = CancellationToken::new();
        let app2 = app.clone();
        tokio::spawn(async move {
            if let Err(e) = pipeline::run_single(&app2, &domain, &stage, cancel).await {
                tracing::error!("single stage error: {e:?}");
                let _ = app2.emit(
                    "pipeline-event",
                    models::PipelineEvent {
                        stage: stage.clone(),
                        status: "error".into(),
                        message: format!("stage failed: {e}"),
                        count: 0,
                        progress: 1.0,
                    },
                );
            }
        });

        Ok(())
    }
}
