<div align="center">

# O'MOTIM — Rust Backend

**`src-tauri` — the Rust/Tauri v2 backend for O'MOTIM**

[![Rust](https://img.shields.io/badge/Rust-1.77+-orange?logo=rust)](https://rustup.rs)
[![Tauri](https://img.shields.io/badge/Tauri-v2-blue?logo=tauri)](https://tauri.app)
[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg)](LICENSE)

**Tags:** `osint` `pentest` `reconnaissance` `rust` `tauri` `cybersecurity` `security-tools` `hacking`

*This repo is the `src-tauri/` directory for [NordHQ/O-Motim](https://github.com/NordHQ/O-Motim)*

</div>

---

## Overview

This is the Rust backend powering O'MOTIM. It implements:

- **Pipeline orchestrator** — runs 24 stages sequentially/in-parallel, with cancellation token and CPU/RAM throttle
- **Shared context** — all stages read/write a single `ScanContext` (no duplicated HTTP calls)
- **Tauri IPC commands** — frontend communicates via typed commands and real-time events
- **AI integration** — Gemini, Ollama, OpenAI, Anthropic

---

## Structure

```
src/
├── main.rs                    Tauri app entry point
├── lib.rs                     Command registration
│
├── pipeline/
│   ├── orchestrator.rs        Stage runner, cancel token, event emitter
│   ├── context.rs             ScanContext — shared state between all stages
│   └── throttle.rs            CPU/RAM watchdog (auto-yield at >80% CPU)
│
├── modules/
│   ├── subdomains.rs          6-source subdomain discovery
│   ├── dns.rs                 Async DNS resolver (hickory)
│   ├── http_probe.rs          HTTP probe, 30-worker semaphore
│   ├── fingerprint.rs         Tech detection, 26 signatures (lazy_static regex)
│   ├── headers.rs             Security header analysis
│   ├── secrets.rs             40+ regex secret patterns
│   ├── cve.rs                 NVD API v2 + OSV.dev CVE matching
│   ├── backdoor.rs            220+ sensitive path checker
│   ├── cors.rs                CORS misconfiguration detection
│   ├── open_redirect.rs       180-combo redirect tester
│   ├── ssl.rs                 TLS/SSL inspection
│   ├── http_methods.rs        Dangerous method detection
│   ├── header_dump.rs         Raw header collector
│   ├── api_discovery.rs       JS analysis + endpoint extraction
│   ├── api_brute.rs           API endpoint brute forcer
│   ├── forms.rs               HTML form extractor
│   ├── dead_links.rs          Broken link / hijackable domain finder
│   ├── stealth_crawl.rs       Rotating UA/header crawler
│   ├── resource_enum.rs       Static resource enumerator
│   ├── ws_scanner.rs          WebSocket endpoint detector
│   ├── host_analyze.rs        Host metadata collector
│   ├── security_probe.rs      Security grade scorer
│   ├── dirs.rs                Directory brute force (streaming)
│   ├── score.rs               Finding prioritizer
│   └── report.rs              HTML + JSON report writer
│
└── commands/
    ├── scan.rs                start_scan / stop_scan / get_scan_context
    ├── ai.rs                  ai_chat / check_ollama / list_models
    └── system.rs              get_system_stats
```

---

## Key Design Decisions

### Shared ScanContext
Every module receives `&mut ScanContext` — a single struct holding all findings. This means fingerprinting can immediately inform CVE matching, HTTP probe results feed into secrets scanning, and so on.

```rust
pub struct ScanContext {
    pub domain:        String,
    pub subdomains:    Vec<String>,
    pub ips:           HashMap<String, Vec<IpAddr>>,
    pub http_results:  Vec<HttpResult>,
    pub technologies:  Vec<Technology>,
    pub header_issues: Vec<HeaderIssue>,
    pub secrets:       Vec<Secret>,
    pub cves:          Vec<CveMatch>,
    pub backdoors:     Vec<Backdoor>,
    pub dirs:          Vec<DirResult>,
    pub summary:       ScanSummary,
}
```

### Streaming via Tauri Events
Every finding is emitted to the frontend immediately — the UI never waits for a stage to finish:

```rust
window.emit("pipeline-event", PipelineEvent {
    stage: "backdoor",
    status: StageStatus::Running,
    message: format!("Found: {path}"),
    count: ctx.backdoors.len(),
}).ok();
```

### Cancellation
Every async stage receives a `CancellationToken`. Long loops check `cancel.is_cancelled()` frequently so Stop button responds instantly.

### Throttle
`throttle.rs` monitors CPU and RAM via `sysinfo`. If CPU > 80% or RAM > 85%, all workers sleep 500ms. This keeps O'MOTIM from freezing the machine during heavy scans.

### RAM efficiency
- No headless Chrome — HTML reports open with `open::that()`
- HTTP response bodies capped at 256KB
- Semaphore limits concurrency to 30 workers max
- Results streamed immediately, not buffered

---

## Building

```bash
# Clone alongside the frontend
cd /path/to/O-Motim
git clone https://github.com/NordHQ/O-Motim-src-tauri.git src-tauri

# Check (fast)
cargo check

# Build release
cargo build --release

# Or via Tauri CLI from the frontend root
cargo tauri build
```

### Dependencies

```toml
tokio          = { version = "1", features = ["full"] }
tauri          = { version = "2" }
reqwest        = { version = "0.12", features = ["json", "rustls-tls"] }
hickory-resolver = "0.24"
serde          = { version = "1", features = ["derive"] }
serde_json     = "1"
regex          = "1"
lazy_static    = "1"
rayon          = "1"
dashmap        = "6"
anyhow         = "1"
tokio-util     = "0.7"
sysinfo        = "0.30"
open           = "5"
chrono         = { version = "0.4", features = ["serde"] }
```

---

## Tauri Commands

| Command | Description |
|---------|-------------|
| `start_scan(domain, options)` | Start full pipeline, emits `pipeline-event` per finding |
| `stop_scan()` | Cancel via token, pipeline stops within seconds |
| `get_scan_context()` | Return full `ScanContext` as JSON |
| `get_system_stats()` | CPU%, RAM MB, thread count |
| `ai_chat(message, context)` | Send message + scan context to AI provider |
| `check_ollama()` | Returns true if Ollama running at localhost:11434 |

---

## Adding a Module

1. Create `src/modules/my_module.rs`
2. Implement the `Stage` trait:

```rust
pub struct MyStage;

#[async_trait]
impl Stage for MyStage {
    fn name(&self) -> &str { "My Module" }

    async fn run(
        &self,
        ctx: &mut ScanContext,
        cancel: &CancellationToken,
        emit: &dyn Fn(PipelineEvent),
    ) -> anyhow::Result<()> {
        // use ctx.http_results, ctx.subdomains, etc.
        // call emit() for each finding
        // check cancel.is_cancelled() in loops
        Ok(())
    }
}
```

3. Add it to the stage list in `orchestrator.rs`

That's it.

---

## License

MIT — see [LICENSE](LICENSE)

*Part of the [O'MOTIM](https://github.com/NordHQ/O-Motim) project by [NordHQ](https://github.com/NordHQ)*
