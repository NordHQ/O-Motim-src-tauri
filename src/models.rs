//! Frontend (scanStore.ts) bilan bir xil ma'lumotlar tuzilmasi.
//!
//! Hammasi `#[derive(Serialize)]` — Tauri orqali JSON'ga aylanadi.
//! Maydon nomlari frontend bilan AYNAN bir xil bo'lishi shart (snake_case).

use serde::{Deserialize, Serialize};

/// Bosqich holati — frontend `StageStatus` tipiga mos.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StageStatus {
    Pending,
    Running,
    Done,
    Error,
    Skipped,
}

/// Frontend'ga yuboriladigan pipeline event'i.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PipelineEvent {
    pub stage: String,
    pub status: String, // frontend string kutadi: "running" | "done" | ...
    pub message: String,
    pub count: i64,
    pub progress: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpResult {
    pub url: String,
    pub status: u16,
    pub title: String,
    pub server: Option<String>,
    pub response_time_ms: u64,
    pub redirect_chain: Vec<String>,
    pub content_length: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Technology {
    pub name: String,
    pub version: Option<String>,
    pub category: String,
    pub confidence: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderIssue {
    pub url: String,
    pub issue: String,
    pub severity: Severity,
    pub header: String,
    pub recommendation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secret {
    pub secret_type: String,
    pub preview: String,
    pub location: String,
    pub severity: Severity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CveMatch {
    pub cve_id: String,
    pub description: String,
    pub cvss_score: f32,
    pub severity: Severity,
    pub affected_tech: String,
    pub affected_urls: Vec<String>,
    pub published: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_subdomains: usize,
    pub alive_hosts: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub secrets_found: usize,
    pub elapsed_secs: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
// Parasite'dan olingan yangi scan natija tuzilmalari
// ═══════════════════════════════════════════════════════════════════════════

/// Backdoor Hunter — 62 sensitiv fayl natijasi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackdoorResult {
    pub path: String,
    pub description: String,
    pub severity: String,
    pub status_code: u16,
    pub url: String,
}

/// Directory Brute — brute-force natijasi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResult {
    pub path: String,
    pub status_code: u16,
    pub url: String,
}

/// CORS Probe — CORS misconfiguration natijasi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorsResult {
    pub origin: String,
    pub allow_origin: String,
    pub allow_credentials: bool,
    pub vulnerable: bool,
}

/// HTTP Methods — metod test natijasi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpMethodResult {
    pub method: String,
    pub status_code: u16,
    pub dangerous: bool,
}

/// SSL Inspector — SSL/TLS tekshirish natijasi.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SslResult {
    pub url: String,
    pub https_active: bool,
    pub http_to_https_redirect: bool,
    pub hsts: bool,
    pub hsts_value: Option<String>,
    pub has_csp: bool,
    pub has_x_frame_options: bool,
    pub has_x_content_type_options: bool,
    pub has_referrer_policy: bool,
}

/// Open Redirect — ochiq redirect natijasi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenRedirectResult {
    pub parameter: String,
    pub payload_type: String,
    pub payload: String,
    pub redirect_location: Option<String>,
    pub vulnerable: bool,
}

/// API Endpoint — API topish natijasi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiEndpointResult {
    pub method: String,
    pub path: String,
    pub params: Vec<String>,
    pub found_in: String,
}

/// Form Analysis — forma tahlili natijasi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FormResult {
    pub action: String,
    pub form_method: String,
    pub form_type: String,
    pub fields: Vec<FormFieldResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FormFieldResult {
    pub name: String,
    pub field_type: String,
    pub has_password: bool,
}

/// Broken Link — o'lik domen natijasi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BrokenLinkResult {
    pub domain: String,
    pub status: String, // "alive" | "dead"
    pub pages: Vec<String>,
}

/// Header Dump — barcha header natijasi.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HeaderDumpResult {
    pub url: String,
    pub headers: Vec<(String, String)>, // (name, value)
    pub security_headers: Vec<String>,    // topilgan security header nomlari
}

/// Stealth Crawl / Shadow Crawl natijasi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrawlResult {
    pub url: String,
    pub title: String,
    pub status_code: u16,
    pub content_type: String,
    pub depth: u32,
}

/// Resource Enum — resurs topish natijasi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceResult {
    pub url: String,
    pub resource_type: String, // "image" | "script" | "style" | "font" | "audio" | "video"
    pub size: Option<u64>,
}

/// WebSocket — WS topish natijasi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WsResult {
    pub url: String,
    pub reachable: bool,
}

/// Host Analyze — host biopsy natijasi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalyzeResult {
    pub url: String,
    pub status: u16,
    pub title: String,
    pub server: Option<String>,
    pub tech: Vec<String>,
    pub links_count: usize,
    pub has_csp: bool,
    pub has_hsts: bool,
    pub score: i32,
}

/// Security Probe — A-F graded audit natijasi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityProbeResult {
    pub url: String,
    pub grade: String, // A, B, C, D, F
    pub score: i32,    // 0-100
    pub findings: Vec<SecurityFinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub header: String,
    pub present: bool,
    pub value: Option<String>,
    pub points: i32,
}

// ═══════════════════════════════════════════════════════════════════════════
// Graph tuzilmasi — parasite vizualizatsiya uchun
// ═══════════════════════════════════════════════════════════════════════════

/// Grafdagi tugun (node).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub node_type: String, // "domain" | "subdomain" | "ip" | "tech" | "cve" | "secret" | "backdoor" | "api" | "form" | "url"
    pub color: String,
    pub detail: Option<String>,
}

/// Grafdagi qirra (edge).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub label: String,
}

/// Butun graf ma'lumotlari — "graph-ready" event'ida yuboriladi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GraphData {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Butun skanlash konteksti — "scan-complete" event'ida yuboriladi
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanContext {
    pub domain: String,
    pub subdomains: Vec<String>,
    pub ips: std::collections::HashMap<String, Vec<String>>,
    pub http_results: Vec<HttpResult>,
    pub technologies: Vec<Technology>,
    pub headers_analysis: Vec<HeaderIssue>,
    pub secrets: Vec<Secret>,
    pub cves: Vec<CveMatch>,
    pub summary: ScanSummary,

    // Parasite operatsiyalari natijalari
    pub backdoors: Vec<BackdoorResult>,
    pub directories: Vec<DirectoryResult>,
    pub cors_results: Vec<CorsResult>,
    pub http_methods: Vec<HttpMethodResult>,
    pub ssl_results: Vec<SslResult>,
    pub header_dumps: Vec<HeaderDumpResult>,
    pub open_redirects: Vec<OpenRedirectResult>,
    pub api_endpoints: Vec<ApiEndpointResult>,
    pub forms: Vec<FormResult>,
    pub broken_links: Vec<BrokenLinkResult>,
    pub crawl_results: Vec<CrawlResult>,
    pub resources: Vec<ResourceResult>,
    pub ws_results: Vec<WsResult>,
    pub analyze_results: Vec<AnalyzeResult>,
    pub security_probes: Vec<SecurityProbeResult>,
}

/// StatusBar uchun tizim statistikasi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemStats {
    pub cpu_usage: f32,
    pub ram_used_mb: u64,
    pub ram_total_mb: u64,
    pub thread_count: usize,
}

/// Bosqich natijasi — "stage-results" event'ida yuboriladi.
/// Har bir maydon ixtiyoriy — faqat tugagan bosqichga tegishli maydonlar to'ldiriladi.
/// Frontend buni incrementally ScanContext'ga qo'shadi.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StageResult {
    pub stage: String,
    pub subdomains: Option<Vec<String>>,
    pub ips: Option<std::collections::HashMap<String, Vec<String>>>,
    pub http_results: Option<Vec<HttpResult>>,
    pub technologies: Option<Vec<Technology>>,
    pub headers_analysis: Option<Vec<HeaderIssue>>,
    pub secrets: Option<Vec<Secret>>,
    pub cves: Option<Vec<CveMatch>>,
    pub backdoors: Option<Vec<BackdoorResult>>,
    pub directories: Option<Vec<DirectoryResult>>,
    pub cors_results: Option<Vec<CorsResult>>,
    pub http_methods: Option<Vec<HttpMethodResult>>,
    pub ssl_results: Option<Vec<SslResult>>,
    pub header_dumps: Option<Vec<HeaderDumpResult>>,
    pub open_redirects: Option<Vec<OpenRedirectResult>>,
    pub api_endpoints: Option<Vec<ApiEndpointResult>>,
    pub forms: Option<Vec<FormResult>>,
    pub broken_links: Option<Vec<BrokenLinkResult>>,
    pub crawl_results: Option<Vec<CrawlResult>>,
    pub resources: Option<Vec<ResourceResult>>,
    pub ws_results: Option<Vec<WsResult>>,
    pub analyze_results: Option<Vec<AnalyzeResult>>,
    pub security_probes: Option<Vec<SecurityProbeResult>>,
}

impl Severity {
    /// AI prompt'i uchun matn ko'rinishi.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Info",
        }
    }
}
