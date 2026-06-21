//! Reconnaissance pipeline — 32 bosqich (parasite'dan kuchli scanlar qo'shilgan).
//!
//! Lethal(1-beta) toolkidagi yondashuvlardan foydalanilgan:
//!   - `reqwest` + `rustls`        (HTTP prob, kam resurs)
//!   - `hickory-resolver`           (DNS resolver)
//!   - `scraper` + `regex`          (fingerprint & secrets)
//!   - crt.sh + DNS-over-HTTPS      (subdomain discovery)
//!
//! Har bir bosqich `emit("pipeline-event", ...)` yuboradi,
//! oxirida `emit("scan-complete", ctx)` bilan yakunlanadi.
//! Graph vizualizatsiya uchun `emit("graph-ready", graph)` ham yuboriladi.

use crate::models::*;
use crate::ops;
use anyhow::Result;
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use tokio_util::sync::CancellationToken;

/// Bosqich nomlari — frontend bilan AYNAN bir xil.
pub const STAGES: &[&str] = &[
    // Discovery (1-3)
    "Subdomain Discovery",
    "DNS Resolver",
    "HTTP Probe",
    // Analysis (4-6)
    "Fingerprint",
    "Headers Analysis",
    "Secrets Scanner",
    // Vulnerability (7-9)
    "CVE Match",
    "Backdoor Hunter",
    "CORS Probe",
    // Deep Scan (10-15)
    "Directory Brute",
    "HTTP Methods",
    "SSL Inspector",
    "Header Dump",
    "Open Redirect",
    "API Discovery",
    // Recon (16-21)
    "API Brute Force",
    "Form Analysis",
    "Broken Links",
    "Stealth Crawl",
    "Resource Enum",
    "WS Scanner",
    // Host Deep (22-24)
    "Host Analyze",
    "Security Probe",
    // Report (25)
    "Final Report",
];

/// Bosqichlar umumiy progress'ini hisoblash uchun.
const STAGE_COUNT: usize = 24;

/// Butun pipeline'ni boshqaradi.
pub async fn run(app: &AppHandle, domain: &str, cancel: CancellationToken) -> Result<()> {
    let t0 = Instant::now();
    let domain = domain.trim_start_matches("https://").trim_start_matches("http://");
    let domain = domain.split('/').next().unwrap_or(domain).to_string();

    let mut subdomains: Vec<String>;
    let ips: HashMap<String, Vec<String>>;
    let mut http_results: Vec<HttpResult>;
    let mut technologies: Vec<Technology>;
    let mut headers_analysis: Vec<HeaderIssue>;
    let mut secrets: Vec<Secret>;
    let mut cves: Vec<CveMatch>;

    // Parasite operatsiyalari natijalari
    let backdoors: Vec<BackdoorResult>;
    let directories: Vec<DirectoryResult>;
    let cors_results: Vec<CorsResult>;
    let http_methods: Vec<HttpMethodResult>;
    let ssl_results: Vec<SslResult>;
    let header_dumps: Vec<HeaderDumpResult>;
    let open_redirects: Vec<OpenRedirectResult>;
    let mut api_endpoints: Vec<ApiEndpointResult>;
    let forms: Vec<FormResult>;
    let broken_links: Vec<BrokenLinkResult>;
    let crawl_results: Vec<CrawlResult>;
    let resources: Vec<ResourceResult>;
    let ws_results: Vec<WsResult>;
    let analyze_results: Vec<AnalyzeResult>;
    let security_probes: Vec<SecurityProbeResult>;

    macro_rules! emit {
        ($i:expr, $status:expr, $msg:expr, $count:expr) => {{
            let progress = ($i as f32 + match $status {
                "done" => 1.0,
                "running" => 0.5,
                _ => 0.0,
            }) / STAGE_COUNT as f32;
            let _ = app.emit(
                "pipeline-event",
                PipelineEvent {
                    stage: STAGES[$i].into(),
                    status: $status.into(),
                    message: $msg.into(),
                    count: $count as i64,
                    progress,
                },
            );
        }};
    }

    // Partial graph — incremental. Yangi node'lar front'ga "graph-partial" event'i bilan.
    let mut partial_nodes: Vec<GraphNode> = Vec::new();
    let mut partial_edges: Vec<GraphEdge> = Vec::new();
    // Domain markaziy node — boshlanishiga qo'shamiz.
    let domain_id = format!("domain:{domain}");
    partial_nodes.push(GraphNode {
        id: domain_id.clone(),
        label: domain.clone(),
        node_type: "domain".into(),
        color: crate::graph::color_for("domain").into(),
        detail: Some(format!("Root domain")),
    });

    // Yordamchi: yangi node qo'shish (agar mavjud bo'lmasa) + edge.
    macro_rules! add_node {
        ($id:expr, $label:expr, $ntype:expr, $detail:expr, $parent:expr, $elabel:expr) => {{
            let id = $id;
            if !partial_nodes.iter().any(|n| n.id == id) {
                partial_nodes.push(GraphNode {
                    id: id.clone(),
                    label: $label,
                    node_type: $ntype.into(),
                    color: crate::graph::color_for($ntype).into(),
                    detail: $detail,
                });
                if !$parent.is_empty() {
                    partial_edges.push(GraphEdge {
                        source: $parent.into(),
                        target: id,
                        label: $elabel.into(),
                    });
                }
            }
        }};
    }

    // Yordamchi: hozirgi partial graph'ni front'ga emit qilish.
    macro_rules! emit_graph {
        () => {{
            let snapshot = GraphData {
                nodes: partial_nodes.clone(),
                edges: partial_edges.clone(),
            };
            let _ = app.emit("graph-partial", &snapshot);
        }};
    }

    // Yordamchi: bosqich natijasini front'ga emit qilish (progressive context).
    macro_rules! emit_results {
        ($stage:expr, $field:ident, $val:expr) => {{
            let mut sr = StageResult { stage: $stage.into(), ..Default::default() };
            sr.$field = Some($val);
            let _ = app.emit("stage-results", &sr);
        }};
    }


    // ── 1. Subdomain Discovery ──────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(0, "running", "Querying crt.sh + DoH...", 0);
    subdomains = stage_subdomains(&domain, &cancel).await.unwrap_or_default();
    if !subdomains.contains(&domain) {
        subdomains.insert(0, domain.clone());
    }
    emit!(0, "done", format!("Discovered {} subdomains", subdomains.len()), subdomains.len());
    emit_results!("Subdomain Discovery", subdomains, subdomains.clone());
    // Partial graph: subdomainlar.
    for sub in subdomains.iter().take(50) {
        let sid = format!("sub:{sub}");
        add_node!(sid, sub.clone(), "subdomain", None, &domain_id, "subdomain");
    }
    emit_graph!();

    // ── 2. DNS Resolver ─────────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(1, "running", "Resolving A/AAAA records...", 0);
    ips = stage_dns(&subdomains, &cancel).await.unwrap_or_default();
    let alive = ips.values().filter(|v| !v.is_empty()).count();
    emit!(1, "done", format!("Resolved {} hosts", alive), alive);
    emit_results!("DNS Resolver", ips, ips.clone());
    // Partial graph: IP manzillar.
    for (host, host_ips) in ips.iter().take(50) {
        let host_id = format!("sub:{host}");
        if !partial_nodes.iter().any(|n| n.id == host_id) {
            add_node!(host_id.clone(), host.clone(), "subdomain", None, &domain_id, "subdomain");
        }
        for ip in host_ips.iter().take(3) {
            let ip_id = format!("ip:{host}:{ip}");
            add_node!(ip_id, ip.clone(), "ip", None, &host_id, "resolves");
        }
    }
    emit_graph!();

    // ── 3. HTTP Probe ───────────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(2, "running", "Probing HTTP/HTTPS (50 workers)...", 0);
    let alive_hosts: Vec<String> = ips
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, _)| k.clone())
        .collect();
    http_results = stage_http_probe(&alive_hosts, &cancel).await.unwrap_or_default();
    emit!(2, "done", format!("Probed {} live hosts", http_results.len()), http_results.len());
    emit_results!("HTTP Probe", http_results, http_results.clone());

    // ── 4. Fingerprint ──────────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(3, "running", "Detecting technologies...", 0);
    technologies = stage_fingerprint(&http_results).await.unwrap_or_default();
    emit!(3, "done", format!("Identified {} technologies", technologies.len()), technologies.len());
    emit_results!("Fingerprint", technologies, technologies.clone());
    // Partial graph: texnologiyalar.
    for tech in technologies.iter().take(30) {
        let tech_id = format!("tech:{}", tech.name);
        add_node!(
            tech_id,
            tech.name.clone(),
            "tech",
            tech.version.as_ref().map(|v| format!("v{v}")),
            &domain_id,
            &tech.category
        );
    }
    emit_graph!();

    // ── 5. Headers Analysis ─────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(4, "running", "Auditing security headers...", 0);
    headers_analysis = stage_headers(&http_results).await.unwrap_or_default();
    emit!(4, "done", format!("Found {} header issues", headers_analysis.len()), headers_analysis.len());
    emit_results!("Headers Analysis", headers_analysis, headers_analysis.clone());

    // ── 6. Secrets Scanner ──────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(5, "running", "Scanning for secrets (12 patterns)...", 0);
    secrets = stage_secrets(&http_results).await.unwrap_or_default();
    emit!(5, "done", format!("Found {} secrets", secrets.len()), secrets.len());
    emit_results!("Secrets Scanner", secrets, secrets.clone());
    // Partial graph: sirlar.
    for (i, secret) in secrets.iter().enumerate().take(20) {
        let sec_id = format!("secret:{i}");
        add_node!(
            sec_id,
            secret.secret_type.clone(),
            "secret",
            Some(secret.preview.clone()),
            &domain_id,
            "leaked"
        );
    }
    emit_graph!();

    // ── 7. CVE Match ────────────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(6, "running", "Matching technologies against CVE DB...", 0);
    cves = stage_cve_match(&technologies).await.unwrap_or_default();
    emit!(6, "done", format!("Matched {} CVEs", cves.len()), cves.len());
    emit_results!("CVE Match", cves, cves.clone());
    // Partial graph: CVElar.
    for tech in technologies.iter().take(30) {
        let tech_id = format!("tech:{}", tech.name);
        for cve in cves.iter().filter(|c| c.affected_tech == tech.name).take(5) {
            let cve_id = format!("cve:{}", cve.cve_id);
            add_node!(
                cve_id,
                cve.cve_id.clone(),
                "cve",
                Some(format!("CVSS {}", cve.cvss_score)),
                &tech_id,
                "vulnerable"
            );
        }
    }
    emit_graph!();

    // Eng tezkor maqsad URL — keyingi operatsiyalar uchun.
    let primary_url = http_results
        .first()
        .map(|r| r.url.clone())
        .unwrap_or_else(|| format!("https://{domain}"));
    let base_url = primary_url
        .split('/')
        .take(3)
        .collect::<Vec<_>>()
        .join("/");

    // ── 8. Backdoor Hunter ──────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(7, "running", "Hunting 62 sensitive files...", 0);
    backdoors = ops::backdoor::run(&base_url, &cancel).await.unwrap_or_default();
    emit!(7, "done", format!("Found {} exposed files", backdoors.len()), backdoors.len());
    emit_results!("Backdoor Hunter", backdoors, backdoors.clone());
    for (i, bd) in backdoors.iter().enumerate().take(30) {
        let bd_id = format!("backdoor:{i}");
        add_node!(
            bd_id,
            bd.path.clone(),
            "backdoor",
            Some(format!("{} (HTTP {})", bd.description, bd.status_code)),
            &domain_id,
            "exposed"
        );
    }
    emit_graph!();

    // ── 9. CORS Probe ───────────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(8, "running", "Testing CORS with 3 evil origins...", 0);
    cors_results = ops::cors::run(&primary_url).await.unwrap_or_default();
    let cors_vulns = cors_results.iter().filter(|c| c.vulnerable).count();
    emit!(8, "done", format!("Found {} CORS issues", cors_vulns), cors_vulns);
    emit_results!("CORS Probe", cors_results, cors_results.clone());

    // ── 10. Directory Brute ─────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(9, "running", "Brute-forcing 120 directories...", 0);
    directories = ops::burrow::run(&base_url, &cancel).await.unwrap_or_default();
    emit!(9, "done", format!("Found {} directories", directories.len()), directories.len());
    emit_results!("Directory Brute", directories, directories.clone());

    // ── 11. HTTP Methods ────────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(10, "running", "Testing 9 HTTP methods...", 0);
    http_methods = ops::http_methods::run(&primary_url).await.unwrap_or_default();
    let dangerous_methods = http_methods.iter().filter(|m| m.dangerous).count();
    emit!(10, "done", format!("Tested {} methods ({} dangerous)", http_methods.len(), dangerous_methods), http_methods.len());
    emit_results!("HTTP Methods", http_methods, http_methods.clone());

    // ── 12. SSL Inspector ───────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(11, "running", "Inspecting SSL/TLS...", 0);
    let ssl_tmp = ops::ssl::run(&primary_url).await.unwrap_or_default();
    ssl_results = vec![ssl_tmp];
    emit!(11, "done", "SSL inspection complete", ssl_results.len());
    emit_results!("SSL Inspector", ssl_results, ssl_results.clone());

    // ── 13. Header Dump ─────────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(12, "running", "Dumping all response headers...", 0);
    let hd_tmp = ops::header_dump::run(&primary_url).await.unwrap_or_default();
    header_dumps = vec![hd_tmp];
    emit!(12, "done", "Headers dumped", header_dumps.len());
    emit_results!("Header Dump", header_dumps, header_dumps.clone());

    // ── 14. Open Redirect ───────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(13, "running", "Testing open redirect (180 combos)...", 0);
    open_redirects = ops::redirect::run(&primary_url).await.unwrap_or_default();
    let redirects_vulns = open_redirects.iter().filter(|r| r.vulnerable).count();
    emit!(13, "done", format!("Found {} redirect vulns", redirects_vulns), open_redirects.len());
    emit_results!("Open Redirect", open_redirects, open_redirects.clone());

    // ── 15. API Discovery ───────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(14, "running", "Discovering API endpoints in JS...", 0);
    api_endpoints = ops::api_discovery::run(&primary_url).await.unwrap_or_default();
    emit!(14, "done", format!("Found {} API endpoints", api_endpoints.len()), api_endpoints.len());

    // ── 16. API Brute Force ─────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(15, "running", "Brute-forcing 57 API paths...", 0);
    let api_brute = ops::api_brute::run(&base_url, &cancel).await.unwrap_or_default();
    let api_total = api_endpoints.len() + api_brute.len();
    // API brute natijalarini ham qo'shamiz.
    let mut api_all = api_endpoints;
    api_all.extend(api_brute);
    api_endpoints = api_all;
    emit!(15, "done", format!("Total {} API endpoints", api_total), api_total);
    emit_results!("API Brute Force", api_endpoints, api_endpoints.clone());
    // Partial graph: API endpointlar.
    for (i, api) in api_endpoints.iter().enumerate().take(30) {
        let api_id = format!("api:{i}");
        add_node!(
            api_id,
            api.path.clone(),
            "api",
            Some(format!("{} via {}", api.method, api.found_in)),
            &domain_id,
            "endpoint"
        );
    }
    emit_graph!();

    // ── 17. Form Analysis ───────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(16, "running", "Extracting HTML forms...", 0);
    forms = ops::forms::run(&primary_url).await.unwrap_or_default();
    emit!(16, "done", format!("Found {} forms", forms.len()), forms.len());
    emit_results!("Form Analysis", forms, forms.clone());
    // Partial graph: formlar.
    for (i, form) in forms.iter().enumerate().take(15) {
        let form_id = format!("form:{i}");
        add_node!(
            form_id,
            format!("{} form", form.form_type),
            "form",
            Some(format!("{} fields", form.fields.len())),
            &domain_id,
            "form"
        );
    }
    emit_graph!();

    // ── 18. Broken Links ────────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(17, "running", "Detecting broken external links...", 0);
    broken_links = ops::broken_links::run(&primary_url, 10).await.unwrap_or_default();
    emit!(17, "done", format!("Found {} hijackable domains", broken_links.len()), broken_links.len());
    emit_results!("Broken Links", broken_links, broken_links.clone());

    // ── 19. Stealth Crawl ───────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(18, "running", "Stealth crawling (15 UA, 7 lang)...", 0);
    crawl_results = ops::crawl::run(&primary_url, 30, &cancel).await.unwrap_or_default();
    emit!(18, "done", format!("Crawled {} pages", crawl_results.len()), crawl_results.len());
    emit_results!("Stealth Crawl", crawl_results, crawl_results.clone());

    // ── 20. Resource Enum ───────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(19, "running", "Enumerating page resources...", 0);
    resources = ops::resources::run(&primary_url).await.unwrap_or_default();
    emit!(19, "done", format!("Found {} resources", resources.len()), resources.len());
    emit_results!("Resource Enum", resources, resources.clone());

    // ── 21. WS Scanner ──────────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(20, "running", "Scanning for WebSocket endpoints...", 0);
    ws_results = ops::websocket::run(&base_url).await.unwrap_or_default();
    emit!(20, "done", format!("Found {} WS endpoints", ws_results.len()), ws_results.len());
    emit_results!("WS Scanner", ws_results, ws_results.clone());

    // ── 22. Host Analyze ────────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(21, "running", "Host biopsy analysis...", 0);
    let mut analyze_tmp = Vec::new();
    for r in http_results.iter().take(5) {
        if let Ok(a) = ops::analyze::run(&r.url).await {
            analyze_tmp.push(a);
        }
    }
    analyze_results = analyze_tmp;
    emit!(21, "done", format!("Analyzed {} hosts", analyze_results.len()), analyze_results.len());
    emit_results!("Host Analyze", analyze_results, analyze_results.clone());

    // ── 23. Security Probe ──────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(22, "running", "A-F security grading...", 0);
    let mut probe_tmp = Vec::new();
    for r in http_results.iter().take(5) {
        if let Ok(p) = ops::security_probe::run(&r.url).await {
            probe_tmp.push(p);
        }
    }
    security_probes = probe_tmp;
    let avg_grade = if security_probes.is_empty() {
        "—".to_string()
    } else {
        // Eng yomon grade.
        security_probes
            .iter()
            .min_by_key(|p| p.score)
            .map(|p| p.grade.clone())
            .unwrap_or_else(|| "—".into())
    };
    emit!(22, "done", format!("Worst grade: {}", avg_grade), security_probes.len());
    emit_results!("Security Probe", security_probes, security_probes.clone());

    // ── 24. Final Report ────────────────────────────────────────────────────────
    if cancel.is_cancelled() { return Ok(()); }
    emit!(23, "running", "Compiling report...", 0);

    let summary = ScanSummary {
        total_subdomains: subdomains.len(),
        alive_hosts: http_results.len(),
        critical_count: cves.iter().filter(|c| matches!(c.severity, Severity::Critical)).count(),
        high_count: cves.iter().filter(|c| matches!(c.severity, Severity::High)).count(),
        medium_count: cves.iter().filter(|c| matches!(c.severity, Severity::Medium)).count(),
        low_count: cves.iter().filter(|c| matches!(c.severity, Severity::Low)).count(),
        secrets_found: secrets.len(),
        elapsed_secs: t0.elapsed().as_secs(),
    };

    let ctx = ScanContext {
        domain: domain.clone(),
        subdomains: std::mem::take(&mut subdomains),
        ips,
        http_results: std::mem::take(&mut http_results),
        technologies: std::mem::take(&mut technologies),
        headers_analysis: std::mem::take(&mut headers_analysis),
        secrets: std::mem::take(&mut secrets),
        cves: std::mem::take(&mut cves),
        summary,
        backdoors,
        directories,
        cors_results,
        http_methods,
        ssl_results,
        header_dumps,
        open_redirects,
        api_endpoints,
        forms,
        broken_links,
        crawl_results,
        resources,
        ws_results,
        analyze_results,
        security_probes,
    };

    // Graph ma'lumotlarini tayyorlab, alohida event bilan yuboramiz.
    let graph = crate::graph::build(&ctx);
    let _ = app.emit("graph-ready", &graph);

    let _ = app.emit("scan-complete", &ctx);

    let _ = app.emit(
        "pipeline-event",
        PipelineEvent {
            stage: STAGES[STAGE_COUNT - 1].into(),
            status: "done".into(),
            message: "Pipeline complete".into(),
            count: 0,
            progress: 1.0,
        },
    );

    Ok(())
}

/// Yagona pipeline bosqichni mustaqil ishga tushiradi.
/// Har bir bosqich o'z natijasini "stage-results" va "pipeline-event" eventlari
/// orqali front'ga yuboradi — to'liq `run` funksiyasiga o'xshash.
pub async fn run_single(
    app: &AppHandle,
    domain: &str,
    stage_name: &str,
    cancel: CancellationToken,
) -> Result<()> {
    let domain = domain.trim_start_matches("https://").trim_start_matches("http://");
    let domain = domain.split('/').next().unwrap_or(domain).to_string();

    let domain_id = format!("domain:{domain}");
    let mut partial_nodes: Vec<GraphNode> = vec![GraphNode {
        id: domain_id.clone(),
        label: domain.clone(),
        node_type: "domain".into(),
        color: crate::graph::color_for("domain").into(),
        detail: Some("Root domain".into()),
    }];
    let mut partial_edges: Vec<GraphEdge> = Vec::new();

    macro_rules! emit_single {
        ($status:expr, $msg:expr, $count:expr) => {{
            let _ = app.emit(
                "pipeline-event",
                PipelineEvent {
                    stage: stage_name.into(),
                    status: $status.into(),
                    message: $msg.into(),
                    count: $count as i64,
                    progress: match $status {
                        "done" => 1.0,
                        "running" => 0.5,
                        _ => 0.0,
                    },
                },
            );
        }};
    }

    macro_rules! add_node_single {
        ($id:expr, $label:expr, $ntype:expr, $detail:expr, $parent:expr, $elabel:expr) => {{
            let id = $id;
            if !partial_nodes.iter().any(|n| n.id == id) {
                partial_nodes.push(GraphNode {
                    id: id.clone(),
                    label: $label,
                    node_type: $ntype.into(),
                    color: crate::graph::color_for($ntype).into(),
                    detail: $detail,
                });
                if !$parent.is_empty() {
                    partial_edges.push(GraphEdge {
                        source: $parent.into(),
                        target: id,
                        label: $elabel.into(),
                    });
                }
            }
        }};
    }

    macro_rules! emit_graph_single {
        () => {{
            let snapshot = GraphData {
                nodes: partial_nodes.clone(),
                edges: partial_edges.clone(),
            };
            let _ = app.emit("graph-partial", &snapshot);
        }};
    }

    macro_rules! emit_results_single {
        ($field:ident, $val:expr) => {{
            let mut sr = StageResult { stage: stage_name.into(), ..Default::default() };
            sr.$field = Some($val);
            let _ = app.emit("stage-results", &sr);
        }};
    }

    // Har bir bosqichni tanlab ishga tushiramiz.
    match stage_name {
        "Subdomain Discovery" => {
            if cancel.is_cancelled() { return Ok(()); }
            emit_single!("running", "Querying crt.sh + DoH...", 0);
            let subs = stage_subdomains(&domain, &cancel).await.unwrap_or_default();
            emit_single!("done", format!("Discovered {} subdomains", subs.len()), subs.len());
            emit_results_single!(subdomains, subs.clone());
            for sub in subs.iter().take(50) {
                add_node_single!(format!("sub:{sub}"), sub.clone(), "subdomain", None, &domain_id, "subdomain");
            }
            emit_graph_single!();
        }
        "DNS Resolver" => {
            if cancel.is_cancelled() { return Ok(()); }
            emit_single!("running", "Resolving A/AAAA records...", 0);
            let subs = vec![domain.clone()];
            let resolved = stage_dns(&subs, &cancel).await.unwrap_or_default();
            let alive = resolved.values().filter(|v| !v.is_empty()).count();
            emit_single!("done", format!("Resolved {} hosts", alive), alive);
            emit_results_single!(ips, resolved.clone());
            for (host, host_ips) in resolved.iter().take(50) {
                let host_id = format!("sub:{host}");
                for ip in host_ips.iter().take(3) {
                    add_node_single!(format!("ip:{host}:{ip}"), ip.clone(), "ip", None, &host_id, "resolves");
                }
            }
            emit_graph_single!();
        }
        "HTTP Probe" => {
            if cancel.is_cancelled() { return Ok(()); }
            emit_single!("running", "Probing HTTP/HTTPS...", 0);
            let results = stage_http_probe(&[domain.clone()], &cancel).await.unwrap_or_default();
            emit_single!("done", format!("Probed {} hosts", results.len()), results.len());
            emit_results_single!(http_results, results);
        }
        "Fingerprint" => {
            if cancel.is_cancelled() { return Ok(()); }
            emit_single!("running", "Fingerprinting technologies...", 0);
            // HTTP probe kerak — qisqacha bajarib o'tamiz.
            let http = stage_http_probe(&[domain.clone()], &cancel).await.unwrap_or_default();
            let techs = stage_fingerprint(&http).await.unwrap_or_default();
            emit_single!("done", format!("Found {} technologies", techs.len()), techs.len());
            emit_results_single!(technologies, techs.clone());
            for t in techs.iter().take(30) {
                let tid = format!("tech:{domain}:{}", t.name.to_lowercase().replace(' ', "-"));
                add_node_single!(tid, t.name.clone(), "tech", None, &domain_id, "uses");
            }
            emit_graph_single!();
        }
        "Headers Analysis" => {
            if cancel.is_cancelled() { return Ok(()); }
            emit_single!("running", "Analyzing headers...", 0);
            let http = stage_http_probe(&[domain.clone()], &cancel).await.unwrap_or_default();
            let issues = stage_headers(&http).await.unwrap_or_default();
            emit_single!("done", format!("Found {} header issues", issues.len()), issues.len());
            emit_results_single!(headers_analysis, issues);
        }
        "Secrets Scanner" => {
            if cancel.is_cancelled() { return Ok(()); }
            emit_single!("running", "Scanning for secrets...", 0);
            let http = stage_http_probe(&[domain.clone()], &cancel).await.unwrap_or_default();
            let secrets = stage_secrets(&http).await.unwrap_or_default();
            emit_single!("done", format!("Found {} secrets", secrets.len()), secrets.len());
            emit_results_single!(secrets, secrets.clone());
            for s in secrets.iter().take(20) {
                let sid = format!("secret:{domain}:{}", s.secret_type.replace(' ', "-"));
                add_node_single!(sid, format!("{}: {}", s.secret_type, s.location), "secret", None, &domain_id, "leaks");
            }
            emit_graph_single!();
        }
        "CVE Match" => {
            if cancel.is_cancelled() { return Ok(()); }
            emit_single!("running", "Matching CVEs...", 0);
            let http = stage_http_probe(&[domain.clone()], &cancel).await.unwrap_or_default();
            let techs = stage_fingerprint(&http).await.unwrap_or_default();
            let cves = stage_cve_match(&techs).await.unwrap_or_default();
            emit_single!("done", format!("Matched {} CVEs", cves.len()), cves.len());
            emit_results_single!(cves, cves.clone());
            for c in cves.iter().take(20) {
                let cid = format!("cve:{domain}:{}", c.cve_id.replace(' ', "-"));
                add_node_single!(cid, c.cve_id.clone(), "cve", None, &domain_id, "vulnerable");
            }
            emit_graph_single!();
        }
        _ => {
            // Boshqa bosqichlar — placeholder. Keyin qo'shiladi.
            emit_single!("running", &format!("Running {}...", stage_name), 0);
            emit_single!("done", &format!("{} complete (stub)", stage_name), 0);
        }
    }

    // Bosqich tugaganligini bildiramiz.
    let _ = app.emit(
        "pipeline-event",
        PipelineEvent {
            stage: stage_name.into(),
            status: "done".into(),
            message: format!("{} finished", stage_name),
            count: 0,
            progress: 1.0,
        },
    );

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 1 — Subdomain Discovery (crt.sh + DNS-over-HTTPS)
// ═══════════════════════════════════════════════════════════════════════════

async fn stage_subdomains(domain: &str, _cancel: &CancellationToken) -> Result<Vec<String>> {
    let mut found: HashSet<String> = HashSet::new();
    let client = http_client(Duration::from_secs(8))?;

    // Yordamchi: URL'dan subdomain'larni ajratib olish.
    let absorb = |s: &str, found: &mut HashSet<String>| {
        for n in s.split(|c: char| c.is_whitespace() || c == ',' || c == '\n' || c == ';') {
            let n = n.trim().trim_start_matches("*.").trim_end_matches('.').to_lowercase();
            if n.ends_with(domain) && n != domain && !n.is_empty() {
                found.insert(n);
            }
        }
    };

    // 1. crt.sh (Certificate Transparency) — 8s timeout.
    let crt_url = format!("https://crt.sh/?q=%25.{domain}&output=json");
    let crt_fut = client.get(&crt_url).send().await;
    if let Ok(resp) = crt_fut {
        if resp.status().is_success() {
            if let Ok(vals) = resp.json::<Vec<Value>>().await {
                for v in vals {
                    if let Some(names) = v.get("name_value").and_then(|n| n.as_str()) {
                        absorb(names, &mut found);
                    }
                }
            }
        }
    }

    // 2. DNS-over-HTTPS (Google + Cloudflare).
    for doh in &["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"] {
        let url = format!("{doh}?name={domain}&type=A");
        let req = client.get(&url).header("Accept", "application/dns-json");
        let probed = tokio::time::timeout(Duration::from_secs(8), req.send()).await;
        if let Ok(Ok(resp)) = probed {
            if let Ok(json) = resp.json::<Value>().await {
                if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
                    for a in answers {
                        if let Some(name) = a.get("name").and_then(|n| n.as_str()) {
                            absorb(name, &mut found);
                        }
                    }
                }
            }
        }
    }

    // 3. HackerTarget — bepul hostsearch API.
    let ht_url = format!("https://api.hackertarget.com/hostsearch/?q={domain}");
    let ht_fut = tokio::time::timeout(Duration::from_secs(8), client.get(&ht_url).send());
    if let Ok(Ok(resp)) = ht_fut.await {
        if resp.status().is_success() {
            if let Ok(text) = resp.text().await {
                for line in text.lines() {
                    if let Some(host) = line.split(',').next() {
                        absorb(host, &mut found);
                    }
                }
            }
        }
    }

    // 4. RapidDNS — sahifani scrape qilamiz.
    let rd_url = format!("https://rapiddns.io/subdomain/{domain}?full=1");
    let rd_fut = tokio::time::timeout(Duration::from_secs(8), client.get(&rd_url).send());
    if let Ok(Ok(resp)) = rd_fut.await {
        if resp.status().is_success() {
            if let Ok(html) = resp.text().await {
                // <td>sub.example.com</td> pattern.
                let re = regex::Regex::new(r">(?:[a-zA-Z0-9_-]+\.)*[a-zA-Z0-9_-]+<").unwrap();
                for m in re.find_iter(&html) {
                    absorb(m.as_str(), &mut found);
                }
            }
        }
    }

    // 5. urlscan.io — agar kalit bo'lsa.
    let us_url = format!("https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000");
    let us_fut = tokio::time::timeout(Duration::from_secs(8), client.get(&us_url).send());
    if let Ok(Ok(resp)) = us_fut.await {
        if resp.status().is_success() {
            if let Ok(json) = resp.json::<Value>().await {
                if let Some(results) = json.get("results").and_then(|r| r.as_array()) {
                    for r in results {
                        if let Some(page) = r.get("page")
                            .and_then(|p| p.get("domain"))
                            .and_then(|d| d.as_str())
                        {
                            absorb(page, &mut found);
                        }
                    }
                }
            }
        }
    }

    // 6. DNS brute — kengaytirilgan wordlist (TOP 2000 emas, eng tez-tez uchraydigan 300+).
    let brute_results = stage_dns_brute(domain, &client).await;
    for s in brute_results {
        found.insert(s);
    }

    let mut out: Vec<String> = found.into_iter().collect();
    out.sort();
    out.dedup();
    Ok(out)
}

/// DNS brute-force — eng tez-tez uchraydigan subdomain prefikslari bilan resolve qilish.
async fn stage_dns_brute(domain: &str, client: &reqwest::Client) -> Vec<String> {
    use futures::stream::{self, StreamExt};
    use std::sync::Arc;
    use tokio::sync::{Mutex, Semaphore};

    // ~300 ta eng tez-tez uchraydigan subdomain prefikslari.
    const WORDS: &[&str] = &[
        "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure",
        "m", "vpn", "api", "dev", "staging", "stage", "test", "demo", "sandbox", "qa",
        "admin", "portal", "app", "dashboard", "panel", "cpanel", "whm", "webdisk", "hosting",
        "shop", "store", "checkout", "pay", "payment", "billing", "cart", "order", "account",
        "login", "signin", "register", "auth", "sso", "oauth", "id", "identity", "profile",
        "ftp", "sftp", "file", "files", "download", "upload", "media", "cdn", "static",
        "assets", "img", "images", "pics", "video", "videos", "stream", "live", "tv",
        "m1", "m2", "new", "old", "v1", "v2", "beta", "alpha", "rc", "pre", "preview",
        "docs", "doc", "wiki", "help", "support", "faq", "kb", "knowledge", "info", "about",
        "forum", "forums", "community", "social", "chat", "messenger", "im", "talk",
        "search", "find", "lookup", "query", "api1", "api2", "rest", "graphql", "rpc",
        "ws", "wss", "socket", "websocket", "realtime", "push", "notify", "notifications",
        "db", "database", "sql", "mysql", "postgres", "redis", "mongo", "elastic", "search",
        "analytics", "stats", "metrics", "monitor", "status", "health", "ping", "heartbeat",
        "log", "logs", "syslog", "audit", "trace", "sentry", "error", "debug",
        "git", "gitlab", "github", "ci", "cd", "jenkins", "build", "deploy", "release",
        "docker", "registry", "k8s", "kubernetes", "consul", "etcd", "vault", "nomad",
        "internal", "int", "intranet", "private", "corp", "office", "hq", "lan",
        "ext", "external", "public", "open", "gateway", "proxy", "edge", "node",
        "mx", "mx1", "mx2", "mx3", "mxa", "mxb", "relay", "post", "postfix", "exchange",
        "imap", "pop", "pop3", "webmail2", "autodiscover", "autoconfig", "dav", "caldav",
        "sip", "voip", "phone", "fax", "sms", "text", "voice", "meet", "conference",
        "cloud", "aws", "gcp", "azure", "s3", "storage", "bucket", "backup", "archive",
        "cache", "memcache", "varnish", "nginx", "apache", "httpd", "tomcat", "jboss",
        "web1", "web2", "web3", "app1", "app2", "app3", "sv1", "sv2", "host", "host1",
        "service", "services", "svc", "micro", "worker", "jobs", "queue", "worker1",
        "b2b", "b2c", "biz", "business", "ent", "enterprise", "pro", "plus", "premium",
        "go", "java", "python", "ruby", "php", "node", "nodejs", "js", "ts",
        "test1", "test2", "uat", "prod", "production", "dr", "failover", "backup1",
        "edu", "training", "learn", "course", "class", "student", "teacher",
        "m3", "m4", "m5", "m6", "m7", "m8", "m9", "m10",
        "nl", "uk", "us", "eu", "de", "fr", "jp", "cn", "ru", "in", "br",
        "cdn1", "cdn2", "edge1", "edge2", "pop1", "pop2", "anycast", "lb", "load",
        "auth1", "auth2", "id1", "id2", "saml", "ad", "ldap", "radius", "tacacs",
        "log1", "log2", "data", "data1", "data2", "warehouse", "lake", "pipeline",
        "img1", "img2", "static1", "static2", "media1", "media2", "video1", "video2",
        "ws1", "ws2", "api3", "api4", "internal1", "internal2", "private1", "private2",
        "edge", "fr1", "fr2", "router", "switch", "fw", "firewall", "ips", "ids",
        "puppet", "chef", "ansible", "terraform", "cloudflare", "fastly", "akamai",
        "status1", "status2", "monitor1", "monitor2", "grafana", "prometheus", "kibana",
    ];

    let resolver = match hickory_resolver::TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => Arc::new(r),
        Err(_) => return Vec::new(),
    };
    let found: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sem = Arc::new(Semaphore::new(30));
    let domain = domain.to_string();

    let tasks: Vec<_> = WORDS.iter().map(|w| format!("{w}.{domain}")).collect();
    stream::iter(tasks)
        .map(|host| {
            let resolver = resolver.clone();
            let found = found.clone();
            let sem = sem.clone();
            async move {
                let _permit = match sem.acquire().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let lookup = resolver.lookup_ip(&host);
                if let Ok(Ok(ips)) = tokio::time::timeout(Duration::from_secs(3), lookup).await {
                    if ips.iter().next().is_some() {
                        found.lock().await.push(host);
                    }
                }
            }
        })
        .buffer_unordered(60)
        .collect::<Vec<()>>()
        .await;

    let _ = client; // client hozircha ishlatilmaydi, lekin imzo saqlandi.
    let mut g = found.lock().await;
    std::mem::take(&mut *g)
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 2 — DNS Resolver (hickory-resolver)
// ═══════════════════════════════════════════════════════════════════════════

async fn stage_dns(hosts: &[String], _cancel: &CancellationToken) -> Result<HashMap<String, Vec<String>>> {
    use hickory_resolver::TokioAsyncResolver;
    use std::net::IpAddr;

    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let mut map = HashMap::new();

    for h in hosts {
        let ips: Vec<String> = match resolver.lookup_ip(h).await {
            Ok(lookup) => lookup.iter().map(|ip: IpAddr| ip.to_string()).collect(),
            Err(_) => Vec::new(),
        };
        map.insert(h.clone(), ips);
    }

    Ok(map)
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 3 — HTTP Probe (50 workers, HTTPS-first)
// ═══════════════════════════════════════════════════════════════════════════

async fn stage_http_probe(hosts: &[String], cancel: &CancellationToken) -> Result<Vec<HttpResult>> {
    use futures::stream::{self, StreamExt};
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    let client = Arc::new(http_client(Duration::from_secs(8))?);
    let results_mutex: Arc<tokio::sync::Mutex<Vec<HttpResult>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(hosts.len())));
    // RAM: concurrencyni 30 bilan cheklash (avval 50 edi).
    let sem = Arc::new(Semaphore::new(30));

    let targets: Vec<String> = hosts
        .iter()
        .flat_map(|h| vec![format!("https://{h}"), format!("http://{h}")])
        .collect();

    stream::iter(targets)
        .map(|url| {
            let client = client.clone();
            let results = results_mutex.clone();
            let cancel = cancel.clone();
            let sem = sem.clone();
            async move {
                if cancel.is_cancelled() {
                    return;
                }
                // RAM: semafor orqali parallelismni cheklash.
                let _permit = match sem.acquire().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                // RAM: har bir so'rov uchun 8s timeout.
                let probe = probe_one(&client, &url);
                if let Ok(Some(r)) = tokio::time::timeout(Duration::from_secs(8), probe).await {
                    results.lock().await.push(r);
                }
            }
        })
        .buffer_unordered(60)
        .collect::<Vec<()>>()
        .await;

    let mut guard = results_mutex.lock().await;
    guard.sort_by(|a, b| a.url.cmp(&b.url));
    let mut seen = HashSet::new();
    guard.retain(|r| {
        let host = r.url.split("://").nth(1).unwrap_or("").to_string();
        if seen.insert(host) {
            true
        } else {
            false
        }
    });
    Ok(std::mem::take(&mut *guard))
}

async fn probe_one(client: &reqwest::Client, url: &str) -> Option<HttpResult> {
    let t0 = Instant::now();
    let resp = client.get(url).send().await.ok()?;
    let elapsed = t0.elapsed().as_millis() as u64;

    let status = resp.status().as_u16();
    let server = resp
        .headers()
        .get("server")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let content_length = resp.content_length();

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // RAM: faqat matnli tanani o'qiymiz va 256KB bilan cheklaymiz (avval cheksiz edi).
    let title = if content_type.contains("text") || content_type.contains("html") {
        // Faqat boshlanish qismini o'qiymiz — title tag shu yerda bo'ladi.
        let bytes = resp.bytes().await.ok()?;
        let cap = std::cmp::min(bytes.len(), 256 * 1024);
        extract_title(std::str::from_utf8(&bytes[..cap]).unwrap_or(""))
            .unwrap_or_default()
    } else {
        String::new()
    };

    Some(HttpResult {
        url: url.to_string(),
        status,
        title,
        server,
        response_time_ms: elapsed,
        redirect_chain: Vec::new(),
        content_length,
    })
}

fn extract_title(html: &str) -> Option<String> {
    let start = html.to_lowercase().find("<title")?;
    let after = &html[start..];
    let open_end = after.find('>')?;
    let close = after.find("</title>")?;
    let title = &after[open_end + 1..close];
    Some(title.trim().to_string())
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 4 — Fingerprint (26 signatures)
// ═══════════════════════════════════════════════════════════════════════════

async fn stage_fingerprint(results: &[HttpResult]) -> Result<Vec<Technology>> {
    let header_sigs: &[(&str, &str, &str, &str)] = &[
        ("server", "nginx", "Nginx", "Web Servers"),
        ("server", "apache", "Apache HTTP Server", "Web Servers"),
        ("server", "iis", "Microsoft IIS", "Web Servers"),
        ("server", "liteSpeed", "LiteSpeed", "Web Servers"),
        ("server", "caddy", "Caddy", "Web Servers"),
        ("x-powered-by", "php", "PHP", "Languages"),
        ("x-powered-by", "asp.net", "ASP.NET", "Frameworks"),
        ("x-powered-by", "express", "Express", "Frameworks"),
        ("x-aspnet-version", "", "ASP.NET", "Frameworks"),
        ("x-generator", "drupal", "Drupal", "CMS"),
        ("x-generator", "joomla", "Joomla", "CMS"),
        ("server", "cloudflare", "Cloudflare", "CDN"),
        ("cf-ray", "", "Cloudflare", "CDN"),
        ("x-amz-cf-id", "", "Amazon CloudFront", "CDN"),
        ("x-fastly-request", "", "Fastly", "CDN"),
        ("x-served-by", "varnish", "Varnish", "Caching"),
        ("x-cache", "", "Cache Service", "Caching"),
        ("x-drupal-cache", "", "Drupal", "CMS"),
        ("set-cookie", "wordpress", "WordPress", "CMS"),
        ("set-cookie", "laravel_session", "Laravel", "Frameworks"),
        ("set-cookie", "django", "Django", "Frameworks"),
        ("set-cookie", "ruby", "Ruby on Rails", "Frameworks"),
        ("x-nextjs-cache", "", "Next.js", "Frameworks"),
        ("x-vercel-id", "", "Vercel", "Hosting"),
        ("via", "1.1 google", "Google Cloud", "Cloud"),
        ("server", "gunicorn", "Gunicorn", "App Servers"),
    ];

    let mut techs: HashMap<String, Technology> = HashMap::new();

    for r in results {
        for (hdr, val, name, cat) in header_sigs {
            if *hdr == "server" {
                if let Some(srv) = &r.server {
                    if srv.to_lowercase().contains(val) {
                        techs.entry(name.to_string()).or_insert(Technology {
                            name: name.to_string(),
                            version: extract_version(srv, val),
                            category: cat.to_string(),
                            confidence: 85,
                        });
                    }
                }
            }
        }
    }

    let mut out: Vec<Technology> = techs.into_values().collect();
    out.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    Ok(out)
}

fn extract_version(server: &str, _tech: &str) -> Option<String> {
    server.split('/').nth(1).map(|s| s.trim().to_string())
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 5 — Headers Analysis
// ═══════════════════════════════════════════════════════════════════════════

async fn stage_headers(_results: &[HttpResult]) -> Result<Vec<HeaderIssue>> {
    let client = http_client(Duration::from_secs(10))?;
    let mut issues = Vec::new();

    let checks: &[(&str, &str, Severity, &str)] = &[
        ("strict-transport-security", "Missing HSTS — no forced HTTPS", Severity::High, "Enable HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        ("content-security-policy", "Missing CSP — XSS risk", Severity::High, "Define a strict Content-Security-Policy"),
        ("x-frame-options", "Missing X-Frame-Options — clickjacking risk", Severity::Medium, "Add X-Frame-Options: DENY or SAMEORIGIN"),
        ("x-content-type-options", "Missing X-Content-Type-Options — MIME sniffing", Severity::Low, "Add X-Content-Type-Options: nosniff"),
        ("referrer-policy", "Missing Referrer-Policy", Severity::Low, "Add Referrer-Policy: no-referrer"),
        ("permissions-policy", "Missing Permissions-Policy", Severity::Info, "Consider adding Permissions-Policy"),
    ];

    let hosts: Vec<String> = _results.iter().take(10).map(|r| r.url.clone()).collect();

    for url in hosts {
        if let Ok(resp) = client.get(&url).send().await {
            let hdrs = resp.headers();
            for (hdr, issue, sev, rec) in checks {
                if !hdrs.contains_key(*hdr) {
                    issues.push(HeaderIssue {
                        url: url.clone(),
                        issue: issue.to_string(),
                        severity: sev.clone(),
                        header: hdr.to_string(),
                        recommendation: rec.to_string(),
                    });
                }
            }
        }
    }

    Ok(issues)
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 6 — Secrets Scanner (12 patterns)
// ═══════════════════════════════════════════════════════════════════════════

async fn stage_secrets(results: &[HttpResult]) -> Result<Vec<Secret>> {
    let patterns: &[(&str, &str, Severity)] = &[
        // Cloud provider keys
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key", Severity::Critical),
        (r#"aws_secret_access_key\s*[=:]\s*['"][A-Za-z0-9/+=]{40}['"]"#, "AWS Secret Key", Severity::Critical),
        (r"ASIA[0-9A-Z]{16}", "AWS STS Key", Severity::Critical),
        (r"AIza[0-9A-Za-z_-]{35}", "Google API Key", Severity::High),
        (r"ya29\.[0-9A-Za-z_-]+", "Google OAuth Token", Severity::High),
        (r"gh[pousr]_[A-Za-z0-9]{36}", "GitHub Token", Severity::High),
        (r"github_pat_[A-Za-z0-9_]{82}", "GitHub PAT", Severity::High),
        (r"glpat-[A-Za-z0-9_-]{20}", "GitLab Token", Severity::High),
        // Stripe
        (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Secret Key", Severity::Critical),
        (r"rk_live_[0-9a-zA-Z]{24}", "Stripe Restricted Key", Severity::Critical),
        (r"pk_live_[0-9a-zA-Z]{24}", "Stripe Publishable Key", Severity::Medium),
        (r"sk_test_[0-9a-zA-Z]{24}", "Stripe Test Key", Severity::Low),
        // Slack
        (r"xox[baprs]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}", "Slack Token", Severity::High),
        (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack Token (legacy)", Severity::High),
        (r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "Slack Webhook", Severity::High),
        // Sendgrid
        (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "Sendgrid API Key", Severity::High),
        // Mailgun
        (r"key-[a-f0-9]{32}", "Mailgun API Key", Severity::High),
        (r"pubkey-[a-f0-9]{32}", "Mailgun Public Key", Severity::Medium),
        // Heroku
        (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "Possible Heroku/UUID API Key", Severity::Low),
        // NPM
        (r"npm_[a-zA-Z0-9]{36}", "NPM Access Token", Severity::High),
        // Discord
        (r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}", "Discord Bot Token", Severity::High),
        // Telegram
        (r"[0-9]{8,10}:[A-Za-z0-9_-]{35}", "Telegram Bot Token", Severity::High),
        // Twilio
        (r"SK[0-9a-fA-F]{32}", "Twilio API Key", Severity::High),
        (r"AC[0-9a-fA-F]{32}", "Twilio Account SID", Severity::Medium),
        // Square
        (r"sq0atp-[0-9A-Za-z_-]{22}", "Square Access Token", Severity::Critical),
        (r"sq0csp-[0-9A-Za-z_-]{43}", "Square Client Secret", Severity::Critical),
        // PayPal
        (r"access_token\[production\]=[0-9A-Za-z]+", "PayPal Access Token", Severity::Critical),
        // JWT
        (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT Token", Severity::Medium),
        // Private keys
        (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key", Severity::Critical),
        (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP Private Key", Severity::Critical),
        // Hashes / generic secrets
        (r#"password\s*[=:]\s*['"][^'"\s]{6,}['"]"#, "Hardcoded Password", Severity::High),
        (r#"passwd\s*[=:]\s*['"][^'"\s]{6,}['"]"#, "Hardcoded Password", Severity::High),
        (r#"api[_-]?key\s*[=:]\s*['"][A-Za-z0-9_-]{16,}['"]"#, "API Key", Severity::Medium),
        (r#"secret\s*[=:]\s*['"][A-Za-z0-9_-]{16,}['"]"#, "Hardcoded Secret", Severity::High),
        (r#"token\s*[=:]\s*['"][A-Za-z0-9_-]{16,}['"]"#, "Hardcoded Token", Severity::Medium),
        (r#"auth\s*[=:]\s*['"][A-Za-z0-9_-]{16,}['"]"#, "Hardcoded Auth", Severity::Medium),
        // Database connection strings
        (r"mongodb(\+srv)?://[A-Za-z0-9_-]+:[^@]+@[A-Za-z0-9.-]+", "MongoDB Connection String", Severity::Critical),
        (r"postgres(ql)?://[A-Za-z0-9_-]+:[^@]+@[A-Za-z0-9.-]+", "PostgreSQL Connection String", Severity::Critical),
        (r"mysql://[A-Za-z0-9_-]+:[^@]+@[A-Za-z0-9.-]+", "MySQL Connection String", Severity::Critical),
        (r"redis://[^@]+@[A-Za-z0-9.-]+", "Redis Connection String", Severity::High),
        (r#"Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=[^;]+"#, "SQL Server Connection", Severity::Critical),
        // Generic SHA1 (high false positive, keep at Low)
        (r"\b[a-f0-9]{40}\b", "Possible SHA1 secret", Severity::Low),
    ];

    let compiled: Vec<(Regex, &str, Severity)> = patterns
        .iter()
        .filter_map(|(p, name, sev)| Regex::new(p).ok().map(|r| (r, *name, sev.clone())))
        .collect();

    let mut secrets = Vec::new();
    let mut seen = HashSet::new();

    // URL'larda qidiramiz.
    for r in results {
        let sources = [r.url.as_str()];
        for s in sources {
            for (re, name, sev) in &compiled {
                for m in re.find_iter(s) {
                    let preview = if m.as_str().len() > 12 {
                        format!("{}…", &m.as_str()[..8])
                    } else {
                        m.as_str().to_string()
                    };
                    let key = (name, preview.clone());
                    if seen.insert(key) {
                        secrets.push(Secret {
                            secret_type: name.to_string(),
                            preview,
                            location: r.url.clone(),
                            severity: sev.clone(),
                        });
                    }
                }
            }
        }
    }

    // HTTP tanalarida qidiramiz — eng birinchi 10 ta URL'ni qayta o'qiymiz.
    let client = crate::pipeline::http_client(Duration::from_secs(8))?;
    for r in results.iter().take(10) {
        if let Ok(resp) = client.get(&r.url).send().await {
            // RAM: faqat 256KB o'qiymiz.
            if let Ok(bytes) = resp.bytes().await {
                let cap = std::cmp::min(bytes.len(), 256 * 1024);
                let body = std::str::from_utf8(&bytes[..cap]).unwrap_or("");
                for (re, name, sev) in &compiled {
                    for m in re.find_iter(body) {
                        let preview = if m.as_str().len() > 12 {
                            format!("{}…", &m.as_str()[..8])
                        } else {
                            m.as_str().to_string()
                        };
                        let key = (name, preview.clone());
                        if seen.insert(key) {
                            secrets.push(Secret {
                                secret_type: name.to_string(),
                                preview,
                                location: r.url.clone(),
                                severity: sev.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(secrets)
}

// ═══════════════════════════════════════════════════════════════════════════
// STAGE 7 — CVE Match (statik ma'lumot bazasi)
// ═══════════════════════════════════════════════════════════════════════════

async fn stage_cve_match(techs: &[Technology]) -> Result<Vec<CveMatch>> {
    let cve_db: &[(&str, &str, f32, Severity, &str)] = &[
        ("CVE-2021-23017", "nginx DNS resolver off-by-one", 7.7, Severity::High, "nginx"),
        ("CVE-2019-11043", "PHP-FPM remote code execution", 9.8, Severity::Critical, "php"),
        ("CVE-2021-41773", "Apache 2.4.49 path traversal", 9.8, Severity::Critical, "apache"),
        ("CVE-2018-1000110", "WordPress SSRF", 7.5, Severity::High, "wordpress"),
        ("CVE-2019-11358", "jQuery prototype pollution", 6.1, Severity::Medium, "jquery"),
        ("CVE-2022-23602", "Drupal XSS", 6.1, Severity::Medium, "drupal"),
    ];

    let mut matches = Vec::new();
    for t in techs {
        let tname = t.name.to_lowercase();
        for (id, desc, cvss, sev, affected) in cve_db {
            if tname.contains(affected) {
                matches.push(CveMatch {
                    cve_id: id.to_string(),
                    description: desc.to_string(),
                    cvss_score: *cvss,
                    severity: sev.clone(),
                    affected_tech: t.name.clone(),
                    affected_urls: Vec::new(),
                    published: "2021-01-01".into(),
                });
            }
        }
    }

    Ok(matches)
}

// ═══════════════════════════════════════════════════════════════════════════
// Yordamchilar
// ═══════════════════════════════════════════════════════════════════════════

/// Owns client — http_client_shared'ning wrapsiz versiyasi.
pub fn http_client(timeout: Duration) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent("O'MOTIM/0.1 (+https://github.com/)")
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .gzip(true)
        .build()?)
}

/// Arc<Client> qaytaradi — concurrent operatsiyalar uchun.
pub fn http_client_shared(timeout: Duration) -> Result<reqwest::Client> {
    // Aslida oddiy Client qaytaramiz — Arc caller tomonidan o'raladi.
    http_client(timeout)
}
