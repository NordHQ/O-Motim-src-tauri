//! API Brute Force — 57 ta umumiy API endpoint'ni brute-force.
//!
//! Parasite `symbiosis.rs`'dan olingan: 404 emas natijalar.

use crate::models::ApiEndpointResult;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// 57 ta umumiy API/documentation endpoint path'i.
const API_PATHS: &[(&str, &str)] = &[
    ("/api", "API root"),
    ("/api/v1", "API v1"),
    ("/api/v2", "API v2"),
    ("/api/v3", "API v3"),
    ("/rest", "REST root"),
    ("/rest/v1", "REST v1"),
    ("/graphql", "GraphQL endpoint"),
    ("/graphiql", "GraphiQL UI"),
    ("/playground", "GraphQL Playground"),
    ("/swagger", "Swagger"),
    ("/swagger-ui.html", "Swagger UI"),
    ("/api-docs", "API docs"),
    ("/openapi.json", "OpenAPI spec JSON"),
    ("/openapi.yaml", "OpenAPI spec YAML"),
    ("/api/swagger.json", "Swagger JSON"),
    ("/api/swagger.yaml", "Swagger YAML"),
    ("/api/spec", "API spec"),
    ("/api/schema", "API schema"),
    ("/api/health", "API health"),
    ("/api/status", "API status"),
    ("/api/version", "API version"),
    ("/api/info", "API info"),
    ("/api/ping", "API ping"),
    ("/api/users", "Users endpoint"),
    ("/api/user", "User endpoint"),
    ("/api/auth", "Auth endpoint"),
    ("/api/login", "Login endpoint"),
    ("/api/token", "Token endpoint"),
    ("/api/refresh", "Refresh endpoint"),
    ("/api/me", "Profile endpoint"),
    ("/api/profile", "Profile endpoint"),
    ("/api/admin", "Admin API"),
    ("/api/metrics", "Metrics API"),
    ("/api/logs", "Logs API"),
    ("/api/search", "Search API"),
    ("/api/products", "Products API"),
    ("/api/orders", "Orders API"),
    ("/.well-known/openid-configuration", "OIDC config"),
    ("/.well-known/jwks.json", "JWKS"),
    ("/oauth/token", "OAuth token"),
    ("/oauth/authorize", "OAuth authorize"),
    ("/metrics", "Prometheus metrics"),
    ("/health", "Health check"),
    ("/healthz", "Healthz"),
    ("/readyz", "Readyz"),
    ("/debug/pprof", "Go pprof"),
    ("/actuator", "Spring actuator"),
    ("/actuator/health", "Actuator health"),
    ("/actuator/env", "Actuator env"),
    ("/actuator/beans", "Actuator beans"),
    ("/actuator/mappings", "Actuator mappings"),
    ("/actuator/configprops", "Actuator config"),
    ("/actuator/heapdump", "Actuator heapdump"),
    ("/console", "Spring console"),
    ("/h2-console", "H2 console"),
    ("/druid", "Druid console"),
];

/// Berilgan base URL uchun API endpoint brute-force.
pub async fn run(
    base_url: &str,
    cancel: &CancellationToken,
) -> Result<Vec<ApiEndpointResult>> {
    let client = Arc::new(crate::pipeline::http_client_shared(Duration::from_secs(8))?);
    let results: Arc<tokio::sync::Mutex<Vec<ApiEndpointResult>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let base = base_url.trim_end_matches('/').to_string();

    // Owned string'larga aylantiramiz — closure referencelarsiz ishlashi uchun.
    let owned: Vec<String> = API_PATHS.iter().map(|(p, _)| p.to_string()).collect();

    stream::iter(owned)
        .map(|path| {
            let client = client.clone();
            let results = results.clone();
            let base = base.clone();
            let cancel = cancel.clone();
            async move {
                if cancel.is_cancelled() {
                    return;
                }
                let url = format!("{base}{path}");
                if let Ok(resp) = client.get(&url).send().await {
                    let status = resp.status().as_u16();
                    if status != 404 {
                        results.lock().await.push(ApiEndpointResult {
                            method: "GET".to_string(),
                            path,
                            params: Vec::new(),
                            found_in: format!("HTTP {status}"),
                        });
                    }
                }
            }
        })
        .buffer_unordered(15)
        .collect::<Vec<()>>()
        .await;

    let mut guard = results.lock().await;
    // Path bo'yicha saralash.
    guard.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(std::mem::take(&mut *guard))
}
