//! Directory Brute — 120+ directory/file nomlarini brute-force qilish.
//!
//! Parasite `burrow.rs`'dan olingan: HEAD so'rovlari, 404 emas natijalar.

use crate::models::DirectoryResult;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Parasite'dagi ~120 ta directory/file wordlist.
const WORDLIST: &[&str] = &[
    "admin", "wp-admin", "phpmyadmin", "cpanel", "adminer", "administrator",
    "login", "signin", "signup", "register", "account", "user", "users",
    "profile", "dashboard", "panel", "manage", "management", "control",
    "api", "api/v1", "api/v2", "api/v3", "rest", "graphql", "graphql/playground",
    "swagger", "swagger-ui.html", "swagger.json", "swagger.yaml",
    "api-docs", "openapi.json", "openapi.yaml", "docs", "documentation",
    "config", "configuration", "settings", "setup", "install",
    ".env", ".env.local", ".env.production", ".env.backup",
    "backup", "backups", "dump.sql", "backup.sql", "backup.zip", "backup.tar.gz",
    "uploads", "upload", "files", "media", "images", "img", "assets",
    "static", "public", "private", "tmp", "temp", "cache",
    "test", "tests", "testing", "dev", "development", "debug",
    "old", "new", "v1", "v2", "beta", "alpha", "rc",
    "log", "logs", "error.log", "access.log", "debug.log",
    "index.php", "index.html", "default.html", "robots.txt", "sitemap.xml",
    ".git/HEAD", ".git/config", ".svn/entries", ".htaccess", ".htpasswd",
    "Dockerfile", "docker-compose.yml", "package.json", "composer.json",
    "requirements.txt", "Gemfile", "package-lock.json", "yarn.lock",
    "status", "health", "healthz", "readyz", "metrics", "ping", "info",
    "phpinfo", "info.php", "test.php", "server-status", "server-info",
    "cgi-bin", "cgi", "bin", "include", "includes", "lib", "libs",
    "src", "source", "build", "dist", "node_modules", "vendor",
    "shop", "store", "cart", "checkout", "order", "orders", "product", "products",
    "blog", "news", "article", "post", "posts", "comment", "comments",
    "search", "find", "query", "tag", "tags", "category", "categories",
    "download", "downloads", "content", "data", "db", "sql",
    "wp-content", "wp-includes", "wp-config.php", "xmlrpc.php",
    "oauth", "oauth/authorize", "oauth/token", ".well-known/openid-configuration",
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "console", "shell", "terminal", "exec", "execute",
];

/// Berilgan base URL uchun directory brute-force.
pub async fn run(
    base_url: &str,
    cancel: &CancellationToken,
) -> Result<Vec<DirectoryResult>> {
    let client = Arc::new(crate::pipeline::http_client_shared(Duration::from_secs(8))?);
    let results: Arc<tokio::sync::Mutex<Vec<DirectoryResult>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let base = base_url.trim_end_matches('/').to_string();

    // Owned string'larga aylantiramiz — closure referencelarsiz ishlashi uchun.
    let owned: Vec<String> = WORDLIST.iter().map(|s| s.to_string()).collect();

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
                let url = format!("{base}/{path}");
                // HEAD so'rovi — tezroq, body yuklanmaydi.
                if let Ok(resp) = client.head(&url).send().await {
                    let status = resp.status().as_u16();
                    if status != 404 {
                        results.lock().await.push(DirectoryResult {
                            path,
                            status_code: status,
                            url,
                        });
                    }
                }
            }
        })
        .buffer_unordered(20)
        .collect::<Vec<()>>()
        .await;

    let mut guard = results.lock().await;
    // Status code bo'yicha saralash.
    guard.sort_by(|a, b| a.status_code.cmp(&b.status_code));
    Ok(std::mem::take(&mut *guard))
}
