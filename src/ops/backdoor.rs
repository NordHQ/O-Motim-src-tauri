//! Backdoor Hunter — 62 ta sensitiv faylni tekshirish.
//!
//! Parasite `backdoor_hunter.rs`'dan olingan: concurrent GET so'rovlari,
//! 404 bo'lmagan javoblar "topildi" deb belgilanadi.

use crate::models::BackdoorResult;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// 200+ ta sensitiv path ro'yxati: (path, tavsif, severity).
const TARGETS: &[(&str, &str, &str)] = &[
    // Environment files (7)
    (".env", "Environment file", "CRITICAL"),
    (".env.local", "Local environment file", "CRITICAL"),
    (".env.production", "Production environment file", "CRITICAL"),
    (".env.backup", "Environment backup", "CRITICAL"),
    (".env.old", "Old environment file", "HIGH"),
    (".env.dev", "Dev environment file", "HIGH"),
    (".env.staging", "Staging environment file", "HIGH"),
    // Git repos (5)
    (".git/HEAD", "Git repository HEAD", "CRITICAL"),
    (".git/config", "Git repository config", "CRITICAL"),
    (".git/COMMIT_EDITMSG", "Git commit message", "HIGH"),
    (".git/logs/HEAD", "Git logs", "HIGH"),
    (".gitignore", "Git ignore file", "LOW"),
    // DB backups (7)
    ("backup.sql", "Database backup", "CRITICAL"),
    ("dump.sql", "Database dump", "CRITICAL"),
    ("database.sql", "Database backup", "CRITICAL"),
    ("db.sql", "Database backup", "CRITICAL"),
    ("backup.tar.gz", "Tarball backup", "CRITICAL"),
    ("backup.zip", "Zip backup", "CRITICAL"),
    ("site.tar.gz", "Site backup", "CRITICAL"),
    // Config files
    ("config.php", "PHP config", "CRITICAL"),
    ("wp-config.php", "WordPress config", "CRITICAL"),
    ("wp-config.php.bak", "WordPress config backup", "CRITICAL"),
    ("configuration.php", "Joomla config", "CRITICAL"),
    ("app/config/parameters.yml", "Symfony config", "CRITICAL"),
    (".htpasswd", "Apache password file", "HIGH"),
    (".htaccess", "Apache access config", "MEDIUM"),
    ("config.yml", "YAML config", "CRITICAL"),
    ("config.yaml", "YAML config", "CRITICAL"),
    ("config/database.yml", "Database YAML config", "CRITICAL"),
    ("database.yml", "Database YAML config", "CRITICAL"),
    ("settings.py", "Python settings", "CRITICAL"),
    ("local_settings.py", "Python local settings", "CRITICAL"),
    ("settings.local.py", "Python local settings", "CRITICAL"),
    ("settings/production.py", "Production settings", "CRITICAL"),
    // AWS / SSH / cloud credentials
    (".aws/credentials", "AWS credentials", "CRITICAL"),
    (".aws/config", "AWS config", "HIGH"),
    (".ssh/id_rsa", "SSH private key", "CRITICAL"),
    (".ssh/id_dsa", "SSH DSA private key", "CRITICAL"),
    (".ssh/id_ecdsa", "SSH ECDSA private key", "CRITICAL"),
    (".ssh/id_ed25519", "SSH ed25519 private key", "CRITICAL"),
    (".ssh/authorized_keys", "SSH authorized keys", "HIGH"),
    (".ssh/known_hosts", "SSH known hosts", "MEDIUM"),
    (".ssh/config", "SSH config", "HIGH"),
    // DB dumps (extra)
    ("backup.sql.gz", "Compressed DB backup", "CRITICAL"),
    ("dump.sql.gz", "Compressed DB dump", "CRITICAL"),
    ("db/backup.sql", "DB backup in db/", "CRITICAL"),
    ("db/dump.sql", "DB dump in db/", "CRITICAL"),
    ("data.sql", "Data SQL file", "CRITICAL"),
    ("db.sql.gz", "Compressed DB", "CRITICAL"),
    ("mysql.sql", "MySQL dump", "CRITICAL"),
    ("db/mysql.sql", "MySQL dump in db/", "CRITICAL"),
    // Admin panels
    ("admin", "Admin panel", "HIGH"),
    ("admin/", "Admin panel", "HIGH"),
    ("admin/login", "Admin login", "HIGH"),
    ("admin/index.php", "Admin index", "HIGH"),
    ("administrator", "Administrator panel", "HIGH"),
    ("administrator/", "Administrator panel", "HIGH"),
    ("panel", "Admin panel", "HIGH"),
    ("panel/", "Admin panel", "HIGH"),
    ("cpanel", "cPanel", "HIGH"),
    ("whm", "WHM panel", "HIGH"),
    ("manage", "Management panel", "HIGH"),
    ("manager", "Manager panel", "HIGH"),
    ("manager/html", "Tomcat manager", "CRITICAL"),
    ("manager/status", "Tomcat status", "HIGH"),
    // phpMyAdmin
    ("phpmyadmin", "phpMyAdmin", "HIGH"),
    ("phpMyAdmin", "phpMyAdmin", "HIGH"),
    ("phpmyadmin/", "phpMyAdmin", "HIGH"),
    ("pma", "phpMyAdmin alias", "HIGH"),
    ("pma/", "phpMyAdmin alias", "HIGH"),
    ("myadmin", "phpMyAdmin alias", "HIGH"),
    ("dbadmin", "DB admin", "HIGH"),
    ("mysql", "MySQL admin", "HIGH"),
    ("mysqladmin", "MySQL admin", "HIGH"),
    // Spring Boot actuator
    ("actuator", "Spring Boot actuator", "CRITICAL"),
    ("actuator/", "Spring Boot actuator", "CRITICAL"),
    ("actuator/health", "Actuator health", "HIGH"),
    ("actuator/env", "Actuator env (secrets!)", "CRITICAL"),
    ("actuator/beans", "Actuator beans", "MEDIUM"),
    ("actuator/mappings", "Actuator mappings", "MEDIUM"),
    ("actuator/configprops", "Actuator config props", "CRITICAL"),
    ("actuator/heapdump", "Actuator heap dump", "CRITICAL"),
    ("actuator/threaddump", "Actuator thread dump", "HIGH"),
    ("actuator/loggers", "Actuator loggers", "MEDIUM"),
    ("actuator/metrics", "Actuator metrics", "MEDIUM"),
    // GraphQL
    ("graphql", "GraphQL endpoint", "HIGH"),
    ("graphql/", "GraphQL endpoint", "HIGH"),
    ("graphql.php", "GraphQL PHP", "HIGH"),
    ("graphiql", "GraphiQL IDE", "HIGH"),
    ("graphiql.php", "GraphiQL PHP", "HIGH"),
    ("__graphql", "GraphQL alt path", "HIGH"),
    ("api/graphql", "GraphQL API", "HIGH"),
    ("v1/graphql", "GraphQL v1", "HIGH"),
    // Swagger / API docs
    ("swagger", "Swagger", "MEDIUM"),
    ("swagger-ui", "Swagger UI", "MEDIUM"),
    ("swagger-ui.html", "Swagger UI", "MEDIUM"),
    ("swagger-ui/", "Swagger UI", "MEDIUM"),
    ("swagger.json", "Swagger spec", "MEDIUM"),
    ("swagger.yaml", "Swagger spec", "MEDIUM"),
    ("swagger/v1/swagger.json", "Swagger v1 spec", "MEDIUM"),
    ("api-docs", "API docs", "MEDIUM"),
    ("api-docs/", "API docs", "MEDIUM"),
    ("v1/api-docs", "API docs v1", "MEDIUM"),
    ("openapi.json", "OpenAPI spec", "MEDIUM"),
    ("openapi.yaml", "OpenAPI spec", "MEDIUM"),
    ("openapi/", "OpenAPI directory", "MEDIUM"),
    ("redoc", "ReDoc", "MEDIUM"),
    ("api/swagger.json", "API Swagger", "MEDIUM"),
    // API v1 endpoints
    ("api/v1/users", "API users endpoint", "HIGH"),
    ("api/v1/admin", "API admin endpoint", "CRITICAL"),
    ("api/v1/config", "API config", "CRITICAL"),
    ("api/v1/settings", "API settings", "HIGH"),
    ("api/v1/system", "API system", "HIGH"),
    ("api/v1/me", "API me endpoint", "MEDIUM"),
    ("api/users", "API users", "HIGH"),
    ("api/admin", "API admin", "CRITICAL"),
    ("api/config", "API config", "CRITICAL"),
    ("api/account", "API account", "MEDIUM"),
    // OS artifacts
    (".DS_Store", "macOS folder info", "LOW"),
    ("Thumbs.db", "Windows thumbnail cache", "LOW"),
    ("desktop.ini", "Windows desktop config", "LOW"),
    (".DS_Store~", "macOS backup", "LOW"),
    ("._.DS_Store", "macOS AppleDouble", "LOW"),
    // Debug/info (6)
    ("phpinfo.php", "PHP info page", "HIGH"),
    ("info.php", "Info page", "HIGH"),
    ("test.php", "Test page", "MEDIUM"),
    ("debug.php", "Debug page", "HIGH"),
    ("server-status", "Apache server status", "HIGH"),
    ("server-info", "Apache server info", "HIGH"),
    // Logs (5)
    ("error.log", "Error log", "MEDIUM"),
    ("access.log", "Access log", "MEDIUM"),
    ("debug.log", "Debug log", "MEDIUM"),
    ("laravel.log", "Laravel log", "MEDIUM"),
    ("storage/logs/laravel.log", "Laravel storage log", "MEDIUM"),
    ("logs/error.log", "Error log", "MEDIUM"),
    ("logs/access.log", "Access log", "MEDIUM"),
    ("app.log", "App log", "MEDIUM"),
    ("application.log", "Application log", "MEDIUM"),
    ("out.log", "Output log", "MEDIUM"),
    // Source archives (4)
    ("source.zip", "Source archive", "HIGH"),
    ("src.zip", "Source archive", "HIGH"),
    ("website.zip", "Website archive", "HIGH"),
    ("old.zip", "Old archive", "MEDIUM"),
    ("www.zip", "WWW archive", "HIGH"),
    ("html.zip", "HTML archive", "HIGH"),
    ("backup.tar", "Tar backup", "HIGH"),
    ("backup.tar.bz2", "Tar bz2 backup", "HIGH"),
    ("backup.tgz", "Tar gz backup", "HIGH"),
    ("release.zip", "Release archive", "MEDIUM"),
    // API/tokens (6)
    ("api.key", "API key file", "CRITICAL"),
    ("private.key", "Private key file", "CRITICAL"),
    ("id_rsa", "SSH private key", "CRITICAL"),
    (".npmrc", "NPM config (tokens)", "HIGH"),
    (".pypirc", "PyPI config (tokens)", "HIGH"),
    ("credentials", "Credentials file", "CRITICAL"),
    ("credentials.json", "Credentials JSON", "CRITICAL"),
    ("service-account.json", "GCP service account", "CRITICAL"),
    ("firebase-adminsdk.json", "Firebase admin SDK", "CRITICAL"),
    ("google-services.json", "Google services config", "CRITICAL"),
    ("secrets.yml", "Secrets YAML", "CRITICAL"),
    ("secrets.yaml", "Secrets YAML", "CRITICAL"),
    (".env.example", "Env example", "LOW"),
    (".env.sample", "Env sample", "LOW"),
    // Docker/k8s (3)
    ("docker-compose.yml", "Docker compose", "MEDIUM"),
    ("docker-compose.yaml", "Docker compose", "MEDIUM"),
    ("docker-compose.override.yml", "Docker compose override", "MEDIUM"),
    ("Dockerfile", "Docker build file", "LOW"),
    ("Dockerfile.dev", "Docker dev file", "LOW"),
    ("Dockerfile.prod", "Docker prod file", "LOW"),
    (".dockerignore", "Docker ignore", "LOW"),
    ("k8s.yaml", "Kubernetes config", "MEDIUM"),
    ("kubernetes.yaml", "Kubernetes config", "MEDIUM"),
    ("k8s/", "Kubernetes directory", "MEDIUM"),
    // CI/CD config
    (".gitlab-ci.yml", "GitLab CI config", "HIGH"),
    (".github/workflows", "GitHub workflows", "MEDIUM"),
    (".circleci/config.yml", "CircleCI config", "MEDIUM"),
    ("Jenkinsfile", "Jenkins pipeline", "HIGH"),
    ("azure-pipelines.yml", "Azure pipelines", "MEDIUM"),
    ("bitbucket-pipelines.yml", "Bitbucket pipelines", "MEDIUM"),
    // Extra sensitive paths
    (".svn/entries", "SVN repository", "HIGH"),
    (".svn/wc.db", "SVN database", "CRITICAL"),
    (".hg/store", "Mercurial repo", "HIGH"),
    (".bzr/README", "Bazaar repo", "MEDIUM"),
    ("web.config", "IIS web config", "HIGH"),
    ("robots.txt", "Robots file", "INFO"),
    ("sitemap.xml", "Sitemap", "INFO"),
    ("package.json", "Node package file", "LOW"),
    ("package-lock.json", "Node lock file", "LOW"),
    ("composer.json", "PHP composer file", "LOW"),
    ("composer.lock", "PHP composer lock", "LOW"),
    ("Gemfile", "Ruby Gemfile", "LOW"),
    ("Gemfile.lock", "Ruby Gemfile lock", "LOW"),
    ("requirements.txt", "Python requirements", "LOW"),
    ("Pipfile", "Python Pipfile", "LOW"),
    ("Pipfile.lock", "Python Pipfile lock", "LOW"),
    ("go.mod", "Go module file", "LOW"),
    ("go.sum", "Go checksum file", "LOW"),
    (".well-known/security.txt", "Security contact", "INFO"),
    // CMS-specific
    ("/wp-login.php", "WordPress login", "MEDIUM"),
    ("/wp-admin/", "WordPress admin", "HIGH"),
    ("/wp-content/uploads/", "WordPress uploads", "LOW"),
    ("/wp-content/debug.log", "WordPress debug log", "MEDIUM"),
    ("/wp-content/backup-db/", "WordPress DB backup", "CRITICAL"),
    ("/administrator/index.php", "Joomla admin", "HIGH"),
    ("/user/login", "Drupal login", "MEDIUM"),
    ("/sites/default/settings.php", "Drupal settings", "CRITICAL"),
    ("/xmlrpc.php", "XML-RPC interface", "HIGH"),
    // Backup patterns
    ("/~admin", "Admin home dir", "MEDIUM"),
    ("/~root", "Root home dir", "HIGH"),
    ("/backup/", "Backup directory", "HIGH"),
    ("/backups/", "Backups directory", "HIGH"),
    ("/old/", "Old directory", "MEDIUM"),
    ("/temp/", "Temp directory", "MEDIUM"),
    ("/tmp/", "Tmp directory", "MEDIUM"),
    ("/test/", "Test directory", "MEDIUM"),
    ("/_dev/", "Dev directory", "MEDIUM"),
    ("/_test/", "Test directory", "MEDIUM"),
    ("/_old/", "Old directory", "MEDIUM"),
];

/// Berilgan base URL uchun barcha sensitiv path'larni tekshiradi.
///
/// `base_url` — `https://example.com` kabi (oxirgi `/`siz).
pub async fn run(
    base_url: &str,
    cancel: &CancellationToken,
) -> Result<Vec<BackdoorResult>> {
    use tokio::sync::Semaphore;

    let client = Arc::new(crate::pipeline::http_client_shared(Duration::from_secs(8))?);
    let results: Arc<tokio::sync::Mutex<Vec<BackdoorResult>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    // RAM: concurrencyni 30 bilan cheklash.
    let sem = Arc::new(Semaphore::new(30));

    let base = base_url.trim_end_matches('/').to_string();

    // Owned tuple'larga aylantiramiz — closure referencelarsiz ishlashi uchun.
    let owned: Vec<(String, String, String)> = TARGETS
        .iter()
        .map(|(p, d, s)| (p.to_string(), d.to_string(), s.to_string()))
        .collect();

    stream::iter(owned)
        .map(|(path, desc, sev)| {
            let client = client.clone();
            let results = results.clone();
            let base = base.clone();
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
                let url = format!("{base}/{path}");
                let req = client.get(&url).send();
                // RAM: har bir so'rov uchun 8s timeout.
                if let Ok(Ok(resp)) = tokio::time::timeout(Duration::from_secs(8), req).await {
                    let status = resp.status().as_u16();
                    if status != 404 && status != 0 {
                        results.lock().await.push(BackdoorResult {
                            path,
                            description: desc,
                            severity: sev,
                            status_code: status,
                            url,
                        });
                    }
                }
            }
        })
        .buffer_unordered(60)
        .collect::<Vec<()>>()
        .await;

    let mut guard = results.lock().await;
    // Severity bo'yicha saralaymiz: CRITICAL birinchi.
    guard.sort_by(|a, b| {
        let order = |s: &str| match s {
            "CRITICAL" => 0,
            "HIGH" => 1,
            "MEDIUM" => 2,
            "LOW" => 3,
            _ => 4,
        };
        order(&a.severity).cmp(&order(&b.severity))
    });
    Ok(std::mem::take(&mut *guard))
}
