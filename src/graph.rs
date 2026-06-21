//! Graph builder — scan natijalaridan force-directed graph tuzadi.
//!
//! Domain → Subdomain → IP → Technology → CVE
//! Host → Secret, Backdoor, API endpoint, Form
//!
//! Har bir node type uchun o'z rangi bor (MOTIM theme'ga mos).

use crate::models::{GraphData, GraphEdge, GraphNode, ScanContext};

/// Node type → hex color (MOTIM dark theme'ga moslashtirilgan).
pub fn color_for(node_type: &str) -> &'static str {
    match node_type {
        "domain" => "#c84b0e",       // accent (orange) — markaziy domen
        "subdomain" => "#33bbff",     // severity-info (cyan)
        "ip" => "#33dd77",            // severity-success (green)
        "tech" => "#a78bfa",          // binafsha
        "cve" => "#ff3333",           // severity-critical (qizil)
        "secret" => "#ff7700",        // severity-high (to'q sariq)
        "backdoor" => "#ffbb00",      // severity-medium (sariq)
        "api" => "#3388ff",           // severity-low (ko'k)
        "form" => "#e8531a",          // accent-hover
        "url" => "#7a7a99",           // text-secondary (kulrang)
        _ => "#7a7a99",
    }
}

/// Scan kontekstidan graf quradi.
pub fn build(ctx: &ScanContext) -> GraphData {
    let mut nodes: Vec<GraphNode> = Vec::new();
    let mut edges: Vec<GraphEdge> = Vec::new();

    // Domain — markaziy node.
    let domain_id = format!("domain:{}", ctx.domain);
    nodes.push(GraphNode {
        id: domain_id.clone(),
        label: ctx.domain.clone(),
        node_type: "domain".into(),
        color: color_for("domain").into(),
        detail: Some(format!("Root domain — {} subdomains", ctx.subdomains.len())),
    });

    // Subdomains.
    let mut sub_ids: Vec<String> = Vec::new();
    for sub in ctx.subdomains.iter().take(50) {
        let sid = format!("sub:{sub}");
        nodes.push(GraphNode {
            id: sid.clone(),
            label: sub.clone(),
            node_type: "subdomain".into(),
            color: color_for("subdomain").into(),
            detail: None,
        });
        edges.push(GraphEdge {
            source: domain_id.clone(),
            target: sid.clone(),
            label: "subdomain".into(),
        });
        sub_ids.push(sid);
    }

    // IP addresses.
    for (host, ips) in ctx.ips.iter().take(50) {
        let host_id = format!("sub:{host}");
        // Agar host node sifatida yo'q bo'lsa, yaratamiz.
        if !nodes.iter().any(|n| n.id == host_id) {
            nodes.push(GraphNode {
                id: host_id.clone(),
                label: host.clone(),
                node_type: "subdomain".into(),
                color: color_for("subdomain").into(),
                detail: None,
            });
            edges.push(GraphEdge {
                source: domain_id.clone(),
                target: host_id.clone(),
                label: "subdomain".into(),
            });
        }
        for ip in ips.iter().take(3) {
            let ip_id = format!("ip:{host}:{ip}");
            nodes.push(GraphNode {
                id: ip_id.clone(),
                label: ip.clone(),
                node_type: "ip".into(),
                color: color_for("ip").into(),
                detail: None,
            });
            edges.push(GraphEdge {
                source: host_id.clone(),
                target: ip_id,
                label: "resolves".into(),
            });
        }
    }

    // Technologies.
    for tech in ctx.technologies.iter().take(30) {
        let tech_id = format!("tech:{}", tech.name);
        if !nodes.iter().any(|n| n.id == tech_id) {
            nodes.push(GraphNode {
                id: tech_id.clone(),
                label: tech.name.clone(),
                node_type: "tech".into(),
                color: color_for("tech").into(),
                detail: tech.version.as_ref().map(|v| format!("v{v}")),
            });
            edges.push(GraphEdge {
                source: domain_id.clone(),
                target: tech_id.clone(),
                label: tech.category.clone(),
            });
        }

        // Technology → CVE
        for cve in ctx.cves.iter().filter(|c| c.affected_tech == tech.name).take(5) {
            let cve_id = format!("cve:{}", cve.cve_id);
            if !nodes.iter().any(|n| n.id == cve_id) {
                nodes.push(GraphNode {
                    id: cve_id.clone(),
                    label: cve.cve_id.clone(),
                    node_type: "cve".into(),
                    color: color_for("cve").into(),
                    detail: Some(format!("CVSS {}", cve.cvss_score)),
                });
            }
            edges.push(GraphEdge {
                source: tech_id.clone(),
                target: cve_id,
                label: "vulnerable".into(),
            });
        }
    }

    // Secrets — har biri alohida node.
    for (i, secret) in ctx.secrets.iter().enumerate().take(20) {
        let sec_id = format!("secret:{i}");
        nodes.push(GraphNode {
            id: sec_id.clone(),
            label: secret.secret_type.clone(),
            node_type: "secret".into(),
            color: color_for("secret").into(),
            detail: Some(secret.preview.clone()),
        });
        edges.push(GraphEdge {
            source: domain_id.clone(),
            target: sec_id,
            label: "leaked".into(),
        });
    }

    // Backdoors — sensitive files.
    for (i, bd) in ctx.backdoors.iter().enumerate().take(30) {
        let bd_id = format!("backdoor:{i}");
        nodes.push(GraphNode {
            id: bd_id.clone(),
            label: bd.path.clone(),
            node_type: "backdoor".into(),
            color: color_for("backdoor").into(),
            detail: Some(format!("{} (HTTP {})", bd.description, bd.status_code)),
        });
        edges.push(GraphEdge {
            source: domain_id.clone(),
            target: bd_id,
            label: "exposed".into(),
        });
    }

    // API endpoints.
    for (i, api) in ctx.api_endpoints.iter().enumerate().take(30) {
        let api_id = format!("api:{i}");
        nodes.push(GraphNode {
            id: api_id.clone(),
            label: api.path.clone(),
            node_type: "api".into(),
            color: color_for("api").into(),
            detail: Some(format!("{} via {}", api.method, api.found_in)),
        });
        edges.push(GraphEdge {
            source: domain_id.clone(),
            target: api_id,
            label: "endpoint".into(),
        });
    }

    // Forms.
    for (i, form) in ctx.forms.iter().enumerate().take(15) {
        let form_id = format!("form:{i}");
        nodes.push(GraphNode {
            id: form_id.clone(),
            label: format!("{} form", form.form_type),
            node_type: "form".into(),
            color: color_for("form").into(),
            detail: Some(format!("{} fields", form.fields.len())),
        });
        edges.push(GraphEdge {
            source: domain_id.clone(),
            target: form_id,
            label: "form".into(),
        });
    }

    GraphData { nodes, edges }
}
