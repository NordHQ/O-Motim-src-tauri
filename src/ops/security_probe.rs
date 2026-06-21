//! Security Probe — A-F graded security header audit.
//!
//! Parasite `probe.rs`'dan olingan: 8 security header, A-F grade.

use crate::models::{SecurityFinding, SecurityProbeResult};
use anyhow::Result;
use std::time::Duration;

/// 8 ta security header: (header nomi, points).
const CHECKS: &[(&str, i32)] = &[
    ("strict-transport-security", 15),
    ("content-security-policy", 20),
    ("x-frame-options", 10),
    ("x-content-type-options", 10),
    ("referrer-policy", 10),
    ("permissions-policy", 10),
    ("x-xss-protection", 5),
    ("cross-origin-opener-policy", 10),
];

/// Score'dan A-F grade.
fn score_to_grade(score: i32) -> String {
    match score {
        s if s >= 90 => "A".into(),
        s if s >= 80 => "B".into(),
        s if s >= 70 => "C".into(),
        s if s >= 60 => "D".into(),
        _ => "F".into(),
    }
}

/// Berilgan URL uchun security header audit.
pub async fn run(url: &str) -> Result<SecurityProbeResult> {
    let client = crate::pipeline::http_client(Duration::from_secs(10))?;
    let mut findings = Vec::new();
    let mut score = 0i32;

    if let Ok(resp) = client.get(url).send().await {
        let hdrs = resp.headers();
        for (header, points) in CHECKS {
            let present = hdrs.contains_key(*header);
            let value = if present {
                hdrs.get(*header)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            } else {
                None
            };
            if present {
                score += points;
            }
            findings.push(SecurityFinding {
                header: header.to_string(),
                present,
                value: value.map(|v| {
                    if v.len() > 60 {
                        format!("{}…", &v[..60])
                    } else {
                        v
                    }
                }),
                points: if present { *points } else { 0 },
            });
        }
    }

    Ok(SecurityProbeResult {
        url: url.to_string(),
        grade: score_to_grade(score),
        score: score.min(100),
        findings,
    })
}
