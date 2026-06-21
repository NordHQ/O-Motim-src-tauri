//! WebSocket Scanner — WS endpoint topish va ulanish test.
//!
//! Parasite `ws_leech.rs`'dan olingan (soddalashtirilgan — HTTP tekshiruvi).

use crate::models::WsResult;
use anyhow::Result;
use std::time::Duration;

/// Berilgan URL uchun WS endpoint tekshiruvi.
///
/// HTTP so'rov yuboramiz — agar javob "Upgrade" talab qilsa, WS bor.
pub async fn run(url: &str) -> Result<Vec<WsResult>> {
    let client = crate::pipeline::http_client(Duration::from_secs(8))?;
    let host = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("");

    let mut results = Vec::new();

    // ws, /socket.io/, /ws'ni test qilamiz.
    let ws_paths = ["/ws", "/socket.io/", "/wss", "/websocket", "/live"];
    for path in ws_paths {
        let test_url = format!("https://{host}{path}");
        let req = client
            .get(&test_url)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

        let reachable = if let Ok(resp) = req.send().await {
            let status = resp.status().as_u16();
            // 101 Switching Protocols yoki 426 Upgrade Required.
            status == 101 || status == 426
        } else {
            false
        };

        if reachable {
            results.push(WsResult {
                url: test_url,
                reachable,
            });
        }
    }

    Ok(results)
}
