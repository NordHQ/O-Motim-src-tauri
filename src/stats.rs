//! Tizim statistikasi (CPU / RAM / threadlar).
//!
//! `sysinfo` — juda yengil, cross-platform, tez.
//! StatusBar har 1.5s `get_system_stats` ni chaqiradi.

use crate::models::SystemStats;
use std::sync::{Mutex, OnceLock};
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

/// Global System instance — qayta-qayta yaratilmaydi.
static SYS: OnceLock<Mutex<System>> = OnceLock::new();

fn new_system() -> System {
    System::new_with_specifics(
        RefreshKind::new()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything()),
    )
}

fn system() -> &'static Mutex<System> {
    SYS.get_or_init(|| Mutex::new(new_system()))
}

/// Joriy tizim holatini oladi.
pub fn snapshot() -> SystemStats {
    let mut guard = match system().lock() {
        Ok(g) => g,
        Err(_) => {
            return SystemStats {
                cpu_usage: 0.0,
                ram_used_mb: 0,
                ram_total_mb: 0,
                thread_count: 0,
            }
        }
    };

    guard.refresh_cpu_usage();

    let cpu = guard
        .cpus()
        .iter()
        .map(|c| c.cpu_usage())
        .sum::<f32>()
        / guard.cpus().len().max(1) as f32;

    let used = guard.used_memory() / 1024; // KB → MB
    let total = guard.total_memory() / 1024;

    SystemStats {
        cpu_usage: cpu,
        ram_used_mb: used,
        ram_total_mb: total,
        thread_count: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
    }
}
