//! Parasite'dan olingan yangi operatsiyalar.
//!
//! Har bir modul non-interactive, event-based ishlaydi — TUI prompt'lari
//! olib tashlangan, natija `Vec<T>` sifatida qaytariladi.
//! Pipeline (`crate::pipeline`) bu funksiyalarni chaqiradi.

pub mod analyze;
pub mod api_brute;
pub mod api_discovery;
pub mod backdoor;
pub mod broken_links;
pub mod burrow;
pub mod cors;
pub mod crawl;
pub mod forms;
pub mod header_dump;
pub mod http_methods;
pub mod redirect;
pub mod resources;
pub mod security_probe;
pub mod ssl;
pub mod websocket;
