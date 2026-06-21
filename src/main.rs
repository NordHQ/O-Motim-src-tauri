// Prevents an extra console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Sauron ko'zi splash animatsiyasi
    omotim_lib::eye::animate();
    omotim_lib::run();
}
