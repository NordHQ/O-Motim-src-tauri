//! Sauron ko'zi startup animatsiyasi — Tauri log chiqaradi.
//!
//! 5 marta miltilash (har bir ~1.6s), keyin 8 marta tez miltilash (50ms).

use std::io::{self, Write};
use std::thread;
use std::time::Duration;

const EYE_LINES: usize = 7;

const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

/// (pupil_offset_x, pupil_size: 1-3, squint: 0=open 1=squint 2=closed, delay_ms)
const FRAMES: &[(i32, i32, i32, u64)] = &[
    // === 5 marta miltilash ===
    // 1
    (0, 1, 2, 200), (0, 2, 1, 100), (0, 3, 0, 300), (0, 3, 0, 300),
    (0, 2, 1, 100), (0, 1, 2, 200),
    (0, 1, 2, 300), (0, 1, 2, 300),
    // 2
    (0, 1, 2, 200), (0, 2, 1, 100), (0, 3, 0, 300), (0, 3, 0, 300),
    (0, 2, 1, 100), (0, 1, 2, 200),
    (0, 1, 2, 300), (0, 1, 2, 300),
    // 3
    (0, 1, 2, 200), (0, 2, 1, 100), (0, 3, 0, 300), (0, 3, 0, 300),
    (0, 2, 1, 100), (0, 1, 2, 200),
    (0, 1, 2, 300), (0, 1, 2, 300),
    // 4
    (0, 1, 2, 200), (0, 2, 1, 100), (0, 3, 0, 300), (0, 3, 0, 300),
    (0, 2, 1, 100), (0, 1, 2, 200),
    (0, 1, 2, 300), (0, 1, 2, 300),
    // 5
    (0, 1, 2, 200), (0, 2, 1, 100), (0, 3, 0, 300), (0, 3, 0, 300),
    (0, 2, 1, 100), (0, 1, 2, 200),
    (0, 1, 2, 300), (0, 1, 2, 300),
    // === 8 marta tez miltilash ===
    (0, 3, 0, 50), (0, 1, 2, 50),
    (0, 3, 0, 50), (0, 1, 2, 50),
    (0, 3, 0, 50), (0, 1, 2, 50),
    (0, 3, 0, 50), (0, 1, 2, 50),
    (0, 3, 0, 50), (0, 1, 2, 50),
    (0, 3, 0, 50), (0, 1, 2, 50),
    (0, 3, 0, 50), (0, 1, 2, 50),
    (0, 3, 0, 50), (0, 1, 2, 50),
];

fn draw_frame(px: i32, ps: i32, sq: i32) {
    eprint!("\x1b[{}A", EYE_LINES);
    for y in 0..EYE_LINES {
        let mut row = String::new();
        for x in 0..42 {
            let ch = eye_char(x, y, px, ps, sq);
            row.push(ch);
        }
        eprintln!("{}", row);
    }
    let _ = io::stderr().flush();
}

fn eye_char(x: usize, y: usize, px: i32, ps: i32, sq: i32) -> char {
    let w = 42.0_f64;
    let h = 7.0_f64;
    let nx = (x as f64 - w / 2.0) / (w / 2.0);
    let ny = (y as f64 - h / 2.0) / (h / 2.0);
    let eye_d = (nx * nx + ny * ny * 5.0).sqrt(); // ellipse

    if sq == 2 {
        // Yopilgan
        if y == h as usize / 2 && (x as f64 - w / 2.0).abs() < w * 0.35 {
            return '─';
        }
        return ' ';
    }

    if sq == 1 {
        // Yarim yopilgan
        if eye_d > 0.95 {
            return ' ';
        }
        if eye_d > 0.8 {
            return '─';
        }
        if y == h as usize / 2 {
            let dx = x as i32 - (w as usize / 2) as i32 - px;
            if dx.abs() <= ps {
                return '●';
            }
        }
        return ' ';
    }

    // Ochilgan
    if eye_d > 0.95 {
        return ' ';
    }
    if eye_d > 0.82 {
        return if eye_d > 0.88 { '●' } else { '·' };
    }

    // Iris zone
    let cx = (w as usize / 2) as i32 + px;
    let cy = h as usize / 2;
    let dx = x as i32 - cx;
    let dy = y as i32 - cy as i32;
    let dist = ((dx * dx + dy * dy) as f64).sqrt() as i32;

    if dist <= ps {
        '●' // pupil
    } else if dist <= 4 {
        '○' // iris
    } else {
        // Tomirlar
        let vx = x as i32 - w as i32 / 2;
        let vy = y as i32 - h as i32 / 2;
        if (vx == -10 && vy == -1) || (vx == -8 && vy == 0) {
            '╲'
        } else if (vx == 10 && vy == 1) || (vx == 8 && vy == 0) {
            '╱'
        } else {
            ' '
        }
    }
}

/// Startup animatsiyasi.
pub fn animate() {
    for _ in 0..EYE_LINES {
        eprintln!();
    }
    let _ = io::stderr().flush();

    for &(px, ps, sq, ms) in FRAMES {
        draw_frame(px, ps, sq);
        thread::sleep(Duration::from_millis(ms));
    }

    // Clear eye
    eprint!("\x1b[{}A", EYE_LINES);
    for _ in 0..EYE_LINES {
        eprintln!();
    }
    let _ = io::stderr().flush();

    // Banner
    eprintln!("{}{}  ◈ O'MOTIM — Eye of Recon{}{}", RED, BOLD, RED, RESET);
    eprintln!();
}
