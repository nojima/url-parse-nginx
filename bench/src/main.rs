//! Micro-benchmark: nginx (C) vs url-parse-nginx (Rust).
//!
//! Times both implementations on long URLs (~1 KiB) so that the fixed per-call
//! allocation cost (nginx always `malloc`s two buffers; the Rust port allocates
//! for a normalized path) does not dominate the measured parse time — the goal
//! is to compare the *parsing* work, not the allocator.
//!
//! Run with an optimized build:
//!
//!   cd bench && cargo run --release
//!
//! For each input we first cross-check that C and Rust agree, then report the
//! best (minimum) average ns/op over several rounds.

use std::hint::black_box;
use std::time::Instant;

extern "C" {
    fn nginx_normalize_path(
        input: *const u8,
        in_len: usize,
        merge_slashes: i32,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> i32;
}

/// Call the real nginx code, writing into the caller-provided `out`.
/// Returns the normalized length, or `None` if nginx rejected the input.
fn c_normalize(input: &[u8], merge: bool, out: &mut [u8]) -> Option<usize> {
    let mut out_len = 0usize;
    let rc = unsafe {
        nginx_normalize_path(
            input.as_ptr(),
            input.len(),
            merge as i32,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        )
    };
    (rc == 0).then_some(out_len)
}

struct Case {
    name: &'static str,
    input: Vec<u8>,
    merge: bool,
}

/// Build ~1 KiB inputs, each exercising a different normalization path.
fn cases() -> Vec<Case> {
    let target = 1000;

    // Repeat `unit` until the buffer reaches ~`target` bytes (always ending on
    // a whole unit, so no dangling "%X" or half segment).
    let grow = |prefix: &[u8], unit: &[u8]| -> Vec<u8> {
        let mut v = prefix.to_vec();
        while v.len() < target {
            v.extend_from_slice(unit);
        }
        v
    };

    vec![
        // Fast path: no '.', '..', '%', or '//' — nginx returns the input
        // unchanged and the Rust port borrows it (no allocation, no stage 2).
        Case { name: "simple (no normalization)", input: grow(b"", b"/abcdefghij"), merge: true },
        // Decoding-heavy: every segment is percent-encoded ("%41" -> 'A').
        Case { name: "percent-decode", input: grow(b"", b"/%41%42%43%44"), merge: true },
        // Path resolution: each "/x/.." cancels out, back to "/base".
        Case { name: "dot-dot resolution", input: grow(b"/base", b"/x/.."), merge: true },
        // Slash merging: runs of '/' collapse to one.
        Case { name: "slash merge", input: grow(b"", b"/a//b///"), merge: true },
    ]
}

/// Minimum average ns/op over `rounds` rounds of `iters` calls each. The first
/// round doubles as warmup; taking the min filters out scheduler noise.
fn bench<F: FnMut()>(iters: u64, rounds: u32, mut f: F) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..rounds {
        let start = Instant::now();
        for _ in 0..iters {
            f();
        }
        let per = start.elapsed().as_nanos() as f64 / iters as f64;
        best = best.min(per);
    }
    best
}

fn main() {
    let cases = cases();
    let iters = 200_000u64;
    let rounds = 12u32;

    println!(
        "{:<30} {:>6} {:>11} {:>11} {:>9}",
        "case", "bytes", "C ns/op", "Rust ns/op", "speedup"
    );
    println!("{}", "-".repeat(70));

    for c in &cases {
        let mut out = vec![0u8; c.input.len() + 1];

        // Cross-check agreement before timing (a benchmark of divergent code
        // would be meaningless).
        let c_res = c_normalize(&c.input, c.merge, &mut out).map(|n| out[..n].to_vec());
        let r_res = url_parse_nginx::normalize_path(&c.input, c.merge)
            .ok()
            .map(|n| n.path.into_owned());
        assert_eq!(c_res, r_res, "C/Rust divergence on bench case {:?}", c.name);

        let c_ns = bench(iters, rounds, || {
            let n = c_normalize(black_box(&c.input), c.merge, &mut out);
            black_box(n);
            black_box(out[0]);
        });

        let r_ns = bench(iters, rounds, || {
            let n = url_parse_nginx::normalize_path(black_box(&c.input), c.merge).unwrap();
            black_box(n.path.len());
            black_box(n.path.as_ptr());
            black_box(n.args);
        });

        println!(
            "{:<30} {:>6} {:>11.1} {:>11.1} {:>8.2}x",
            c.name,
            c.input.len(),
            c_ns,
            r_ns,
            c_ns / r_ns,
        );
    }

    println!("\nspeedup = C ns/op / Rust ns/op  (>1.0 means the Rust port is faster)");
}
