//! Differential fuzzer: nginx (C) vs url-parse-nginx (Rust).
//!
//! For each generated input and both `merge_slashes` values, run nginx's real
//! `ngx_http_parse_uri` + `ngx_http_parse_complex_uri` (via the C harness) and
//! the Rust port, then assert the results are identical:
//!   - both accept  -> normalized path and query string must match
//!   - both reject  -> ok
//!   - disagreement -> print the failing input and exit non-zero
//!
//! Usage:  fuzz [iterations] [seed]
//!   iterations  number of random inputs (default 5_000_000)
//!   seed        u64 PRNG seed (default 0x9E3779B97F4A7C15)

use std::borrow::Cow;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::ExitCode;

extern "C" {
    fn nginx_parse_path_and_query(
        input: *const u8,
        in_len: usize,
        merge_slashes: i32,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
        args_offset: *mut usize,
        args_len: *mut usize,
        args_present: *mut i32,
    ) -> i32;
}

#[derive(Debug, PartialEq, Eq)]
struct ParseResult<'a> {
    path: Cow<'a, [u8]>,
    args: Option<&'a [u8]>,
}

/// Call the real nginx code. `None` == rejected (rc -1).
///
/// The C wrapper returns `args` as an offset and length into `input`, so
/// exposing it as a slice requires no additional allocation.
fn c_parse(input: &[u8], merge: bool) -> Option<ParseResult<'_>> {
    let mut out = vec![0u8; input.len() + 1];
    let mut out_len = 0usize;
    let mut args_offset = 0usize;
    let mut args_len = 0usize;
    let mut args_present = 0i32;
    let rc = unsafe {
        nginx_parse_path_and_query(
            input.as_ptr(),
            input.len(),
            merge as i32,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
            &mut args_offset,
            &mut args_len,
            &mut args_present,
        )
    };
    match rc {
        0 => {
            out.truncate(out_len);
            let args = match args_present {
                0 => None,
                1 => {
                    let args_end = args_offset
                        .checked_add(args_len)
                        .filter(|&end| end <= input.len())
                        .unwrap_or_else(|| {
                            panic!(
                                "C harness returned invalid args range \
                                 {args_offset}..+{args_len} for input length {}",
                                input.len()
                            )
                        });
                    Some(&input[args_offset..args_end])
                }
                other => panic!(
                    "C harness returned unexpected args_present={other} for {:?}",
                    input
                ),
            };
            Some(ParseResult {
                path: Cow::Owned(out),
                args,
            })
        }
        -1 => None,
        other => panic!("C harness returned unexpected rc={other} for {:?}", input),
    }
}

/// Call the Rust port. `None` == rejected.
fn rust_parse(input: &[u8], merge: bool) -> Option<ParseResult<'_>> {
    url_parse_nginx::parse_path_and_query(input, merge)
        .ok()
        .map(|parsed| ParseResult {
            path: parsed.path,
            args: parsed.args,
        })
}

/// xorshift64* PRNG (deterministic, reproducible from the seed).
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

/// Alphabet biased toward URL-significant bytes (repeats raise the weight).
const ALPHABET: &[u8] = &[
    b'/', b'/', b'/', b'/', b'.', b'.', b'.', b'.', b'%', b'%', b'%', //
    b'2', b'e', b'E', b'f', b'0', b'a', b'g', b'Z', b'A', b'z', //
    b'?', b'#', b'+', b' ', b'\\', b':', b'~', b'=', b'&', //
    0x00, 0x7f, 0x01, 0x80, 0xff, b'-', b'_',
];

fn gen_input(rng: &mut Rng, buf: &mut Vec<u8>) {
    buf.clear();
    let len = rng.below(33); // 0..=32
    // Bias toward starting with '/', since only origin-form is in scope, but
    // still sometimes produce non-'/' starts to exercise the rejection path.
    for i in 0..len {
        let b = if i == 0 && rng.below(4) != 0 {
            b'/'
        } else {
            ALPHABET[rng.below(ALPHABET.len())]
        };
        buf.push(b);
    }
}

/// Returns true on agreement; prints details and returns false on divergence.
fn check(input: &[u8], merge: bool) -> bool {
    let c = catch_unwind(AssertUnwindSafe(|| c_parse(input, merge)));
    let r = catch_unwind(AssertUnwindSafe(|| rust_parse(input, merge)));

    match (c, r) {
        (Ok(c), Ok(r)) if c == r => true,
        (c, r) => {
            eprintln!("\n=== DIVERGENCE ===");
            eprintln!("input (len {}):  {}", input.len(), escape(input));
            eprintln!("bytes:           {:?}", input);
            eprintln!("merge_slashes:   {merge}");
            eprintln!("C   result:      {}", fmt_res(&c));
            eprintln!("Rust result:     {}", fmt_res(&r));
            false
        }
    }
}

fn fmt_res(r: &std::thread::Result<Option<ParseResult<'_>>>) -> String {
    match r {
        Ok(Some(parsed)) => format!(
            "Ok {{ path: {:?} = {}, args: {} }}",
            parsed.path,
            escape(&parsed.path),
            fmt_args(parsed.args)
        ),
        Ok(None) => "Rejected".to_string(),
        Err(_) => "PANIC".to_string(),
    }
}

fn fmt_args(args: Option<&[u8]>) -> String {
    match args {
        Some(args) => format!("Some({args:?} = {})", escape(args)),
        None => "None".to_string(),
    }
}

fn escape(b: &[u8]) -> String {
    let mut s = String::from("\"");
    for &c in b {
        if (0x20..0x7f).contains(&c) && c != b'"' && c != b'\\' {
            s.push(c as char);
        } else {
            s.push_str(&format!("\\x{c:02x}"));
        }
    }
    s.push('"');
    s
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let iterations: u64 = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000_000);
    let seed: u64 = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x9E37_79B9_7F4A_7C15);

    // 1) Fixed corpus of tricky cases — always exercised first.
    let corpus: &[&[u8]] = &[
        b"", b"/", b"//", b"///", b"/.", b"/..", b"/../", b"/./", b"/a/./b",
        b"/a/../b", b"/a/b/../../c", b"/a/b/../../../c", b"/%2e%2e/", b"/%2f",
        b"/a%2fb", b"/%00", b"/foo?bar", b"/foo#frag", b"/foo?a=b#c", b"/+",
        b"/foo?", b"/foo?#frag", b"/foo?x=%20", b"/%20", b"/a..b", b"/...",
        b"/....", b"/a/..", b"relative", b"/%zz", b"/%2", b"/a%", b"/\\",
        b"/a\\b", b"/.%2e/", b"/%2e./",
    ];
    for input in corpus {
        for &merge in &[true, false] {
            if !check(input, merge) {
                eprintln!("\n(divergence in fixed corpus)");
                return ExitCode::FAILURE;
            }
        }
    }
    eprintln!("fixed corpus ({} cases): OK", corpus.len());

    // 1b) Exhaustive: every 1-, 2-, and 3-byte suffix appended to a leading "/".
    for suffix_len in 1..=3usize {
        let total = 256usize.pow(suffix_len as u32);
        let mut input = vec![b'/'; 1 + suffix_len];
        for n in 0..total {
            // little-endian odometer over the suffix bytes
            let mut v = n;
            for i in 0..suffix_len {
                input[1 + i] = (v & 0xff) as u8;
                v >>= 8;
            }
            for &merge in &[true, false] {
                if !check(&input, merge) {
                    eprintln!("\n(divergence in '/'+{suffix_len}-byte exhaustive corpus)");
                    return ExitCode::FAILURE;
                }
            }
        }
        eprintln!("'/'+{suffix_len}-byte exhaustive ({total} cases): OK");
    }

    // 2) Random differential fuzzing.
    let mut rng = Rng(seed);
    let mut buf = Vec::with_capacity(64);
    let mut done = 0u64;
    let report_every = (iterations / 20).max(1);

    for i in 0..iterations {
        gen_input(&mut rng, &mut buf);
        let merge = rng.next_u64() & 1 == 0;
        if !check(&buf, merge) {
            eprintln!("\n(divergence after {done} random iterations, seed {seed})");
            return ExitCode::FAILURE;
        }
        done += 1;
        if (i + 1) % report_every == 0 {
            eprintln!("  {}/{} random inputs OK", i + 1, iterations);
        }
    }

    eprintln!(
        "\nALL PASSED: {} fixed + {} random inputs, no divergence (seed {seed}).",
        corpus.len(),
        done
    );
    ExitCode::SUCCESS
}
