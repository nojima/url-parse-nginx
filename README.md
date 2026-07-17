# url-parse-nginx

A faithful, 1-to-1 Rust port of nginx's URL **path normalization**.

`url-parse-nginx` reproduces exactly what nginx does when it turns a raw
request path into the normalized `$uri`: percent-decoding (`%XX`), resolution
of `.` and `..` segments, and `//` collapsing. It is a close port of two
functions from nginx's `src/http/ngx_http_parse.c`:

- `ngx_http_parse_uri()` — validates an origin-form path and detects whether
  normalization is needed.
- `ngx_http_parse_complex_uri()` — performs the normalization.

The goal is **byte-for-byte agreement with nginx**, so that Rust code (proxies,
routers, WAFs, security tooling) can reason about a path the same way nginx
will. Agreement is not just claimed but continuously checked by a differential
fuzzer that runs the real nginx C code against this port (see below).

## Scope

- **Origin-form paths only** (starting with `/`) — i.e. the semantics of the
  HTTP/2 and HTTP/3 `:path` pseudo-header. Absolute-form (`http://host/path`),
  authority-form (`CONNECT`), and `OPTIONS *` are out of scope.
- Targets the Linux, non-debug build of nginx (`NGX_WIN32` / `NGX_DEBUG` off).

## Usage

```rust
use std::borrow::Cow;
use url_parse_nginx::parse_path_and_query;

// merge_slashes = true matches nginx's default `merge_slashes on`.
// The result is a `Parsed { path: Cow<[u8]>, args: Option<&[u8]> }`.
// Deref the path (&*) to compare against a byte slice.
assert_eq!(&*parse_path_and_query(b"/a/./b/../c", true).unwrap().path, b"/c");
assert_eq!(&*parse_path_and_query(b"/%66oo", true).unwrap().path, b"/foo");
assert_eq!(&*parse_path_and_query(b"/a//b", true).unwrap().path, b"/a/b");
assert_eq!(&*parse_path_and_query(b"/a//b", false).unwrap().path, b"/a//b");

// The path corresponds to nginx's initial $uri; the query is returned
// separately in `args`, corresponding to the initial $args.
let n = parse_path_and_query(b"/foo/../bar?x=1", true).unwrap();
assert_eq!(&*n.path, b"/bar");
assert_eq!(n.args, Some(&b"x=1"[..]));

// No query component -> args is None.
assert_eq!(parse_path_and_query(b"/foo", true).unwrap().args, None);

// A "simple" path that needs no normalization borrows the input — no allocation.
assert!(matches!(parse_path_and_query(b"/foo/bar", true).unwrap().path, Cow::Borrowed(_)));

// Paths nginx rejects return Err (e.g. escaping above the root).
assert!(parse_path_and_query(b"/../", true).is_err());
```

`parse_path_and_query` returns:

- `Ok(Parsed { path, args })`:
  - `path: Cow<[u8]>` — the normalized path corresponding to nginx's initial
    `$uri`, with the query string excluded. A path that needs no normalization
    borrows the input unchanged (`Cow::Borrowed`) with no allocation; a
    normalized path returns an owned buffer (`Cow::Owned`).
  - `args: Option<&[u8]>` — the query string corresponding to nginx's initial
    `$args`: the bytes after the first `?`, up to a `#` fragment or the end of
    the target. It always borrows the input and is never normalized. `None`
    means nginx found no query arguments; `Some(b"")` marks the empty query
    before a fragment in a target such as `/a?#f`.
- `Err(ParseError)` — nginx rejected the target (invalid request).

## How the equivalence is verified

The repository contains developer tooling (not shipped in the published crate):

- `nginx-reference/` — a tiny C shared object that calls the **real** nginx
  `ngx_http_parse_uri` / `ngx_http_parse_complex_uri`. The C is generated
  verbatim from a pinned official nginx release fetched from nginx.org by
  `tools/extract.sh`.
- `fuzz/` — a differential fuzzer that feeds the same inputs to nginx (C)
  and to this crate and asserts identical results (both the normalized bytes
  and accept/reject), across both `merge_slashes` values.
- `bench/` — a micro-benchmark comparing this crate's parse speed against the
  real nginx C code (see below).

```sh
# exhaustive corpus ("/", "/"+1..3 arbitrary bytes) + random inputs
cd fuzz
cargo run --release -- <iterations> <seed>
```

Before random generation, the fuzzer exhaustively checks `/` followed by every
1-, 2-, and 3-byte suffix (~16.7M cases). Random fuzzing then extends coverage
to longer inputs.

## Benchmark

`bench/` times the Rust port against the real nginx C code on long (~1 KiB)
URLs, chosen so that the fixed per-call allocation cost does not dominate the
measured parse time. It cross-checks that C and Rust agree on each input before
timing, then reports the best (minimum) average ns/op over several rounds.

```sh
cd bench
cargo run --release
```

Both sides are compiled at `-O3` for a fair comparison. Four inputs exercise the
fast path (no normalization → the Rust port borrows the input) and the three
normalization paths (`%XX` decoding, `.`/`..` resolution, `//` merging).

One representative run on an AMD Ryzen 9 5900X (x86-64) with rustc 1.97.1
produced:

| case | bytes | C ns/op | Rust ns/op | speedup |
|---|---:|---:|---:|---:|
| simple (no normalization) | 1001 | 561.9 | 517.3 | 1.09x |
| percent-decode | 1001 | 1945.7 | 2242.5 | 0.87x |
| dot-dot resolution | 1000 | 1928.2 | 2779.9 | 0.69x |
| slash merge | 1000 | 1823.7 | 2264.6 | 0.81x |

`speedup` is C ns/op divided by Rust ns/op, so values above `1.0x` mean the
Rust port is faster. These figures are illustrative: absolute timings and
ratios vary with the CPU, compiler version, system load, and code layout. Run
the benchmark locally when comparing changes.

## Relationship to nginx and license

This crate is a derivative work of nginx and reuses nginx source (a Rust port
in `src/lib.rs`, and verbatim C in the fuzz harness). nginx is licensed under
the 2-clause BSD license, so this crate is distributed under the same license
and retains the original nginx copyright notice.

See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) for details, and
`nginx-reference/tools/extract.sh` for the exact pinned nginx version.
