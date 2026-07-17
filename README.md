# url-parse-nginx

A faithful, 1-to-1 Rust port of nginx's URL **path normalization**.

`url-parse-nginx` reproduces exactly what nginx does when it turns a raw
request path into the normalized `r->uri`: percent-decoding (`%XX`), resolution
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
use url_parse_nginx::normalize_path;

// merge_slashes = true matches nginx's default (cscf->merge_slashes).
// The result is a `Normalized { path: Cow<[u8]>, args: Option<&[u8]> }`.
// Deref the path (&*) to compare against a byte slice.
assert_eq!(&*normalize_path(b"/a/./b/../c", true).unwrap().path, b"/c");
assert_eq!(&*normalize_path(b"/%66oo", true).unwrap().path, b"/foo");
assert_eq!(&*normalize_path(b"/a//b", true).unwrap().path, b"/a/b");
assert_eq!(&*normalize_path(b"/a//b", false).unwrap().path, b"/a//b");

// The path excludes the query string (exactly like nginx's r->uri); the query
// is returned separately in `args` (like r->args), and is never normalized.
let n = normalize_path(b"/foo/../bar?x=1", true).unwrap();
assert_eq!(&*n.path, b"/bar");
assert_eq!(n.args, Some(&b"x=1"[..]));

// No query component -> args is None.
assert_eq!(normalize_path(b"/foo", true).unwrap().args, None);

// A "simple" path that needs no normalization borrows the input — no allocation.
assert!(matches!(normalize_path(b"/foo/bar", true).unwrap().path, Cow::Borrowed(_)));

// Paths nginx rejects return Err (e.g. escaping above the root).
assert!(normalize_path(b"/../", true).is_err());
```

`normalize_path` returns:

- `Ok(Normalized { path, args })`:
  - `path: Cow<[u8]>` — the normalized path (nginx's `r->uri`, query string
    excluded). A path that needs no normalization borrows the input unchanged
    (`Cow::Borrowed`) with no allocation, exactly as nginx returns the original
    bytes; a normalized path returns an owned buffer (`Cow::Owned`).
  - `args: Option<&[u8]>` — the query string (nginx's `r->args`): the bytes
    after the first `?`, up to a `#` fragment or the end of the target. It
    always borrows the input (the query is never normalized). `None` when there
    is no query component; `Some(b"")` marks a present-but-empty query (`/a?#f`).
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

The fixed corpus alone exhaustively covers `/` followed by every 1-, 2-, and
3-byte suffix (~16.7M cases); random fuzzing extends coverage to longer inputs.

## Relationship to nginx and license

This crate is a derivative work of nginx and reuses nginx source (a Rust port
in `src/lib.rs`, and verbatim C in the fuzz harness). nginx is licensed under
the 2-clause BSD license, so this crate is distributed under the same license
and retains the original nginx copyright notice.

See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) for details, and
`nginx-reference/tools/extract.sh` for the exact pinned nginx version.
