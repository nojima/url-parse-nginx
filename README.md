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
use url_parse_nginx::normalize_path;

// merge_slashes = true matches nginx's default (cscf->merge_slashes).
assert_eq!(normalize_path(b"/a/./b/../c", true).unwrap(), b"/c");
assert_eq!(normalize_path(b"/%66oo", true).unwrap(), b"/foo");
assert_eq!(normalize_path(b"/a//b", true).unwrap(), b"/a/b");
assert_eq!(normalize_path(b"/a//b", false).unwrap(), b"/a//b");

// The query string is excluded, exactly like nginx's r->uri.
assert_eq!(normalize_path(b"/foo/../bar?x=1", true).unwrap(), b"/bar");

// Paths nginx rejects return Err (e.g. escaping above the root).
assert!(normalize_path(b"/../", true).is_err());
```

`normalize_path` returns:

- `Ok(path)` — the normalized path bytes. For a path that needs no
  normalization, this is the input unchanged (query string excluded), exactly
  as nginx returns the original bytes.
- `Err(ParseError)` — nginx rejected the path (invalid request).

## How the equivalence is verified

The repository contains developer tooling (not shipped in the published crate):

- `url-fuzz-harness/` — a tiny C shared object that calls the **real** nginx
  `ngx_http_parse_uri` / `ngx_http_parse_complex_uri`. The C is generated
  verbatim from a pinned official nginx release fetched from nginx.org by
  `tools/extract.sh`.
- `difffuzz/` — a differential fuzzer that feeds the same inputs to nginx (C)
  and to this crate and asserts identical results (both the normalized bytes
  and accept/reject), across both `merge_slashes` values.

```sh
# exhaustive corpus ("/", "/"+1..3 arbitrary bytes) + random inputs
cd difffuzz
cargo run --release -- <iterations> <seed>
```

The fixed corpus alone exhaustively covers `/` followed by every 1-, 2-, and
3-byte suffix (~16.7M cases); random fuzzing extends coverage to longer inputs.

## Relationship to nginx and license

This crate is a derivative work of nginx and reuses nginx source (a Rust port
in `src/lib.rs`, and verbatim C in the fuzz harness). nginx is licensed under
the 2-clause BSD license, so this crate is distributed under the same license
and retains the original nginx copyright notice.

See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) for details, and
`url-fuzz-harness/tools/extract.sh` for the exact pinned nginx version.
