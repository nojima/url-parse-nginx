# nginx-reference

A tiny shared object that exposes nginx's URL path normalization logic so it
can be called from the outside (e.g. a Rust fuzzer). It is used to
differentially check that a nginx-compatible normalization crate returns
**the same result as nginx for the same input**.

## What's inside

`nginx_url.c` copies the following **verbatim** from `src/http/ngx_http_parse.c`:

- `usual[]` — the "ordinary character" bitmap.
- `ngx_http_parse_uri()` — stage 1: walks an origin-form path and sets the
  `complex_uri` / `quoted_uri` / `args_start` flags and boundaries.
- `ngx_http_parse_complex_uri()` — stage 2: the **normalizer** itself
  (`%XX` decoding, `.` / `..` / `//` resolution).

It also adds a thin wrapper `nginx_parse_path_and_query()` that reproduces the
Linux path of `ngx_http_process_request_uri()` (from `ngx_http_request.c`) and
exposes the normalized path and query arguments as a C ABI.

> **Only origin-form paths (starting with `/`) are supported.** Absolute-form
> (`http://host/path`), authority-form (`CONNECT`), and `OPTIONS *` are out of
> scope. This matches the semantics of the HTTP/2 and HTTP/3 `:path` header.

The two extracted functions **call no other nginx function**, so there are no
`.o` files to link and the only undefined symbols are libc. nginx's type
definitions are replaced by a minimal `ngx_http_request_t` in `ngx_stub.h`.

## Files

| File | Role |
|---|---|
| `nginx_url.c` | The 3 verbatim regions + the `nginx_parse_path_and_query()` wrapper (generated) |
| `ngx_stub.h` | Minimal type/macro shim (a struct with only the fields the two functions touch) |
| `tools/extract.sh` | Regenerates the extracted regions from nginx |
| `Makefile` | Build / self-test / regenerate / verify |
| `selftest.c` | A small sanity test |
| `libnginx_url.so` | Build artifact (produced by `make`) |

## Build

```sh
cd nginx-reference
make            # -> libnginx_url.so
make check      # build and run the self-test
make clean
```

Leave `NGX_WIN32` and `NGX_DEBUG` **undefined** (to keep the Linux behavior and
disable debug logging). The default `CFLAGS` in the `Makefile` already do this.

## C ABI

```c
int nginx_parse_path_and_query(const unsigned char *in, size_t in_len,
                               int merge_slashes,
                               unsigned char *out, size_t out_cap,
                               size_t *out_len, size_t *args_offset,
                               size_t *args_len, int *args_present);
```

| Argument | Meaning |
|---|---|
| `in`, `in_len` | Raw origin-form request-target bytes. Need not be NUL-terminated; may be empty. |
| `merge_slashes` | `1` collapses `//` (nginx default), `0` keeps it. **Use as a fuzzer input.** |
| `out`, `out_cap` | Output buffer; capacity must be `>= in_len + 1`. |
| `out_len` | Set to the normalized path length on success. |
| `args_offset`, `args_len` | Set to the query string's range within `in` on success. |
| `args_present` | Set to `1` when query arguments are present and `0` otherwise. This distinguishes an absent query from a present empty query. |

Return value:

| Value | Meaning |
|---|---|
| `0` | Success. `out[0..*out_len)` holds the normalized path. When `*args_present == 1`, `in[*args_offset..*args_offset + *args_len)` holds the query string. |
| `-1` | nginx rejected the request target (parse error / invalid request). |
| `-2` | `out_cap` too small (never happens if `out_cap >= in_len + 1`). |

The output is never longer than the input (`%XX` -> 1 byte; `.` / `..` / `//`
are only removed), so `in_len + 1` bytes are always enough.
Query arguments are returned as a range in the input, so exposing them requires
no additional output buffer or allocation.

## Using it from Rust

### Bindings

```rust
use std::os::raw::{c_int, c_uchar};

extern "C" {
    fn nginx_parse_path_and_query(
        input: *const c_uchar, in_len: usize,
        merge_slashes: c_int,
        out: *mut c_uchar, out_cap: usize, out_len: *mut usize,
        args_offset: *mut usize, args_len: *mut usize,
        args_present: *mut c_int,
    ) -> c_int;
}

pub struct Parsed<'a> {
    pub path: Vec<u8>,
    pub args: Option<&'a [u8]>,
}

/// Ok(Some(parsed)) = accepted / Ok(None) = nginx rejected / Err = unexpected
pub fn nginx_parse(
    input: &[u8],
    merge_slashes: bool,
) -> Result<Option<Parsed<'_>>, ()> {
    let mut out = vec![0u8; input.len() + 1];
    let mut out_len = 0usize;
    let mut args_offset = 0usize;
    let mut args_len = 0usize;
    let mut args_present = 0;
    let rc = unsafe {
        nginx_parse_path_and_query(
            input.as_ptr(), input.len(),
            merge_slashes as c_int,
            out.as_mut_ptr(), out.len(), &mut out_len,
            &mut args_offset, &mut args_len, &mut args_present,
        )
    };
    match rc {
        0 => {
            out.truncate(out_len);
            let args = match args_present {
                0 => None,
                1 => {
                    let end = args_offset.checked_add(args_len).ok_or(())?;
                    Some(input.get(args_offset..end).ok_or(())?)
                }
                _ => return Err(()),
            };
            Ok(Some(Parsed { path: out, args }))
        }
        -1 => Ok(None),
        _ => Err(()),
    }
}
```

### Linking (either option)

- **Compile the C directly in `build.rs` (recommended)** — use the `cc` crate to
  build `nginx_url.c` and link it statically. No `.so` to distribute, and the
  fastest path for a fuzzer. This is what `../fuzz` does.

  ```rust
  // build.rs
  fn main() {
      cc::Build::new()
          .file("nginx-reference/nginx_url.c")
          .include("nginx-reference")
          .opt_level(1)
          .compile("nginx_url");
  }
  ```

- **Link the `.so` dynamically** — against the `libnginx_url.so` built by `make`,
  using `cargo:rustc-link-lib=dylib=nginx_url` and `cargo:rustc-link-search=...`.

## Differential checking in a fuzzer

Compare the three return states directly against your own crate's result:

1. `Ok(Some(parsed))` -> both normalized paths and both query strings must be
   identical, including absent versus present-but-empty query strings.
2. `Ok(None)` -> your implementation must also **reject** the input.
3. Randomize `merge_slashes: bool` too, to cover both dimensions.

```rust
// libfuzzer-sys target example
fuzz_target!(|data: &[u8]| {
    if data.is_empty() { return; }
    let merge = data[0] & 1 == 1;
    let target = &data[1..];

    let nginx = nginx_parse(target, merge);
    let mine  = my_crate::parse(target, merge); // expected to return the same states

    assert_eq!(nginx, mine, "divergence on {:?} (merge={})", target, merge);
});
```

## How the nginx source is obtained

This directory is independent of the nginx tree. The reference nginx source is
**fetched on demand from nginx.org** by `tools/extract.sh` (with the version and
sha256 pinned). It does not depend on a parent directory such as `../../src`.

The generated `nginx_url.c` is **committed (vendored)**, so the fuzzer builds
offline. CI uses `make verify` to check that fetching and regenerating produces
the exact same file that is committed.

The nginx-derived code in `nginx_url.c` is covered by nginx's 2-clause BSD
license (Copyright Igor Sysoev / Nginx, Inc.); see the crate-root `LICENSE` and
`NOTICE`.

## When bumping the nginx version

1. Update `NGINX_VERSION` and `NGINX_SHA256` in `tools/extract.sh`
   (the sha256 is for `nginx-<ver>.tar.gz`).
2. Run `./tools/extract.sh` to regenerate `nginx_url.c` (fetch from nginx.org ->
   verify sha256 -> extract verbatim). Extraction is pattern-based (function
   signature through the column-0 `}`), so it is not affected by line-number
   drift.
3. Re-check that `ngx_http_request_t` in `ngx_stub.h` is neither missing nor
   carrying extra fields, against the fields actually referenced (`SRC` is the
   fetched nginx source):
   ```sh
   SRC=path/to/nginx-<ver>/src/http/ngx_http_parse.c
   awk '/^ngx_http_parse_uri\(/{c=1} c{print} c&&/^}/{exit}' "$SRC"; \
   awk '/^ngx_http_parse_complex_uri\(/{c=1} c{print} c&&/^}/{exit}' "$SRC" \
     | grep -oE 'r->[a-z_]+(\.[a-z_]+)?' | sort -u
   ```
4. Run `make check` (build + self-test) and `make verify` (regeneration matches).
