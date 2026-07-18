// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (C) 2026 Yusuke Nojima             (Rust port)
// Copyright (C) 2002-2021 Igor Sysoev          (original nginx code)
// Copyright (C) 2011-2026 Nginx, Inc.          (original nginx code)
// All rights reserved.
//
// This file is a close, 1-to-1 Rust port of ngx_http_parse_uri() and
// ngx_http_parse_complex_uri() (and the `usual[]` table) from nginx's
// src/http/ngx_http_parse.c. It is distributed under the same 2-clause BSD
// license as nginx; see the LICENSE and NOTICE files at the crate root.

#![no_std]

//! Parse and normalize URL paths using nginx semantics.
//!
//! `url-parse-nginx` is a one-to-one Rust port of nginx's URI parser
//! and normalizer. Within the supported scope described below, it matches
//! nginx's accept/reject decisions and produces byte-for-byte identical
//! normalized paths and query strings. This equivalence is continuously
//! checked by differential fuzzing against nginx's C implementation.
//!
//! The crate supports `no_std` environments with `alloc`. Normalizing a path
//! that differs from the input allocates an output buffer; unchanged paths and
//! query strings borrow the input.
//!
//! [`parse_origin_form`] accepts an origin-form request target, normalizes
//! its path, and returns the query string separately. Path normalization
//! percent-decodes `%XX`, resolves `.` and `..` segments, and optionally merges
//! adjacent slashes.
//!
//! [Origin-form] is the usual HTTP request-target format: a path starting
//! with `/`, optionally followed by `?` and a query string, such as
//! `/search?q=rust`.
//!
//! Other request-target forms, such as absolute-form
//! (`http://example.com/path`), authority-form (`example.com:443`), and
//! asterisk-form (`*`), are not supported.
//! The parsing behavior follows nginx on Linux; Windows-specific nginx
//! behavior is not supported.
//!
//! Some nginx processing paths, including some `proxy_pass` cases, first
//! normalize and percent-decode the request path, then percent-encode the
//! normalized path again. To reproduce this decode-then-encode flow, pass
//! [`Parsed::path`] to `percent_encoding::percent_encode` with
//! `PATH_ESCAPE_SET`. The set is available when the default
//! `percent-encoding` feature is enabled.
//!
//! [Origin-form]: https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.1
//!
//! # Example
//!
//! ```
//! use url_parse_nginx::parse_origin_form;
//!
//! let parsed = parse_origin_form(b"/docs/../hello%20world?x=1", true)?;
//! assert_eq!(&*parsed.path, b"/hello world"); // ".." resolved, "%20" decoded
//! assert_eq!(parsed.args, Some(&b"x=1"[..]));
//! # Ok::<(), url_parse_nginx::ParseError>(())
//! ```

#![cfg_attr(
    feature = "percent-encoding",
    doc = r#"
## Percent-encoding the normalized path

The default `percent-encoding` feature also supports nginx-compatible
re-encoding:

```
use percent_encoding::percent_encode;
use url_parse_nginx::{parse_origin_form, PATH_ESCAPE_SET};

let parsed = parse_origin_form(b"/docs/../hello%20world", true)?;
let encoded = percent_encode(parsed.path.as_ref(), PATH_ESCAPE_SET);
assert_eq!(encoded.to_string(), "/hello%20world");
# Ok::<(), url_parse_nginx::ParseError>(())
```
"#
)]

// Implementation notes:
//
// The parser ports two functions from `src/http/ngx_http_parse.c`:
//
// * `ngx_http_parse_uri()` — stage 1. Walks an origin-form path and sets the
//   `complex_uri` / `quoted_uri` / `plus_in_uri` flags and the `args_start` /
//   `uri_ext` boundaries. It does not modify the path.
// * `ngx_http_parse_complex_uri()` — stage 2. Decodes `%XX`, resolves `.` /
//   `..` and collapses `//` (when `merge_slashes` is set), producing the
//   normalized path.
//
// The C code walks raw buffers with `u_char *` cursors. Here:
//
// * `p` (the input cursor) is a `usize` index into a `buf: &[u8]`.
// * `u` (the output cursor) is a `usize` index into `out: &mut [u8]`.
//   Where nginx lets its pointer walk backwards past the buffer start during
//   `..` handling, the Rust port uses `checked_sub` and returns the same error.
// * Pointer fields that C stores as `u_char *` become `usize` offsets. Their
//   base buffer follows the C code exactly: `args_start` is always an offset
//   into the input; `uri_ext` is an input offset in stage 1 and an output
//   offset in stage 2 (it is reset at the top of stage 2, so the two never
//   interact — same as C).
// * nginx relies on "there is always at least one readable byte (the LF)
//   after the URI": stage 2 reads one byte at `uri_end`. The Rust port uses a
//   checked read that yields `\n` at that position, avoiding an input copy
//   made solely to materialize the sentinel.

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::{borrow::Cow, vec};
#[cfg(feature = "percent-encoding")]
use percent_encoding::{AsciiSet, CONTROLS};

/// The percent-encode set nginx uses when escaping normalized paths.
///
/// # Example
///
/// ```
/// use percent_encoding::percent_encode;
/// use url_parse_nginx::PATH_ESCAPE_SET;
///
/// let encoded = percent_encode(b"/hello world", PATH_ESCAPE_SET);
/// assert_eq!(encoded.to_string(), "/hello%20world");
/// ```
#[cfg(feature = "percent-encoding")]
pub const PATH_ESCAPE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'\\')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// nginx's `usual[]` bitmap (`ngx_http_parse.c`), non-`NGX_WIN32` variant.
///
/// Bit `1` marks an "ordinary" URI character that needs no special handling.
const USUAL: [u32; 8] = [
    0x0000_0000, /* control chars */
    0x7fff_37d6, /* symbols / digits: excludes SP " # % + / ? etc. */
    0xffff_ffff, /* @A-Z[\]^_  (0xefffffff under NGX_WIN32) */
    0x7fff_ffff, /* `a-z{|}~  (DEL excluded) */
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
];

/// `usual[ch >> 5] & (1U << (ch & 0x1f))` — is `ch` an ordinary URI byte?
#[inline]
fn usual(ch: u8) -> bool {
    USUAL[(ch >> 5) as usize] & (1u32 << (ch & 0x1f)) != 0
}

/// Read through stage 2's input cursor, including nginx's trailing LF.
#[inline(always)]
fn read_with_lf_sentinel(buf: &[u8], p: usize) -> u8 {
    buf.get(p).copied().unwrap_or(b'\n')
}

/// An error returned when a request target cannot be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError;

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("failed to parse request target")
    }
}

impl core::error::Error for ParseError {}

/// The result of parsing an origin-form request target.
///
/// `path` and `args` correspond to the initial values nginx exposes through
/// its `$uri` and `$args` variables.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Parsed<'a> {
    /// The normalized path, corresponding to nginx's `$uri` variable before
    /// any later rewrite processing. The query string is excluded.
    ///
    /// `/../` segments are removed by resolving the preceding segment, and
    /// percent-encoded bytes are decoded. For example,
    /// `/a/../hello%20world` becomes `/hello world`.
    ///
    /// A path that needs no normalization borrows the input unchanged
    /// ([`Cow::Borrowed`], no allocation); a normalized path is owned
    /// ([`Cow::Owned`]).
    pub path: Cow<'a, [u8]>,

    /// The query string, corresponding to nginx's initial `$args` variable:
    /// the bytes after the first `?`, up to a `#` fragment or the end of the
    /// target. It always borrows the input and is not normalized.
    ///
    /// `None` means nginx found no query arguments; this includes a trailing
    /// `?` with nothing after it (`"/a?"`). `Some(b"")` marks the empty query
    /// before a fragment in a target such as `"/a?#f"`.
    pub args: Option<&'a [u8]>,
}

/// A `{len, data-offset}` pair mirroring nginx's `ngx_str_t`. The base of
/// `data` (input vs output buffer) depends on the field, exactly as in C.
#[derive(Debug, Default, Clone, Copy)]
struct NgxStr {
    len: usize,
    data: usize,
}

/// The subset of `ngx_http_request_t` touched by the two ported functions.
#[derive(Debug, Default)]
struct Request {
    // outputs
    uri: NgxStr,   // len = normalized path length; data = output-buffer offset
    args: NgxStr,  // data = input offset (query string)
    exten: NgxStr, // data = output offset (extension)

    uri_ext: Option<usize>,
    args_start: Option<usize>,

    // flags
    complex_uri: bool,
    quoted_uri: bool,
    plus_in_uri: bool,
    empty_path_in_uri: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UriState {
    Start,
    AfterSlash,
    CheckUri,
    Uri,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Usual,
    Slash,
    Dot,
    DotDot,
    Quoted,
    QuotedSecond,
}

/// Port of `ngx_http_parse_uri()`.
///
/// Scans the entire origin-form request target in `buf` and sets flags/offsets.
/// Returns `Err` where the C returns `NGX_ERROR`.
#[inline(never)]
fn ngx_http_parse_uri(r: &mut Request, buf: &[u8]) -> Result<(), ParseError> {
    let uri_start = 0;
    let uri_end = buf.len();

    let mut state = UriState::Start;
    let mut p = uri_start;

    while p != uri_end {
        let ch = buf[p];

        match state {
            UriState::Start => {
                if ch != b'/' {
                    return Err(ParseError);
                }
                state = UriState::AfterSlash;
            }

            /* check "/.", "//", "%", and "\" (Win32) in URI */
            UriState::AfterSlash => {
                if usual(ch) {
                    state = UriState::CheckUri;
                } else {
                    match ch {
                        b'.' => {
                            r.complex_uri = true;
                            state = UriState::Uri;
                        }
                        b'%' => {
                            r.quoted_uri = true;
                            state = UriState::Uri;
                        }
                        b'/' => {
                            r.complex_uri = true;
                            state = UriState::Uri;
                        }
                        b'?' => {
                            r.args_start = Some(p + 1);
                            state = UriState::Uri;
                        }
                        b'#' => {
                            r.complex_uri = true;
                            state = UriState::Uri;
                        }
                        b'+' => {
                            r.plus_in_uri = true;
                        }
                        _ => {
                            if ch <= 0x20 || ch == 0x7f {
                                return Err(ParseError);
                            }
                            state = UriState::CheckUri;
                        }
                    }
                }
            }

            /* check "/", "%" and "\" (Win32) in URI */
            UriState::CheckUri => {
                if usual(ch) {
                    // Stay in CheckUri. Ordinary bytes commonly occur in long
                    // runs; consume the run here instead of redispatching the
                    // same state for every byte.
                    p += 1;
                    while p != uri_end && usual(buf[p]) {
                        p += 1;
                    }
                    continue;
                } else {
                    match ch {
                        b'/' => {
                            r.uri_ext = None;
                            state = UriState::AfterSlash;
                        }
                        b'.' => {
                            r.uri_ext = Some(p + 1);
                        }
                        b'%' => {
                            r.quoted_uri = true;
                            state = UriState::Uri;
                        }
                        b'?' => {
                            r.args_start = Some(p + 1);
                            state = UriState::Uri;
                        }
                        b'#' => {
                            r.complex_uri = true;
                            state = UriState::Uri;
                        }
                        b'+' => {
                            r.plus_in_uri = true;
                        }
                        _ => {
                            if ch <= 0x20 || ch == 0x7f {
                                return Err(ParseError);
                            }
                        }
                    }
                }
            }

            /* URI */
            UriState::Uri => {
                if usual(ch) {
                    // stay in Uri
                } else {
                    match ch {
                        b'#' => {
                            r.complex_uri = true;
                        }
                        _ => {
                            if ch <= 0x20 || ch == 0x7f {
                                return Err(ParseError);
                            }
                        }
                    }
                }
            }
        }

        p += 1;
    }

    Ok(())
}

/// Shared tail of the `done:` label in `ngx_http_parse_complex_uri()`.
fn finish_done(r: &mut Request, u: usize) -> Result<(), ParseError> {
    r.uri.len = u;

    if let Some(ext) = r.uri_ext {
        // C computes a size_t difference that may wrap when u < uri_ext; match
        // that instead of panicking (exten is not part of the compared path).
        r.exten.len = u.wrapping_sub(ext);
        r.exten.data = ext;
    }

    r.uri_ext = None;
    Ok(())
}

/// The `args:` label of `ngx_http_parse_complex_uri()`.
fn finish_args(r: &mut Request, buf: &[u8], u: usize, mut p: usize) -> Result<(), ParseError> {
    let uri_end = buf.len();

    while p < uri_end {
        let c = buf[p];
        p += 1;
        if c != b'#' {
            continue;
        }

        let args_start = r.args_start.unwrap();
        r.args.len = (p - 1).wrapping_sub(args_start);
        r.args.data = args_start;
        r.args_start = None;
        break;
    }

    finish_done(r, u)
}

/// Port of `ngx_http_parse_complex_uri()`.
///
/// Reads the entire request target in `buf` and writes the normalized path into
/// `out`, setting `r.uri.len`. `out` must have capacity `>= buf.len() + 1`.
#[inline(never)]
fn ngx_http_parse_complex_uri(
    r: &mut Request,
    buf: &[u8],
    out: &mut [u8],
    merge_slashes: bool,
) -> Result<(), ParseError> {
    let uri_start = 0;
    let uri_end = buf.len();

    let mut state = State::Usual;
    let mut quoted_state = State::Usual;
    let mut decoded: u8 = 0;

    let mut p = uri_start;
    let mut u: usize = 0;
    r.uri_ext = None;
    r.args_start = None;

    if r.empty_path_in_uri {
        out[u] = b'/';
        u += 1;
    }

    let mut ch = read_with_lf_sentinel(buf, p);
    p += 1;

    while p <= uri_end {
        match state {
            State::Usual => {
                if usual(ch) {
                    out[u] = ch;
                    u += 1;
                    ch = read_with_lf_sentinel(buf, p);
                    p += 1;
                } else {
                    match ch {
                        b'/' => {
                            r.uri_ext = None;
                            state = State::Slash;
                            out[u] = ch;
                            u += 1;
                        }
                        b'%' => {
                            quoted_state = state;
                            state = State::Quoted;
                        }
                        b'?' => {
                            r.args_start = Some(p);
                            return finish_args(r, buf, u, p);
                        }
                        b'#' => {
                            return finish_done(r, u);
                        }
                        b'.' => {
                            r.uri_ext = Some(u + 1);
                            out[u] = ch;
                            u += 1;
                        }
                        b'+' => {
                            r.plus_in_uri = true;
                            out[u] = ch;
                            u += 1;
                        }
                        _ => {
                            out[u] = ch;
                            u += 1;
                        }
                    }
                    ch = read_with_lf_sentinel(buf, p);
                    p += 1;
                }
            }

            State::Slash => {
                if usual(ch) {
                    state = State::Usual;
                    out[u] = ch;
                    u += 1;
                    ch = read_with_lf_sentinel(buf, p);
                    p += 1;
                } else {
                    match ch {
                        b'/' => {
                            if !merge_slashes {
                                out[u] = ch;
                                u += 1;
                            }
                        }
                        b'.' => {
                            state = State::Dot;
                            out[u] = ch;
                            u += 1;
                        }
                        b'%' => {
                            quoted_state = state;
                            state = State::Quoted;
                        }
                        b'?' => {
                            r.args_start = Some(p);
                            return finish_args(r, buf, u, p);
                        }
                        b'#' => {
                            return finish_done(r, u);
                        }
                        b'+' => {
                            r.plus_in_uri = true;
                            state = State::Usual;
                            out[u] = ch;
                            u += 1;
                        }
                        _ => {
                            state = State::Usual;
                            out[u] = ch;
                            u += 1;
                        }
                    }
                    ch = read_with_lf_sentinel(buf, p);
                    p += 1;
                }
            }

            State::Dot => {
                if usual(ch) {
                    state = State::Usual;
                    out[u] = ch;
                    u += 1;
                    ch = read_with_lf_sentinel(buf, p);
                    p += 1;
                } else {
                    match ch {
                        b'/' => {
                            state = State::Slash;
                            u -= 1;
                        }
                        b'.' => {
                            state = State::DotDot;
                            out[u] = ch;
                            u += 1;
                        }
                        b'%' => {
                            quoted_state = state;
                            state = State::Quoted;
                        }
                        b'?' => {
                            u -= 1;
                            r.args_start = Some(p);
                            return finish_args(r, buf, u, p);
                        }
                        b'#' => {
                            u -= 1;
                            return finish_done(r, u);
                        }
                        b'+' => {
                            r.plus_in_uri = true;
                            state = State::Usual;
                            out[u] = ch;
                            u += 1;
                        }
                        _ => {
                            state = State::Usual;
                            out[u] = ch;
                            u += 1;
                        }
                    }
                    ch = read_with_lf_sentinel(buf, p);
                    p += 1;
                }
            }

            State::DotDot => {
                if usual(ch) {
                    state = State::Usual;
                    out[u] = ch;
                    u += 1;
                    ch = read_with_lf_sentinel(buf, p);
                    p += 1;
                } else {
                    match ch {
                        b'/' | b'?' | b'#' => {
                            // Same backwards scan as nginx's loop, expressed
                            // over a bounded slice so indexing stays checked.
                            let start = u.checked_sub(4).ok_or(ParseError)?;
                            u = out[..=start]
                                .iter()
                                .rposition(|&c| c == b'/')
                                .map(|i| i + 1)
                                .ok_or(ParseError)?;
                            if ch == b'?' {
                                r.args_start = Some(p);
                                return finish_args(r, buf, u, p);
                            }
                            if ch == b'#' {
                                return finish_done(r, u);
                            }
                            state = State::Slash;
                        }
                        b'%' => {
                            quoted_state = state;
                            state = State::Quoted;
                        }
                        b'+' => {
                            r.plus_in_uri = true;
                            state = State::Usual;
                            out[u] = ch;
                            u += 1;
                        }
                        _ => {
                            state = State::Usual;
                            out[u] = ch;
                            u += 1;
                        }
                    }
                    ch = read_with_lf_sentinel(buf, p);
                    p += 1;
                }
            }

            State::Quoted => {
                r.quoted_uri = true;

                if ch.is_ascii_digit() {
                    decoded = ch - b'0';
                    state = State::QuotedSecond;
                    ch = read_with_lf_sentinel(buf, p);
                    p += 1;
                } else {
                    let c = ch | 0x20;
                    if (b'a'..=b'f').contains(&c) {
                        decoded = c - b'a' + 10;
                        state = State::QuotedSecond;
                        ch = read_with_lf_sentinel(buf, p);
                        p += 1;
                    } else {
                        return Err(ParseError);
                    }
                }
            }

            State::QuotedSecond => {
                if ch.is_ascii_digit() {
                    ch = (decoded << 4) + (ch - b'0');

                    if ch == b'%' || ch == b'#' {
                        state = State::Usual;
                        out[u] = ch;
                        u += 1;
                        ch = read_with_lf_sentinel(buf, p);
                        p += 1;
                    } else if ch == b'\0' {
                        return Err(ParseError);
                    } else {
                        state = quoted_state;
                        // no advance: the decoded byte is reprocessed
                    }
                } else {
                    let c = ch | 0x20;
                    if (b'a'..=b'f').contains(&c) {
                        ch = (decoded << 4) + (c - b'a') + 10;

                        if ch == b'?' {
                            state = State::Usual;
                            out[u] = ch;
                            u += 1;
                            ch = read_with_lf_sentinel(buf, p);
                            p += 1;
                        } else {
                            if ch == b'+' {
                                r.plus_in_uri = true;
                            }
                            state = quoted_state;
                            // no advance: the decoded byte is reprocessed
                        }
                    } else {
                        return Err(ParseError);
                    }
                }
            }
        }
    }

    if state == State::Quoted || state == State::QuotedSecond {
        return Err(ParseError);
    }

    if state == State::Dot {
        u -= 1;
    } else if state == State::DotDot {
        // Same backwards scan as above for a trailing `..`.
        let start = u.checked_sub(4).ok_or(ParseError)?;
        u = out[..=start]
            .iter()
            .rposition(|&c| c == b'/')
            .map(|i| i + 1)
            .ok_or(ParseError)?;
    }

    finish_done(r, u)
}

/// Parse a single origin-form request target exactly as nginx does.
///
/// The returned values correspond to the values nginx exposes through
/// its `$uri` and `$args` variables.
///
/// * `Ok(`[`Parsed`]`)` — the normalized path and query string. For a "simple"
///   path that needs no normalization, the path borrows the input unchanged
///   ([`Cow::Borrowed`]) with no allocation; normalization returns an owned
///   buffer ([`Cow::Owned`]). The query string always borrows the input.
/// * `Err(ParseError)` — the request target could not be parsed.
///
/// `merge_slashes` corresponds to nginx's [`merge_slashes`](https://nginx.org/en/docs/http/ngx_http_core_module.html#merge_slashes)
/// directive: `true` is `on` (the nginx default), and `false` is `off`.
pub fn parse_origin_form(input: &[u8], merge_slashes: bool) -> Result<Parsed<'_>, ParseError> {
    // HTTP/2 and HTTP/3 reject an empty :path before parsing it.
    if input.is_empty() {
        return Err(ParseError);
    }

    let mut r = Request::default();

    // Stage 1 scans the request target and records whether normalization is
    // needed. Unlike stage 2, it does not read nginx's trailing LF sentinel.
    ngx_http_parse_uri(&mut r, input)?;

    let path = if r.complex_uri || r.quoted_uri || r.empty_path_in_uri {
        // Stage 2 normalizes the request target into a separate output buffer.
        // `read_with_lf_sentinel` supplies nginx's trailing LF sentinel.
        //
        // Output never exceeds input length; +1 covers the
        // (origin-form-unreachable) empty-path leading slash.
        let mut out = vec![0u8; input.len() + 1];
        ngx_http_parse_complex_uri(&mut r, input, &mut out, merge_slashes)?;
        out.truncate(r.uri.len);
        Cow::Owned(out)
    } else {
        // "simple" path: returned unchanged, query string excluded — borrow the
        // input directly, no allocation.
        let len = match r.args_start {
            Some(a) => a - 1,
            None => input.len(),
        };
        Cow::Borrowed(&input[..len])
    };

    Ok(Parsed {
        path,
        args: parsed_args(&r, input),
    })
}

/// Compute nginx's `r->args` for a parsed target, mirroring the trailing args
/// assignment in `ngx_http_process_request_uri`:
///
/// ```c
/// if (r->args_start && r->uri_end > r->args_start) {
///     r->args.len  = r->uri_end - r->args_start;
///     r->args.data = r->args_start;
/// }
/// ```
///
/// When a complex URI delimits the query with a `#`, `ngx_http_parse_complex_uri`
/// has already recorded `r.args` and cleared `args_start`; that case skips the
/// block above, exactly as the NULL `args_start` does in nginx.
fn parsed_args<'a>(r: &Request, input: &'a [u8]) -> Option<&'a [u8]> {
    let uri_end = input.len();

    // `args.data` is an offset just after a '?', always >= 2 for origin-form
    // input (the path starts with '/'), so 0 is nginx's NULL sentinel. A
    // non-zero `data` means parse_complex_uri delimited the query at a '#'
    // (possibly empty, e.g. "/a?#f").
    if r.args.data != 0 {
        return Some(&input[r.args.data..r.args.data + r.args.len]);
    }
    // Otherwise the query, if any, runs from `args_start` to the end of input.
    match r.args_start {
        Some(a) if uri_end > a => Some(&input[a..uri_end]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::{String, ToString};

    fn norm(s: &str, merge: bool) -> Result<String, ParseError> {
        parse_origin_form(s.as_bytes(), merge)
            .map(|n| String::from_utf8(n.path.into_owned()).unwrap())
    }

    /// The query string as an `Option<&str>` (`None` == no query component).
    fn args(s: &str, merge: bool) -> Option<String> {
        parse_origin_form(s.as_bytes(), merge)
            .unwrap()
            .args
            .map(|a| String::from_utf8(a.to_vec()).unwrap())
    }

    #[test]
    fn parse_error_implements_std_error() {
        fn assert_error<T: std::error::Error>() {}

        assert_error::<ParseError>();
        assert_eq!(ParseError.to_string(), "failed to parse request target");
    }

    #[test]
    fn simple_unchanged() {
        assert_eq!(norm("/", true).unwrap(), "/");
        assert_eq!(norm("/foo/bar", true).unwrap(), "/foo/bar");
    }

    #[test]
    fn dot_segments() {
        assert_eq!(norm("/foo/./bar", true).unwrap(), "/foo/bar");
        assert_eq!(norm("/foo/../bar", true).unwrap(), "/bar");
        assert_eq!(norm("/a/b/../../c", true).unwrap(), "/c");
        assert_eq!(norm("/../", true), Err(ParseError)); // escapes root
    }

    #[test]
    fn merge_slashes_toggle() {
        assert_eq!(norm("/a//b", true).unwrap(), "/a/b");
        assert_eq!(norm("/a//b", false).unwrap(), "/a//b");
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(norm("/%66oo", true).unwrap(), "/foo");
        assert_eq!(norm("/a%2fb", true).unwrap(), "/a/b"); // decoded '/', not merged
        assert_eq!(norm("/%2f/x", true).unwrap(), "/x");
        assert_eq!(norm("/%2e%2e/x", true), Err(ParseError)); // decoded ".." escapes
    }

    #[test]
    fn encoded_dots() {
        assert_eq!(norm("/foo/%2e%2e/bar", true).unwrap(), "/bar");
        assert_eq!(norm("/foo%2f..%2fbar", true).unwrap(), "/bar");
        assert_eq!(norm("/foo%2f%2e%2e%2fbar", true).unwrap(), "/bar");
    }

    #[test]
    fn query_split() {
        assert_eq!(norm("/foo?a=1", true).unwrap(), "/foo");
        assert_eq!(norm("/foo/../bar?x=%20", true).unwrap(), "/bar");
    }

    #[test]
    fn invalid() {
        assert_eq!(norm("relative", true), Err(ParseError)); // must start with '/'
        assert_eq!(norm("*", true), Err(ParseError)); // must start with '/'
        assert_eq!(norm("/%zz", true), Err(ParseError)); // bad %XX
        assert_eq!(norm("/%00", true), Err(ParseError)); // null byte
    }

    #[test]
    fn empty() {
        assert_eq!(norm("", true), Err(ParseError));
    }

    #[test]
    fn simple_path_borrows_input() {
        // A path needing no normalization must not allocate.
        assert!(matches!(
            parse_origin_form(b"/foo/bar", true).unwrap().path,
            Cow::Borrowed(_)
        ));
        // The query string is excluded, still by borrowing.
        assert!(matches!(
            parse_origin_form(b"/foo?a=1", true).unwrap().path,
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn parsed_path_is_owned() {
        assert!(matches!(
            parse_origin_form(b"/foo/../bar", true).unwrap().path,
            Cow::Owned(_)
        ));
        assert!(matches!(
            parse_origin_form(b"/%66oo", true).unwrap().path,
            Cow::Owned(_)
        ));
    }

    #[test]
    fn args_returned() {
        // No query component.
        assert_eq!(args("/foo", true), None);
        assert_eq!(args("/foo/../bar", true), None); // complex, still no query

        // Simple path with a query.
        assert_eq!(args("/foo?a=1", true).as_deref(), Some("a=1"));
        // Complex path (normalized) with a query, terminated by end of input.
        assert_eq!(args("/foo/../bar?x=%20", true).as_deref(), Some("x=%20"));

        // A '#' fragment terminates the query (and the fragment is dropped).
        assert_eq!(args("/foo?a=1#frag", true).as_deref(), Some("a=1"));

        // Trailing '?' with nothing after it: nginx leaves r->args.data NULL.
        assert_eq!(args("/foo?", true), None);
        // Present-but-empty query: '?' immediately followed by '#'.
        assert_eq!(args("/foo?#frag", true).as_deref(), Some(""));

        // The query string is never normalized, even when the path is.
        assert_eq!(args("/a/../b?p=%2e%2e", true).as_deref(), Some("p=%2e%2e"));
    }

    #[test]
    fn args_borrow_input() {
        // args always borrows the input (Option<&[u8]>, no allocation).
        let input = b"/foo?a=1";
        let n = parse_origin_form(input, true).unwrap();
        let a = n.args.unwrap();
        assert!(std::ptr::eq(a.as_ptr(), input[5..].as_ptr()));
    }
}
