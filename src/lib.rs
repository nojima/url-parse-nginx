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

//! A faithful, 1-to-1 Rust port of nginx's URL path parser.
//!
//! This crate ports two functions from `src/http/ngx_http_parse.c`:
//!
//! * [`ngx_http_parse_uri`] — stage 1. Walks an origin-form path and sets the
//!   `complex_uri` / `quoted_uri` / `plus_in_uri` flags and the `args_start` /
//!   `uri_ext` boundaries. It does not modify the path.
//! * [`ngx_http_parse_complex_uri`] — stage 2. Decodes `%XX`, resolves `.` /
//!   `..` and collapses `//` (when `merge_slashes` is set), producing the
//!   normalized path.
//!
//! Only **origin-form** paths (starting with `/`, i.e. the HTTP/2 & HTTP/3
//! `:path` semantics) are handled — matching the fuzzing scope of
//! `nginx-reference`.
//!
//! # Porting conventions
//!
//! The C code walks raw buffers with `u_char *` cursors. Here:
//!
//! * `p` (the input cursor) is a `usize` index into a `buf: &[u8]`.
//! * `u` (the output cursor) is a `usize` index into `out: &mut [u8]`.
//!   Where nginx lets its pointer walk backwards past the buffer start during
//!   `..` handling, the Rust port uses `checked_sub` and returns the same error.
//! * Pointer fields that C stores as `u_char *` become `usize` offsets. Their
//!   base buffer follows the C code exactly: `args_start` is always an offset
//!   into the input; `uri_ext` is an input offset in stage 1 and an output
//!   offset in stage 2 (it is reset at the top of stage 2, so the two never
//!   interact — same as C).
//! * nginx relies on "there is always at least one readable byte (the LF)
//!   after the URI": stage 2 reads one byte at `uri_end`. The Rust port uses a
//!   checked read that yields `\n` at that position, avoiding an input copy
//!   made solely to materialize the sentinel.

use std::borrow::Cow;

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

/// The path was rejected by nginx (maps to `NGX_HTTP_PARSE_INVALID_REQUEST`
/// / `NGX_ERROR`, i.e. `rc == -1` in the C harness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError;

/// The result of parsing an origin-form request target — the normalized
/// `r->uri` and the `r->args` that nginx derives in
/// `ngx_http_process_request_uri`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed<'a> {
    /// The normalized path (nginx's `r->uri`), query string excluded.
    ///
    /// A path that needs no normalization borrows the input unchanged
    /// ([`Cow::Borrowed`], no allocation); a normalized path is owned
    /// ([`Cow::Owned`]).
    pub path: Cow<'a, [u8]>,

    /// The query string (nginx's `r->args`): the bytes after the first `?`, up
    /// to a `#` fragment or the end of the target. It always borrows the input
    /// — nginx never rewrites the query string.
    ///
    /// `None` when the target has no query component (nginx's `r->args.data` is
    /// NULL), which includes a trailing `?` with nothing after it (`"/a?"`).
    /// `Some(b"")` marks a present-but-empty query, e.g. the one in `"/a?#f"`.
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
/// Scans `buf[uri_start .. uri_end]` (origin-form) and sets flags/offsets.
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
/// Reads `buf[uri_start .. uri_end]`, and writes the normalized path into `out`,
/// setting `r.uri.len`. `out` must have capacity
/// `>= (uri_end - uri_start) + 1`.
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
/// Mirrors the Linux path of `ngx_http_process_request_uri()`:
///
/// * `Ok(`[`Parsed`]`)` — the normalized path (`r->uri`) and query string
///   (`r->args`). For a "simple" path that needs no normalization the path
///   borrows the input unchanged ([`Cow::Borrowed`]) — no allocation — just as
///   nginx returns the original bytes; normalization returns an owned buffer
///   ([`Cow::Owned`]). The query string always borrows the input.
/// * `Err(ParseError)` — nginx rejected the target.
///
/// `merge_slashes` corresponds to `cscf->merge_slashes` (nginx default: `true`).
pub fn parse_path_and_query(input: &[u8], merge_slashes: bool) -> Result<Parsed<'_>, ParseError> {
    let uri_start = 0;
    let uri_end = input.len();
    let mut r = Request::default();

    // stage 1: never reads past the input (the loop stops at `uri_end` and does
    // not touch `buf[uri_end]`), so it runs directly on `input` — no copy, no
    // sentinel, no allocation.
    ngx_http_parse_uri(&mut r, input)?;

    let path = if r.complex_uri || r.quoted_uri || r.empty_path_in_uri {
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
            Some(a) => a - 1 - uri_start,
            None => uri_end - uri_start,
        };
        Cow::Borrowed(&input[uri_start..uri_start + len])
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

    fn norm(s: &str, merge: bool) -> Result<String, ParseError> {
        parse_path_and_query(s.as_bytes(), merge)
            .map(|n| String::from_utf8(n.path.into_owned()).unwrap())
    }

    /// The query string as an `Option<&str>` (`None` == no query component).
    fn args(s: &str, merge: bool) -> Option<String> {
        parse_path_and_query(s.as_bytes(), merge)
            .unwrap()
            .args
            .map(|a| String::from_utf8(a.to_vec()).unwrap())
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
        assert_eq!(norm("/%2e%2e/x", true), Err(ParseError)); // decoded ".." escapes
    }

    #[test]
    fn query_split() {
        assert_eq!(norm("/foo?a=1", true).unwrap(), "/foo");
        assert_eq!(norm("/foo/../bar?x=%20", true).unwrap(), "/bar");
    }

    #[test]
    fn invalid() {
        assert_eq!(norm("relative", true), Err(ParseError)); // must start with '/'
        assert_eq!(norm("/%zz", true), Err(ParseError)); // bad %XX
    }

    #[test]
    fn empty() {
        assert_eq!(norm("", true).unwrap(), "");
    }

    #[test]
    fn simple_path_borrows_input() {
        // A path needing no normalization must not allocate.
        assert!(matches!(
            parse_path_and_query(b"/foo/bar", true).unwrap().path,
            Cow::Borrowed(_)
        ));
        // The query string is excluded, still by borrowing.
        assert!(matches!(
            parse_path_and_query(b"/foo?a=1", true).unwrap().path,
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn parsed_path_is_owned() {
        assert!(matches!(
            parse_path_and_query(b"/foo/../bar", true).unwrap().path,
            Cow::Owned(_)
        ));
        assert!(matches!(
            parse_path_and_query(b"/%66oo", true).unwrap().path,
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
        let n = parse_path_and_query(input, true).unwrap();
        let a = n.args.unwrap();
        assert!(std::ptr::eq(a.as_ptr(), input[5..].as_ptr()));
    }
}
