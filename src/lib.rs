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
//! `url-fuzz-harness`.
//!
//! # Porting conventions
//!
//! The C code walks raw buffers with `u_char *` cursors. Here:
//!
//! * `p` (the input cursor) is a `usize` index into a `buf: &[u8]`.
//! * `u` (the output cursor) is an `isize` index into `out: &mut [u8]`. It is
//!   signed because nginx lets it walk *backwards* past the buffer start
//!   during `..` handling and then checks `u < r->uri.data`.
//! * Pointer fields that C stores as `u_char *` become `usize` offsets. Their
//!   base buffer follows the C code exactly: `args_start` is always an offset
//!   into the input; `uri_ext` is an input offset in stage 1 and an output
//!   offset in stage 2 (it is reset at the top of stage 2, so the two never
//!   interact — same as C).
//! * nginx relies on "there is always at least one readable byte (the LF)
//!   after the URI": stage 2 reads one byte at `uri_end`. [`normalize_path`]
//!   reproduces this by appending a trailing `\n` sentinel to the input copy.

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

/// The path was rejected by nginx (maps to `NGX_HTTP_PARSE_INVALID_REQUEST`
/// / `NGX_ERROR`, i.e. `rc == -1` in the C harness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError;

/// A `{len, data-offset}` pair mirroring nginx's `ngx_str_t`. The base of
/// `data` (input vs output buffer) depends on the field, exactly as in C.
#[derive(Debug, Default, Clone, Copy)]
struct Str {
    len: usize,
    data: usize,
}

/// The subset of `ngx_http_request_t` touched by the two ported functions.
#[derive(Debug, Default)]
struct Request {
    // input range (indices into the working buffer)
    uri_start: usize,
    uri_end: usize,

    // outputs
    uri: Str,   // len = normalized path length; data = output-buffer offset
    args: Str,  // data = input offset (query string)
    exten: Str, // data = output offset (extension)

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
/// Scans `buf[r.uri_start .. r.uri_end]` (origin-form) and sets flags/offsets.
/// Returns `Err` where the C returns `NGX_ERROR`.
fn ngx_http_parse_uri(r: &mut Request, buf: &[u8]) -> Result<(), ParseError> {
    let mut state = UriState::Start;
    let mut p = r.uri_start;

    while p != r.uri_end {
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
                    // stay in CheckUri
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
fn finish_done(r: &mut Request, u: isize) -> Result<(), ParseError> {
    r.uri.len = u as usize;

    if let Some(ext) = r.uri_ext {
        // C computes a size_t difference that may wrap when u < uri_ext; match
        // that instead of panicking (exten is not part of the compared path).
        r.exten.len = (u as usize).wrapping_sub(ext);
        r.exten.data = ext;
    }

    r.uri_ext = None;
    Ok(())
}

/// The `args:` label of `ngx_http_parse_complex_uri()`.
fn finish_args(r: &mut Request, buf: &[u8], u: isize, mut p: usize) -> Result<(), ParseError> {
    while p < r.uri_end {
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
/// Reads `buf[r.uri_start ..= r.uri_end]` (note: it reads the sentinel byte at
/// `uri_end`) and writes the normalized path into `out`, setting `r.uri.len`.
/// `out` must have capacity `>= (uri_end - uri_start) + 1`.
fn ngx_http_parse_complex_uri(
    r: &mut Request,
    buf: &[u8],
    out: &mut [u8],
    merge_slashes: bool,
) -> Result<(), ParseError> {
    let mut state = State::Usual;
    let mut quoted_state = State::Usual;
    let mut decoded: u8 = 0;

    let mut p = r.uri_start;
    let mut u: isize = 0;
    r.uri_ext = None;
    r.args_start = None;

    if r.empty_path_in_uri {
        out[u as usize] = b'/';
        u += 1;
    }

    let mut ch = buf[p];
    p += 1;

    while p <= r.uri_end {
        match state {
            State::Usual => {
                if usual(ch) {
                    out[u as usize] = ch;
                    u += 1;
                    ch = buf[p];
                    p += 1;
                } else {
                    match ch {
                        b'/' => {
                            r.uri_ext = None;
                            state = State::Slash;
                            out[u as usize] = ch;
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
                            r.uri_ext = Some((u + 1) as usize);
                            out[u as usize] = ch;
                            u += 1;
                        }
                        b'+' => {
                            r.plus_in_uri = true;
                            out[u as usize] = ch;
                            u += 1;
                        }
                        _ => {
                            out[u as usize] = ch;
                            u += 1;
                        }
                    }
                    ch = buf[p];
                    p += 1;
                }
            }

            State::Slash => {
                if usual(ch) {
                    state = State::Usual;
                    out[u as usize] = ch;
                    u += 1;
                    ch = buf[p];
                    p += 1;
                } else {
                    match ch {
                        b'/' => {
                            if !merge_slashes {
                                out[u as usize] = ch;
                                u += 1;
                            }
                        }
                        b'.' => {
                            state = State::Dot;
                            out[u as usize] = ch;
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
                            out[u as usize] = ch;
                            u += 1;
                        }
                        _ => {
                            state = State::Usual;
                            out[u as usize] = ch;
                            u += 1;
                        }
                    }
                    ch = buf[p];
                    p += 1;
                }
            }

            State::Dot => {
                if usual(ch) {
                    state = State::Usual;
                    out[u as usize] = ch;
                    u += 1;
                    ch = buf[p];
                    p += 1;
                } else {
                    match ch {
                        b'/' => {
                            state = State::Slash;
                            u -= 1;
                        }
                        b'.' => {
                            state = State::DotDot;
                            out[u as usize] = ch;
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
                            out[u as usize] = ch;
                            u += 1;
                        }
                        _ => {
                            state = State::Usual;
                            out[u as usize] = ch;
                            u += 1;
                        }
                    }
                    ch = buf[p];
                    p += 1;
                }
            }

            State::DotDot => {
                if usual(ch) {
                    state = State::Usual;
                    out[u as usize] = ch;
                    u += 1;
                    ch = buf[p];
                    p += 1;
                } else {
                    match ch {
                        b'/' | b'?' | b'#' => {
                            u -= 4;
                            loop {
                                if u < 0 {
                                    return Err(ParseError);
                                }
                                if out[u as usize] == b'/' {
                                    u += 1;
                                    break;
                                }
                                u -= 1;
                            }
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
                            out[u as usize] = ch;
                            u += 1;
                        }
                        _ => {
                            state = State::Usual;
                            out[u as usize] = ch;
                            u += 1;
                        }
                    }
                    ch = buf[p];
                    p += 1;
                }
            }

            State::Quoted => {
                r.quoted_uri = true;

                if ch.is_ascii_digit() {
                    decoded = ch - b'0';
                    state = State::QuotedSecond;
                    ch = buf[p];
                    p += 1;
                } else {
                    let c = ch | 0x20;
                    if (b'a'..=b'f').contains(&c) {
                        decoded = c - b'a' + 10;
                        state = State::QuotedSecond;
                        ch = buf[p];
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
                        out[u as usize] = ch;
                        u += 1;
                        ch = buf[p];
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
                            out[u as usize] = ch;
                            u += 1;
                            ch = buf[p];
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
        u -= 4;
        loop {
            if u < 0 {
                return Err(ParseError);
            }
            if out[u as usize] == b'/' {
                u += 1;
                break;
            }
            u -= 1;
        }
    }

    finish_done(r, u)
}

/// Normalize a single origin-form path exactly as nginx does.
///
/// Mirrors the `nginx_normalize_path` wrapper in `url-fuzz-harness`, which
/// reproduces the Linux path of `ngx_http_process_request_uri()`:
///
/// * `Ok(path)` — the normalized path bytes (query string excluded, matching
///   `r->uri`). For a "simple" path that needs no normalization this is the
///   input unchanged, just as nginx returns the original bytes.
/// * `Err(ParseError)` — nginx rejected the path.
///
/// `merge_slashes` corresponds to `cscf->merge_slashes` (nginx default: `true`).
pub fn normalize_path(input: &[u8], merge_slashes: bool) -> Result<Vec<u8>, ParseError> {
    // nginx invariant: a readable byte (the LF) always follows the URI.
    let mut buf = Vec::with_capacity(input.len() + 1);
    buf.extend_from_slice(input);
    buf.push(b'\n');

    let mut r = Request {
        uri_start: 0,
        uri_end: input.len(),
        ..Request::default()
    };

    // stage 1
    ngx_http_parse_uri(&mut r, &buf)?;

    if r.complex_uri || r.quoted_uri || r.empty_path_in_uri {
        // stage 2: normalization. Output never exceeds input length; +1
        // covers the (origin-form-unreachable) empty-path leading slash.
        let mut out = vec![0u8; input.len() + 1];
        ngx_http_parse_complex_uri(&mut r, &buf, &mut out, merge_slashes)?;
        out.truncate(r.uri.len);
        Ok(out)
    } else {
        // "simple" path: returned unchanged, query string excluded.
        let len = match r.args_start {
            Some(a) => a - 1 - r.uri_start,
            None => r.uri_end - r.uri_start,
        };
        Ok(input[r.uri_start..r.uri_start + len].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(s: &str, merge: bool) -> Result<String, ParseError> {
        normalize_path(s.as_bytes(), merge).map(|v| String::from_utf8(v).unwrap())
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
}
