/*
 * Minimal nginx type/macro shim for the URL-path normalization fuzz harness.
 *
 * This provides ONLY the definitions that ngx_http_parse_uri() and
 * ngx_http_parse_complex_uri() actually reference (Linux, NGX_WIN32 and
 * NGX_DEBUG undefined). It is deliberately NOT a copy of nginx's headers:
 * the two parser functions call no other nginx function, so a tiny struct
 * is enough to run them verbatim.
 *
 * If you bump the vendored nginx version, re-verify the field set with:
 *   sed -n '1148,1296p;1299,1672p' src/http/ngx_http_parse.c \
 *     | grep -oE 'r->[a-z_]+(\.[a-z_]+)?' | sort -u
 */

#ifndef NGX_STUB_H
#define NGX_STUB_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* keep the NGX_SUPPRESS_WARN initializers in parse_complex_uri active */
#define NGX_SUPPRESS_WARN 1

/* NGX_WIN32 and NGX_DEBUG must stay undefined to match the Linux build */

typedef unsigned char   u_char;
typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

/* return codes (only equality against NGX_OK matters to the harness) */
#define NGX_OK                              0
#define NGX_ERROR                          -1
#define NGX_HTTP_PARSE_INVALID_REQUEST     10

/* ngx_log_debug3() is the only "call" in parse_complex_uri; make it vanish.
 * Because it is a no-op, NGX_LOG_DEBUG_HTTP and r->connection are never
 * evaluated, so neither needs to be defined. */
#define ngx_log_debug3(...)

/*
 * Trimmed ngx_http_request_t: exactly the fields touched by the two
 * extracted parsers. Field names/types match nginx so the functions
 * compile verbatim; order is irrelevant (no offset assumptions are made).
 */
typedef struct {
    ngx_str_t   uri;        /* out: normalized path                        */
    ngx_str_t   args;       /* out: query string (split at '?')            */
    ngx_str_t   exten;      /* out: extension                              */

    u_char     *uri_start;  /* in:  first byte of the raw path             */
    u_char     *uri_end;    /* in:  one past the last raw path byte        */

    u_char     *uri_ext;    /* internal                                    */
    u_char     *args_start; /* internal                                    */

    unsigned    complex_uri:1;      /* needs '.'/'..'/'//' normalization   */
    unsigned    quoted_uri:1;       /* contains %XX                        */
    unsigned    plus_in_uri:1;      /* contains '+'                        */
    unsigned    empty_path_in_uri:1;/* not reachable for origin-form input */
} ngx_http_request_t;

/* prototypes for the verbatim-extracted nginx functions */
ngx_int_t ngx_http_parse_uri(ngx_http_request_t *r);
ngx_int_t ngx_http_parse_complex_uri(ngx_http_request_t *r,
    ngx_uint_t merge_slashes);

#endif /* NGX_STUB_H */
