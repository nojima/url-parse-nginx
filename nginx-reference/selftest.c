/* Quick sanity checks for nginx_parse_path_and_query(). Not the fuzzer. */
#include <stdio.h>
#include <string.h>

int nginx_parse_path_and_query(const unsigned char *in, size_t in_len,
                               int merge_slashes,
                               unsigned char *out, size_t out_cap,
                               size_t *out_len, size_t *args_offset,
                               size_t *args_len, int *args_present);

static int fails;

static void
check(const char *in, int merge, int want_rc, const char *want_path,
      const char *want_args)
{
    unsigned char out[256];
    size_t in_len = strlen(in);
    size_t out_len = 0;
    size_t args_offset = 0;
    size_t args_len = 0;
    int args_present = 0;
    int want_args_present = want_args != NULL;
    int rc = nginx_parse_path_and_query(
        (const unsigned char *) in, in_len, merge, out, sizeof(out), &out_len,
        &args_offset, &args_len, &args_present);

    int ok = (rc == want_rc)
             && (rc != 0
                 || (out_len == strlen(want_path)
                     && memcmp(out, want_path, out_len) == 0
                     && args_present == want_args_present
                     && (!args_present
                         || (args_offset <= in_len
                             && args_len <= in_len - args_offset
                             && args_len == strlen(want_args)
                             && memcmp(in + args_offset, want_args, args_len)
                                    == 0))));

    printf("[%s] in=%-24s merge=%d -> rc=%d path=\"%.*s\" "
           "args_present=%d args_offset=%zu args_len=%zu\n",
           ok ? "OK " : "BAD", in, merge, rc, (int) out_len, out,
           args_present, args_offset, args_len);
    if (!ok) fails++;
}

int
main(void)
{
    /* simple / unchanged */
    check("/",                 1, 0, "/", NULL);
    check("/foo/bar",          1, 0, "/foo/bar", NULL);

    /* dot-segments */
    check("/foo/./bar",        1, 0, "/foo/bar", NULL);
    check("/foo/../bar",       1, 0, "/bar", NULL);
    check("/a/b/../../c",      1, 0, "/c", NULL);
    check("/../",              1, -1, "", NULL);  /* escapes root -> reject */

    /* merge_slashes toggle */
    check("/a//b",             1, 0, "/a/b", NULL);
    check("/a//b",             0, 0, "/a//b", NULL);

    /* percent-decoding */
    check("/%66oo",            1, 0, "/foo", NULL);
    check("/a%2fb",            1, 0, "/a/b", NULL); /* decoded '/', not merged */
    check("/%2e%2e/x",         1, -1, "", NULL);  /* decoded ".." escapes */

    /* query split */
    check("/foo?a=1",          1, 0, "/foo", "a=1");
    check("/foo/../bar?x=%20", 1, 0, "/bar", "x=%20");
    check("/foo?a=1#fragment", 1, 0, "/foo", "a=1");
    check("/foo?",             1, 0, "/foo", NULL);
    check("/foo?#fragment",    1, 0, "/foo", "");

    /* invalid */
    check("relative",          1, -1, "", NULL);  /* must start with '/' */
    check("/%zz",              1, -1, "", NULL);  /* bad %XX */

    printf(fails ? "\n%d FAILED\n" : "\nall passed\n", fails);
    return fails ? 1 : 0;
}
