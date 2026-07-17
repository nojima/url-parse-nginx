/* Quick sanity checks for nginx_normalize_path(). Not the fuzzer. */
#include <stdio.h>
#include <string.h>

int nginx_normalize_path(const unsigned char *in, size_t in_len,
                         int merge_slashes,
                         unsigned char *out, size_t out_cap, size_t *out_len);

static int fails;

static void
check(const char *in, int merge, int want_rc, const char *want)
{
    unsigned char out[256];
    size_t out_len = 0;
    int rc = nginx_normalize_path((const unsigned char *) in, strlen(in),
                                  merge, out, sizeof(out), &out_len);

    int ok = (rc == want_rc)
             && (rc != 0 || (out_len == strlen(want)
                             && memcmp(out, want, out_len) == 0));

    printf("[%s] in=%-24s merge=%d -> rc=%d out=\"%.*s\"\n",
           ok ? "OK " : "BAD", in, merge, rc, (int) out_len, out);
    if (!ok) fails++;
}

int
main(void)
{
    /* simple / unchanged */
    check("/",                 1, 0, "/");
    check("/foo/bar",          1, 0, "/foo/bar");

    /* dot-segments */
    check("/foo/./bar",        1, 0, "/foo/bar");
    check("/foo/../bar",       1, 0, "/bar");
    check("/a/b/../../c",      1, 0, "/c");
    check("/../",              1, -1, "");        /* escapes root -> reject */

    /* merge_slashes toggle */
    check("/a//b",             1, 0, "/a/b");
    check("/a//b",             0, 0, "/a//b");

    /* percent-decoding */
    check("/%66oo",            1, 0, "/foo");
    check("/a%2fb",            1, 0, "/a/b");     /* decoded '/', not merged */
    check("/%2e%2e/x",         1, -1, "");        /* decoded ".." escapes    */

    /* query split: path only is returned */
    check("/foo?a=1",          1, 0, "/foo");
    check("/foo/../bar?x=%20", 1, 0, "/bar");

    /* invalid */
    check("relative",          1, -1, "");        /* must start with '/'     */
    check("/%zz",              1, -1, "");         /* bad %XX                 */

    printf(fails ? "\n%d FAILED\n" : "\nall passed\n", fails);
    return fails ? 1 : 0;
}
