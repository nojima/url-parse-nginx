# Build a tiny shared object exposing nginx's URL-path normalizer to Rust.
#
#   make            -> libnginx_url.so
#   make extract    -> fetch pinned nginx from nginx.org, regenerate nginx_url.c
#   make verify     -> regenerate and fail if committed nginx_url.c is stale (CI)
#   make check      -> compile a quick self-test (selftest.c, if present)
#   make clean

CC      ?= cc
# -O0 keeps behavior closest to the reference and eases debugging; fuzzing
# throughput is dominated by the fuzzer, not this ~370-line function.
CFLAGS  ?= -O1 -g -Wall -Wextra -fPIC
# NGX_WIN32 / NGX_DEBUG intentionally left undefined (Linux, no debug logging).

SO      = libnginx_url.so

$(SO): nginx_url.c ngx_stub.h
	$(CC) $(CFLAGS) -shared -o $@ nginx_url.c

.PHONY: extract
extract:
	./tools/extract.sh

# CI: fetch the pinned nginx, regenerate, and fail if the committed vendored
# nginx_url.c is out of date.
.PHONY: verify
verify:
	./tools/extract.sh
	git diff --exit-code -- nginx_url.c

.PHONY: check
check: $(SO) selftest.c
	$(CC) $(CFLAGS) -no-pie -o selftest selftest.c nginx_url.c
	./selftest

.PHONY: clean
clean:
	rm -f $(SO) selftest
