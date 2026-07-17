use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    // bench is at url-parse-nginx/bench; the C reference at
    // url-parse-nginx/nginx-reference.
    let reference = manifest.join("../nginx-reference");
    let src = reference.join("nginx_url.c");

    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", reference.join("ngx_stub.h").display());

    // Optimize the C at -O3 so it is not artificially handicapped against the
    // Rust release build (which is also opt-level 3).
    cc::Build::new()
        .file(&src)
        .include(&reference)
        .opt_level(3)
        .warnings(false)
        .compile("nginx_url");
}
