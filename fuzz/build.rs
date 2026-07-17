use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    // fuzz is at url-parse-nginx/fuzz; the C reference at
    // url-parse-nginx/nginx-reference.
    let harness = manifest.join("../nginx-reference");
    let src = harness.join("nginx_url.c");

    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", harness.join("ngx_stub.h").display());

    cc::Build::new()
        .file(&src)
        .include(&harness)
        .opt_level(1)
        .warnings(false)
        .compile("nginx_url");
}
