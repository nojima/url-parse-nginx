use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    // difffuzz is at url-parse-nginx/difffuzz; the C harness at
    // url-parse-nginx/url-fuzz-harness.
    let harness = manifest.join("../url-fuzz-harness");
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
