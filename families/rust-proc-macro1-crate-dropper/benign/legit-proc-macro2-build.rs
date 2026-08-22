// Benign structural lookalike: a legitimate proc-macro2-style build.rs that
// probes the compiler's feature surface (the real proc-macro2 does exactly
// this). Shares the "build.rs in a proc-macro crate" surface but carries NONE
// of the dropper markers — no base64 URL fragments, no /tmp/rust-setup, no
// TLS-verify bypass, no payload fetch. Must NOT match.

use std::env;
use std::process::Command;

fn main() {
    let rustc = env::var_os("RUSTC").unwrap();
    let output = Command::new(rustc)
        .arg("--version")
        .output()
        .expect("failed to run rustc");
    let version = String::from_utf8_lossy(&output.stdout);

    // enable cfg flags based on detected toolchain features
    if version.contains("nightly") {
        println!("cargo:rustc-cfg=proc_macro_span");
    }
    println!("cargo:rustc-cfg=wrap_proc_macro");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTC_BOOTSTRAP");
}
