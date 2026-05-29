// Embed a Windows PE resource block into puck-agent.exe so File
// Properties → Details shows the same provenance as our Cargo.toml.
//
// Cross-compile note: winres invokes `windres` (mingw-w64) when
// building Windows binaries from Linux/macOS.  The release.yml
// builds Windows binaries on a windows-latest runner where rc.exe
// is available, so cross-compile tooling isn't a concern for our
// release path.  Local cross-compile from Linux requires
// `apt install mingw-w64` to populate windres.
fn main() {
    emit_build_commit();

    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();
        res.set("ProductName", "Puck Agent");
        res.set(
            "FileDescription",
            "Puck endpoint agent — read-only investigation",
        );
        res.set("CompanyName", "Puck Security");
        res.set("LegalCopyright", "Copyright 2026 Puck Security");
        res.set("OriginalFilename", "puck-agent.exe");
        res.set("FileVersion", env!("CARGO_PKG_VERSION"));
        res.set("ProductVersion", env!("CARGO_PKG_VERSION"));
        res.compile().expect("compile windows resource");
    }
}

// Capture the short git commit so the running agent can report which build
// it is (surfaced fleet-wide via puck_investigate agent_versions, mirroring
// the MCP server's -ldflags commit injection).  Best-effort: an explicit
// PUCK_AGENT_COMMIT env var wins (CI / source-tarball builds where .git is
// absent); otherwise shell out to git.  On any failure we leave the var
// unset so option_env!("PUCK_AGENT_COMMIT") yields None and the agent
// reports no commit rather than a bogus one.
fn emit_build_commit() {
    // Re-run if the env override or the checked-out commit changes.
    println!("cargo:rerun-if-env-changed=PUCK_AGENT_COMMIT");
    println!("cargo:rerun-if-changed=../.git/HEAD");

    if let Ok(sha) = std::env::var("PUCK_AGENT_COMMIT") {
        let sha = sha.trim();
        if !sha.is_empty() {
            println!("cargo:rustc-env=PUCK_AGENT_COMMIT={sha}");
            return;
        }
    }

    if let Ok(out) = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
    {
        if out.status.success() {
            if let Ok(sha) = String::from_utf8(out.stdout) {
                let sha = sha.trim();
                if !sha.is_empty() {
                    println!("cargo:rustc-env=PUCK_AGENT_COMMIT={sha}");
                }
            }
        }
    }
}
