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
    let commit = resolve_build_commit();
    if let Some(ref sha) = commit {
        println!("cargo:rustc-env=PUCK_AGENT_COMMIT={sha}");
    }
    emit_version(commit.as_deref());

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
// absent); otherwise shell out to git.  Returns None on any failure so the
// agent reports no commit rather than a bogus one.
fn resolve_build_commit() -> Option<String> {
    // Re-run if the env override or the checked-out commit changes.
    println!("cargo:rerun-if-env-changed=PUCK_AGENT_COMMIT");
    println!("cargo:rerun-if-changed=../.git/HEAD");

    if let Ok(sha) = std::env::var("PUCK_AGENT_COMMIT") {
        let sha = sha.trim().to_string();
        if !sha.is_empty() {
            return Some(sha);
        }
    }

    let out = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if sha.is_empty() {
        None
    } else {
        Some(sha)
    }
}

// Resolve the version the agent reports via `--version` and to the server
// (puck_investigate agent_versions).  Prefer the release tag (GITHUB_REF_TYPE
// == "tag", GITHUB_REF_NAME == "v0.2.0") so a forgotten Cargo.toml bump can't
// mislabel a release — that is exactly the bug that shipped v0.2.0 reporting
// "0.1.0".  Fall back to the crate version for local / branch / dev builds.
// PUCK_AGENT_VERSION is the bare semver; PUCK_AGENT_LONG_VERSION appends the
// short commit (when known) for `--version` provenance.
fn emit_version(commit: Option<&str>) {
    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_TYPE");

    let crate_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let is_release_tag = std::env::var("GITHUB_REF_TYPE")
        .map(|t| t == "tag")
        .unwrap_or(false);
    let version = std::env::var("GITHUB_REF_NAME")
        .ok()
        .filter(|_| is_release_tag)
        .map(|t| t.trim().trim_start_matches('v').to_string())
        .filter(|t| !t.is_empty())
        .unwrap_or(crate_version);

    let long = match commit {
        Some(c) => format!("{version} ({c})"),
        None => version.clone(),
    };
    println!("cargo:rustc-env=PUCK_AGENT_VERSION={version}");
    println!("cargo:rustc-env=PUCK_AGENT_LONG_VERSION={long}");
}
