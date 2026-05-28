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
