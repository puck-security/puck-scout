# Credential Exposure on Developer & Corporate Endpoints: A Comprehensive Reference for a Credential-Discovery Skill (2024–2026)

## TL;DR

- **Modern infostealers (AMOS/Atomic, Banshee, Cthulhu, Poseidon/Odyssey on macOS; Lumma/Remus, StealC v2, Vidar, RedLine, Rhadamanthys, Acreed, Void, Torg Grabber on Windows) converge on the same harvest list**: browser SQLite stores (Login Data, Cookies, Web Data, IndexedDB, Local Storage), 100+ wallet/2FA browser extensions, Telegram tdata, Discord/Slack leveldb tokens, Signal `config.json`, SSH/cloud CLI dotfiles, Keychain/DPAPI credential blobs, and any file in Desktop/Documents/Downloads matching `wallet|key|seed|cred|secret|backup|export|.env|.kdbx|.pem`. Recorded Future indexed ~1.95 billion credential exposures from malware logs in 2025, 31% paired with active session cookies that bypass MFA.
- **The "no user prompt" boundary on Windows is permissive, on macOS narrow.** On Windows, anything DPAPI-protected to the user (`%APPDATA%\Microsoft\Credentials\`, Chrome `Local State` master key pre-Chrome-127, Azure CLI `msal_token_cache.bin`, RDP saved creds, WinSCP/PuTTY registry, FileZilla `sitemanager.xml`) decrypts silently in-process. On macOS, the login keychain auto-unlocks at session start so *generic* keychain items (e.g. Chrome Safe Storage, Slack `xoxc`/`d` cookie, aws-vault default keychain) decrypt silently — but per-item ACLs prompt the user, and any item created with `kSecAccessControlBiometryCurrentSet`/`UserPresence` (Touch ID gated) is **out of scope**. Safari passwords and iCloud Keychain items are end-to-end encrypted to the device key and effectively out of scope without a phishing prompt. Chrome 127+ App-Bound Encryption (ABE) on Windows added an in-scope complication: the per-app key now requires the SYSTEM-run elevation service or in-process injection to retrieve, but every major stealer (Lumma/Remus, StealC v2, Vidar, Rhadamanthys, Meduza, WhiteSnake, Phemedrone, Lumar, Void, Torg) has a working bypass that runs in-user-context.
- **The skill should generalize via patterns rather than a per-tool list.** Six pattern families cover ~95% of what stealers and post-compromise operators actually grab: (1) any `~/.{cli}/` dotdir containing `.json|.toml|.yaml|.ini|credentials|auth|token`; (2) any Electron app's `Local Storage/leveldb/`, `IndexedDB/`, and `Cookies` SQLite under `~/Library/Application Support/<app>` (macOS) or `%APPDATA%\<app>` (Windows); (3) any file matching `(?i)(emergency.?kit|recovery|backup|export|secret|password|cred|api.?key|wallet|seed).*\.(pdf|csv|json|txt|kdbx|1pif|zip|tar\.gz)` in Downloads/Desktop/iCloud Drive/Dropbox/OneDrive/Google Drive; (4) any `*.kdbx`, `*.key`, `id_*` private key, `*.pem`, `*.ppk`, `*.p12`, `*.pfx` outside protected dirs; (5) `.env*`, `.netrc`, `.git-credentials`, embedded tokens in shell history (`(ghp|github_pat|gho|ghs|xox[baprs]|sk-ant|sk-proj|sk-|hf_|nvapi-|AKIA|ASIA|AGPA|AIDA|gho_|glpat-|gsk_)…`); (6) high-entropy strings ≥ 32 chars adjacent to keywords `key|token|secret|password|auth|cred|api`. These compose with trufflehog's ~700 detectors and gitleaks' default rule pack as the regex back-end.

---

## Threat Model & Scope

The skill must reason from **two operator profiles**:

1. **Post-compromise human operator** with an interactive shell as the logged-in user. They can read anything the user can read without triggering UI; they want lateral movement, cloud pivot, and SaaS access. Their cost model values discoverability (`find`/Spotlight) and time-to-pivot.
2. **Infostealer malware** (single-shot, smash-and-grab): Atomic/AMOS, Banshee, Cthulhu, Poseidon, Odyssey, RodStealer, Mac.C/MacSync (macOS); Lumma/LummaC2/Remus, StealC v2/Monster, Vidar, RedLine, Raccoon, Rhadamanthys, Meduza, WhiteSnake, Acreed, Phemedrone, Lumar, Void, Torg Grabber, Sryxen, Chihuahua, Xenostealer, Pupkin (Windows). They use a hand-curated path list compiled into the binary; the skill's job is to know that list and *generalize past it*.

**The "no human confirmation" boundary**:

- **In scope (silent under user privileges):** plaintext config files, SQLite stores readable by user, DPAPI blobs decryptable by `CryptUnprotectData()` from the same user session, macOS keychain items with default ACL on login keychain (auto-unlocked at logon), Electron `safeStorage` items on Windows (DPAPI) and Linux (often `basic_text` plaintext if no GNOME Keyring/KWallet), Chrome 127+ ABE-encrypted material (via in-process injection / IElevator COM bypass — runs without a UI prompt).
- **Out of scope (requires a user-facing confirmation):** Touch ID-gated keychain items (those created with `LAContext`/`SecAccessControl` requiring biometry), Windows Hello-protected Web Credentials in Edge, Safari saved passwords (System Keychain item `com.apple.account.IdentityServices.token` and similar are end-to-end encrypted), iCloud Keychain `keychain-2.db` (sealed with the device escrow key), 1Password/Bitwarden/KeePass/LastPass *unlocked* vault contents (always require master password / biometric unlock), TPM-bound keys, Azure WAM tokens that re-prompt, sudo-required `/Library/Keychains/System.keychain` items.

The boundary is a *capability* check: if reading the artifact requires user input that surfaces a prompt the victim can deny, the skill must *not* attempt extraction. It can still flag *existence* (file present, size, last-modified) — that is itself useful intelligence and matches what tools like Kolide do for 1Password Emergency Kits.

---

## A) Password-Manager Artifacts Accessible Without Master-Password Unlock

### A.1 1Password Emergency Kit PDFs

**Why it matters:** The PDF contains the Sign-in URL, email, and 36-character Secret Key. Combined with a phished or reused master password, this gives full vault access from any device. 1Password's setup flow downloads it through the browser, so it lands in the default Downloads location and most users never move it. This is well-known prior art (Kolide built a dedicated check around it).

- **macOS paths:** `~/Downloads/1Password Emergency Kit*.pdf`, `~/Desktop/`, `~/Documents/`, `~/Library/Mobile Documents/com~apple~CloudDocs/` (iCloud Drive), `~/Library/CloudStorage/Dropbox*/`, `~/Library/CloudStorage/GoogleDrive-*/`, `~/Library/CloudStorage/OneDrive*/`. Spotlight: `mdfind "kMDItemTextContent == 'sign in to your 1Password account in an emergency' || kMDItemFSName == '1Password Emergency Kit*.pdf'"`.
- **Windows paths:** `%USERPROFILE%\Downloads\`, `%USERPROFILE%\Desktop\`, `%USERPROFILE%\Documents\`, `%USERPROFILE%\OneDrive*\`, `%USERPROFILE%\Dropbox*\`, `%USERPROFILE%\iCloudDrive\`. No equivalent indexed search; use recursive walk.
- **Linux:** `~/Downloads/`, `~/Desktop/`, `~/Dropbox/`, `~/OneDrive/`, `~/google-drive/`.
- **Prompt boundary:** Silent. Plain PDF readable by user.
- **Detection pattern:** filename `(?i)1password.?emergency.?kit.*\.pdf`; PDF text-content match for the literal string `"sign in to your 1Password account in an emergency"` or the Secret Key prefix `A3-` followed by `[A-Z0-9]{6}-...` (gitleaks rule `1password-secret-key`).
- **Severity:** Critical (Secret Key + Sign-in URL = half of the auth factors needed; if the PDF is filled in with master password — and a depressing fraction are — full vault compromise).
- **Stealer observation:** AMOS variants explicitly grep Desktop/Documents/Downloads for `*.pdf` paired with `password`, `1password`, `kit`, `recovery` patterns; Trend Micro's Sept 2025 AMOS analysis describes targeting "personal documents (TXT, PDF, DOCX, JSON, DB, WALLET, KEY) from the Desktop, Documents, and Downloads folders."

### A.2 1Password CLI (`op`) Session Tokens & SSH Agent Integration

- **macOS:** Session state in `~/Library/Group Containers/2BUA8C4S2C.com.1password/Library/Caches/` and `~/.config/op/config`. SSH agent socket at `~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock`. The agent itself enforces biometric/system-auth on signing operations (so the *socket existence* is a signal but the *keys* are biometric-gated → **out of scope** for direct key extraction). However, `op signin` session tokens cached for the active session can be read from environment variables in shell history and from any `op` subprocess via `/proc`.
- **Windows:** `%LOCALAPPDATA%\1Password\config\` and named pipe `\\.\pipe\openssh-ssh-agent` if 1Password's SSH agent is enabled. Same biometric gate.
- **Detection:** `op://` references in `.env` files and shell history; `~/.config/op/config` contains account UUIDs and sign-in URLs (not the password) — useful as a fingerprint of which 1Password tenant the user belongs to.
- **Severity:** Low for direct key theft (biometric blocks); medium for reconnaissance.

### A.3 Bitwarden Exports

**Why it matters:** Bitwarden writes exports to whatever the device's default download location is — typically `~/Downloads`. Exports come in three formats: `.csv` and unencrypted `.json` are **plaintext** with full vault contents; `.json (encrypted)` requires a separate password. Many users export "as a backup" and forget to delete.

- **All OSes:** Browser default download location (`~/Downloads` on macOS/Linux, `%USERPROFILE%\Downloads\` on Windows). CLI `bw export` defaults to the working directory.
- **Filename patterns:** `bitwarden_export_<YYYYMMDDHHMMSS>.json`, `bitwarden_export_*.csv`, or user-chosen names.
- **Detection regex:** `(?i)bitwarden[_-]export.*\.(json|csv)$`; for content, JSON files contain top-level keys `"encrypted": false` and `"items": [...]` with cleartext logins.
- **Severity:** Critical when unencrypted; encrypted exports are offline-brute-forceable but with the user's KDF settings (PBKDF2 iterations or Argon2 parameters) embedded.

### A.4 LastPass Exports

- **All OSes:** Browser default download. `lastpass_export.csv` is the historical default name; users frequently rename. Plaintext CSV.
- **Detection:** `(?i)lastpass[_-]?export.*\.csv$`; CSV header line contains `url,username,password,totp,extra,name,grouping,fav`.
- **Severity:** Critical. LastPass's 2022 vault breach made offline cracking of its exported files an industry concern; an unencrypted CSV in Downloads bypasses every LastPass server-side mitigation.

### A.5 KeePass `.kdbx` Files (and Paired Key Files)

**Why it matters:** A `.kdbx` is a strong AES/ChaCha20-encrypted vault, but the threat model permits *exfiltration for offline cracking*. If the user uses a key file in addition to (or instead of) a master password, finding the key file next to the database collapses security to the strength of any password component. JetBrains IDEs ship a `c.kdbx` in `~/.config/JetBrains/<Product><Version>/options/` (or `%APPDATA%\JetBrains\...` on Windows) containing all their stored credentials, and on Windows it is wrapped with a static internal password XOR'd with DPAPI'd `pdb.pwd` — fully recoverable from a logged-in user session (see `JetDecrypt`).

- **Patterns:** `*.kdbx` (KeePass2), `*.kdb` (legacy KeePass1), `*.key` / `*.keyx` adjacent. Common locations: `~/Documents/`, `~/Dropbox/`, `~/OneDrive/`, `~/Desktop/`, `~/.config/JetBrains/*/options/c.kdbx` + `pdb.pwd`.
- **Severity:** High (offline crackability) → Critical (when paired with a key file or when the JetBrains static-key construction is used).

### A.6 Browser Password-Manager Local Stores

These overlap with §B but appear here because they are functionally a password manager:

- **Chromium (Chrome/Edge/Brave/Arc/Vivaldi/Opera/Yandex/Comet):**
  - Windows: `%LOCALAPPDATA%\<vendor>\<browser>\User Data\<Profile>\Login Data` (SQLite), `Cookies`, `Web Data`, plus `User Data\Local State` (JSON) holding the encrypted master key.
  - macOS: `~/Library/Application Support/<vendor>/<browser>/<Profile>/Login Data` etc.; the AES master key lives in **macOS login keychain** under "Chrome Safe Storage" / "Brave Safe Storage" etc.
  - Linux: `~/.config/google-chrome/`, `~/.config/BraveSoftware/Brave-Browser/`, etc., with master key in `gnome-keyring` / `kwallet` (often `basic_text` plaintext if no DE backend exists).
- **Firefox:** `logins.json` + `key4.db` (and legacy `key3.db`/`signons.sqlite`). With **no master password set** (Firefox's default), `logins.json` is decryptable purely from `key4.db` via NSS — no OS prompt — see `firefox_decrypt`/`firepwd`. With a master password (now called "Primary Password") the export is only as strong as that password; offline brute-force is feasible.
- **Safari:** Items live in the user's login keychain with per-item ACLs that frequently include Touch ID gating; on modern macOS it migrates passwords into the Passwords app backed by iCloud Keychain. **Out of scope** for silent extraction.

### A.7 Bitwarden / 1Password / KeePassXC *cached* desktop databases

- **Bitwarden Desktop (Electron):** vault data is cached at `~/Library/Application Support/Bitwarden/data.json` (macOS), `%APPDATA%\Bitwarden\data.json` (Windows), encrypted with the user's master-key-derived key. Database itself is **out of scope** (master password required); but stale `data.json` files in user temp dirs and the existence of `Bitwarden CLI session token` shell history references are signals.
- **1Password 8 desktop:** SQLite at `~/Library/Group Containers/2BUA8C4S2C.com.1password/Library/Application Support/1Password/Data/B5.sqlite` (macOS) — encrypted at rest with a key sealed by the unlock factor; out of scope for content but **existence/file size** is reconnaissance.
- **KeePassXC:** Loaded `.kdbx` paths recorded in `~/.config/keepassxc/keepassxc.ini` `LastDatabases` key — useful pivoting hint to where the user keeps their vault.

---

## B) Browser-Resident Credentials and Session Material

### B.1 Chromium-Family Login Data and Cookies

- **Windows boundary (pre-Chrome 127):** `Login Data` (passwords) and `Cookies` are AES-256-GCM encrypted with a key from `Local State`'s `os_crypt.encrypted_key`, which is DPAPI-wrapped to the user. `CryptUnprotectData()` from the same user session returns plaintext silently. **In scope.**
- **Windows boundary (Chrome 127+, July 2024 — current):** App-Bound Encryption ties the cookie key to a SYSTEM elevation service called via the IElevator COM interface. The new `app_bound_encrypted_key` in `Local State` is double-wrapped with SYSTEM DPAPI. To bypass, in-user-context malware now uses one of:
  - Headless Chrome with `--remote-debugging-port=` to ask Chrome itself to decrypt cookies (Sryxen, Stealc).
  - Reflective DLL injection into a Chromium process to call `IElevator` (Lumma, Remus, Vidar, StealC v2, Rhadamanthys, Meduza, WhiteSnake, Phemedrone, Lumar, Void, Torg, DumpBrowserSecrets).
  - `os_crypt_async::Encryptor` vtable scrape + `CryptUnprotectMemory` (Lumma/Remus shellcode pattern).
  - COM hijacking to point Chrome at a non-existent elevation server, forcing fallback to the legacy DPAPI-only path (CyberArk's "C4 Bomb" technique, abused by stealers as of 2025).
  No user-facing prompt fires for any of these. **Still in scope** — the skill should treat ABE-protected data as *accessible* but flag that decryption requires browser-process injection (which an investigator would observe as anomalous Chrome child process telemetry).
- **macOS boundary:** Login Data is AES-128-GCM encrypted with a key in the **login keychain** under "Chrome Safe Storage". The login keychain auto-unlocks at logon, so a user-context process calling `SecKeychainFindGenericPassword` for the Chrome service typically gets the key without a prompt — but reading another app's keychain item triggers the standard "X wants to access key in your keychain" prompt unless the requesting binary's code-sign identity matches the original creator's ACL. AMOS, Banshee, Cthulhu, Poseidon all sidestep this by **phishing the system password via osascript** and then running `security find-generic-password -wa "Chrome"` — that step is *out of scope* for the skill (it requires a user prompt). In scope: existence of the SQLite files, profile inventory, and unencrypted columns (URL, username, last-used timestamps).
- **Linux:** `~/.config/google-chrome/Default/Login Data`; key in libsecret or `basic_text` plaintext. In-scope when `basic_text`.
- **Detection patterns:** existence of `Login Data`, `Cookies`, `Web Data`, `Network/Cookies`, `History`, `Local State` under the Chromium profile dir tree. The cookie value `user_session` for `github.com`, `d` for `slack.com`, `_iam_idle_session_id` for AWS, `JSESSIONID` / `__Secure-next-auth.session-token` for various SaaS apps are high-value session-theft targets — Recorded Future found 31% of indexed credentials had matching live session cookies.
- **Severity:** Critical. Slack's `d` cookie is workspace-spanning; GitHub's `user_session` bypasses MFA; AWS console cookies enable instant pivot.

### B.2 SaaS Session Storage / IndexedDB / Service-Worker Caches

The browser's `IndexedDB`, `Local Storage/leveldb/`, and `Service Worker/CacheStorage/` directories persist bearer/JWT tokens for many SaaS apps (Notion, Linear, Figma, Atlassian, GitHub, Slack-web). These are **plaintext leveldb/SQLite** — no per-app encryption. Reading them is a trivial walk; the skill should look for the prefix `xoxc-` (Slack), `slack-d` cookie, `gho_`/`ghu_` (GitHub), `github_pat_`, `eyJ` (JWTs), `Bearer ` substrings.

### B.3 Browser Sync / Refresh Tokens

Chrome Sync's `Account` token is encrypted with the same OSCrypt key and yields the user's full sync state when paired with the master key. Edge has equivalent under `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\`. Brave, Arc, Vivaldi inherit Chromium's design.

### B.4 Browser Autofill (Web Data)

`Web Data` SQLite contains addresses, phone numbers, credit-card numbers (CC numbers AES-GCM encrypted with the same OSCrypt key) and *form-history* (text typed into form fields, often including passwords on misconfigured sites).

---

## C) Desktop Application Session Storage (Electron and Native)

The general pattern: **any Electron app with persistent login** stores session material in one of three places:

1. **Cookies** SQLite under `<userdata>/Cookies` or `<userdata>/Network/Cookies` — encrypted with `safeStorage` key (Keychain on macOS / DPAPI on Windows / libsecret-or-plaintext on Linux).
2. **`Local Storage/leveldb/`** — plaintext key-value store. Frequently contains long-lived OAuth tokens because developers think Electron localStorage is "sandboxed". (Empirically, **most Electron apps still leak tokens via leveldb** because `safeStorage` was an afterthought in many products; Signal's 2024 belated migration is the canonical example.)
3. **`IndexedDB/<origin>.indexeddb.leveldb/`** — same story.

The skill heuristic should be: *for any directory that contains both `Local Storage/leveldb/` and `Cookies` (with no `LOCK` from a running process), greppable for `Bearer `, `xox`, `eyJ`, `gho_`, `github_pat_`, `sk_live_`, `sk_test_`*.

| App | macOS path | Windows path | Notes |
|---|---|---|---|
| Slack desktop | `~/Library/Containers/com.tinyspeck.slackmacgap/Data/Library/Application Support/Slack/Local Storage/leveldb/` (sandboxed) or `~/Library/Application Support/Slack/Local Storage/leveldb/` (unsandboxed). Cookies file alongside. | `%APPDATA%\Slack\Local Storage\leveldb\` and `%APPDATA%\Slack\Cookies` | `xoxc-…` token in leveldb + the `d` cookie give full API access; the `d` cookie is shared across all the user's workspaces. Slack's 2022 GitHub breach was rooted in this exact theft pattern. |
| Discord | `~/Library/Application Support/discord/Local Storage/leveldb/` and `~/Library/Application Support/discord/Cookies` | `%APPDATA%\discord\Local Storage\leveldb\` (also `discordcanary`, `discordptb`) | The user token regex `[\w-]{24}\.[\w-]{6}\.[\w-]{27}` and `mfa\.[\w-]{84}` is the most-implemented pattern in token-grabbers. |
| Microsoft Teams | `~/Library/Application Support/Microsoft/Teams/Cookies`, `~/Library/Containers/com.microsoft.teams2/` | `%APPDATA%\Microsoft\Teams\Cookies` (classic), `%LOCALAPPDATA%\Packages\MSTeams_8wekyb3d8bbwe\` (new Teams) | Skype-token cookie + Teams JWT enable Graph access; new Teams uses WAM tokens that re-prompt — partially out of scope. |
| Notion | `~/Library/Application Support/Notion/` | `%APPDATA%\Notion\` | leveldb plaintext often holds workspace JWTs. |
| Linear | `~/Library/Application Support/Linear/` | `%APPDATA%\Linear\` | OAuth tokens in IndexedDB. |
| Figma | `~/Library/Application Support/Figma/` | `%APPDATA%\Figma\` | Sandboxed plugin model; main app cookies still extractable. |
| Zoom | `~/Library/Application Support/zoom.us/` | `%APPDATA%\Zoom\data\` | Per-meeting tokens; less long-lived value but profile data leaks. |
| Postman | `~/Library/Application Support/Postman/` (vault.json + IndexedDB) | `%APPDATA%\Postman\` | Postman Vault stores secrets locally, encrypted with a vault key derived from the user's Postman password — the password is cached in the keychain so vault contents are reachable from user context unless the user explicitly logs out. Saved request `Authorization` headers in `IndexedDB` are typically plaintext bearer tokens to production APIs — high-value. |
| Insomnia | `~/Library/Application Support/Insomnia/` | `%APPDATA%\Insomnia\` | "Vault key" stored in OS keyring; environment.json is plaintext. |
| TablePlus | `~/Library/Application Support/com.tinyapp.TablePlus/` | `%APPDATA%\TablePlus\` | Connection list with passwords keychain-stored. |
| DBeaver | `~/Library/DBeaverData/workspace6/General/.dbeaver/credentials-config.json` | `%APPDATA%\DBeaver\workspace6\General\.dbeaver\credentials-config.json` | Encrypted with the local user's master key by default; offline-crackable when user changes the default. |
| DataGrip / JetBrains DB tools | `~/.config/JetBrains/DataGrip<ver>/options/c.kdbx` + `pdb.pwd` | `%APPDATA%\JetBrains\DataGrip<ver>\options\c.kdbx` + `pdb.pwd` | Recoverable via `JetDecrypt` (static key + DPAPI). |
| Postico, Sequel Ace | `~/Library/Application Support/Postico/` etc. | n/a | Connection strings in plist/SQLite; passwords typically in keychain (silent if same-app ACL). |
| Termius | `~/Library/Application Support/Termius/` | `%APPDATA%\Termius\` | Cloud-synced encrypted vault; local cache `app.db` SQLCipher-encrypted with key derived from account password (cached). |
| Royal TSX/TSE | `~/Library/Application Support/Royal TSX/` | `%APPDATA%\Royal TS\` | Per-document password or master-document; offline-crackable. |
| VS Code / Cursor / Windsurf / Trae / Kiro | `~/Library/Application Support/<App>/User/globalStorage/` and `~/Library/Application Support/<App>/User/workspaceStorage/<hash>/state.vscdb` | `%APPDATA%\<App>\User\…` | Secrets are now stored in `safeStorage` (DPAPI/Keychain), but extension-stored tokens often land in plaintext under `globalStorage/<extension-id>/`. GitHub Copilot specifically: `~/.config/github-copilot/hosts.json` (plaintext OAuth token, `ghu_` prefix) and `~/.config/github-copilot/apps.json`. Cursor: macOS Keychain item `cursor-access-token` (auto-unlocked from user context). |
| JetBrains IDEs (IntelliJ, PyCharm, WebStorm, GoLand, Rider, RubyMine, CLion, PhpStorm, Android Studio, DataGrip) | `~/Library/Application Support/JetBrains/<Product><Ver>/options/c.kdbx` (KeePass backend) — only used when "In KeePass" is selected; default uses native keychain | `%APPDATA%\JetBrains\<Product><Ver>\options\c.kdbx` + `pdb.pwd` | When KeePass backend is in use, recover via `JetDecrypt`. When native backend is used (default on macOS/Windows), creds are in the OS keychain and accessible per the keychain rules above. Prior to 2025.3 some passwords were stored on the IDE backend in plain text (per JetBrains documentation). |

**The Electron `safeStorage` percentage:** per Electron's own documentation, on Linux without a Secret Service backend `safeStorage` falls back to a hardcoded plaintext password (`getSelectedStorageBackend() == "basic_text"`) — meaning the "encryption" is cosmetic. On Windows it uses DPAPI, which is decryptable from the same user. On macOS it uses the login keychain. Empirically **adoption is patchy**: Signal only migrated to it in 2024 after years of plaintext `config.json`; Discord, many smaller apps, and most older Electron apps still rely on plaintext leveldb for non-cookie secrets. Treat any Electron `Local Storage/leveldb` directory as in-scope, plaintext, and worth grepping.

---

## D) IDE / Developer-Tool Token Caches

The pattern: **`~/.<tool>/credentials*` or `~/.config/<tool>/`** dotdir, almost always JSON/TOML/YAML, almost always plaintext, almost always in scope.

| Tool | Path(s) | Format | Notes |
|---|---|---|---|
| GitHub CLI (`gh`) | `~/.config/gh/hosts.yml` (macOS/Linux); `%APPDATA%\GitHub CLI\hosts.yml` (Windows) | YAML with `oauth_token: ghp_…` or `ghu_…` plaintext | Falls back to plaintext even with `--insecure-storage` not specified if no keyring is configured (issue #7757). |
| GitHub Copilot | `~/.config/github-copilot/hosts.json`, `~/.config/github-copilot/apps.json` | JSON, `oauth_token` plaintext (`ghu_` prefix) | Used by VS Code, Neovim, JetBrains (proxied), Vim. |
| npm / Yarn classic | `~/.npmrc`, `./.npmrc` | INI; `//registry.npmjs.org/:_authToken=npm_…` | Already covered in skill; ensure pattern catches scoped registries (`@org:registry=…\n//org.example.com/:_authToken=…`). |
| pnpm | `<pnpm-config>/auth.ini`, falls back to `~/.npmrc` | INI | Same token format. |
| Cargo (Rust) | `~/.cargo/credentials.toml` | TOML; `[registry] token = "…"` | Plaintext. |
| Maven | `~/.m2/settings.xml` | XML; `<server><username>…</username><password>…</password>` (often plaintext; can be Maven-encrypted with `~/.m2/settings-security.xml` master) | The encryption is reversible offline given both files. |
| Gradle | `~/.gradle/gradle.properties` and per-project `gradle.properties` | Java-properties; embedded `*Token`, `*ApiKey`, `*Password` | Frequently committed accidentally. |
| pip / Python | `~/.pip/pip.conf`, `~/.config/pip/pip.conf`, `%APPDATA%\pip\pip.ini`; PyPI token via `~/.pypirc` | INI; `index-url = https://__token__:pypi-…@upload.pypi.org/legacy/` | `pypi-AgEIc…` prefix is a hard signal. |
| Ruby gems | `~/.gem/credentials` (mode 0600) | YAML; `:rubygems_api_key: …` | Plaintext. |
| JFrog / Artifactory CLI | `~/.jfrog/jfrog-cli.conf.v6` | JSON | Plaintext access tokens. |
| Heroku CLI | `~/.netrc` (`api.heroku.com` + `git.heroku.com` machines) and `~/.heroku/` | netrc | Lifetime-bound API tokens. |
| Vercel CLI | macOS: `~/Library/Application Support/com.vercel.cli/auth.json`; Linux: `~/.local/share/com.vercel.cli/auth.json`; Windows: `%LOCALAPPDATA%\com.vercel.cli\auth.json` | JSON; `{"token":"…"}` | Plaintext. |
| Netlify CLI | `~/.config/netlify/config.json` (and `~/.netlify/`) | JSON; `users.{id}.auth.token` | Plaintext. |
| Supabase CLI | `~/.supabase/access-token` | text | Plaintext. |
| Railway CLI | `~/.railway/config.json` | JSON | Plaintext. |
| Firebase CLI | `~/.config/configstore/firebase-tools.json` (per `firebase login`); plus reuse of `~/.config/gcloud/application_default_credentials.json` | JSON | Refresh token + client secret; reusable from any machine. |
| Snyk CLI | `~/.config/configstore/snyk.json` | JSON; `api` token | Plaintext. |
| Datadog CLI | `~/.dogrc`, `~/.datadog.yaml` (`datadog-ci`); also `DD_API_KEY` env | YAML/INI | Plaintext. |
| Sentry CLI | `~/.sentryclirc` | INI; `[auth] token=…` | Plaintext. |
| PagerDuty / Splunk / Honeycomb / New Relic / Logz.io CLIs | various; usually `~/.<tool>/config` or `~/.config/<tool>/` | YAML/JSON | Plaintext API keys. |
| Anthropic Claude Code | `~/.claude/.credentials.json` (Linux containers); on macOS uses macOS Keychain (`Claude Code-credentials` service), so the JSON file is absent on bare-metal Macs. CI tokens via `CLAUDE_CODE_OAUTH_TOKEN` env. | JSON / Keychain item | Keychain item is in login keychain, auto-unlocked, in scope. |
| OpenAI Codex CLI / `openai` CLI | `~/.openai/auth.json` or `OPENAI_API_KEY` env | JSON | Plaintext. |
| Cursor CLI | macOS Keychain `cursor-access-token` service | Keychain | In scope on macOS (login keychain). |
| Zed AI | `~/.config/zed/` and macOS Keychain `Zed Account Credentials` | Keychain | In scope. |

**Generalized detection rule:** for any subdirectory of `~` whose name starts with `.` *or* is under `~/.config`, list `*.json`, `*.toml`, `*.yaml`, `*.yml`, `*.ini`, `*.conf`, `credentials*`, `auth*`, `token*`, `*.netrc`. Read the first ~64 KB and run the regex panel below over it.

---

## E) Cloud SSO and Identity Artifacts

### E.1 AWS SSO Cache (`~/.aws/sso/cache/`)

JSON files with `accessToken` and `refreshToken` for SSO sessions. Already in skill — confirm the path also covers `~/.aws/cli/cache/` (assume-role cache) and the WSL passthrough on Windows (see §I).

### E.2 aws-vault Backends

aws-vault stores root IAM credentials in a vault backend chosen by `--backend`/`AWS_VAULT_BACKEND`:

- **macOS keychain backend (default):** named keychain at `~/Library/Keychains/aws-vault.keychain-db`. Items are *generic password* items in this dedicated keychain. By default the keychain is locked separately from the login keychain and prompts on first access — **out of scope for silent extraction**. However, users frequently set `security set-keychain-settings -t 28800 ~/Library/Keychains/aws-vault.keychain-db` and "Always Allow" the binary, after which it becomes silently readable from any process the user runs.
- **`file` backend:** `~/.awsvault/keys/` — encrypted file with passphrase prompt. Out of scope.
- **`pass` backend:** `~/.password-store/aws-vault/` — gpg-encrypted. Passphrase prompt, out of scope.
- **Windows credential manager backend:** items under "Generic Credentials"; DPAPI-protected, **in scope**.
- **`secret-service`/KWallet backends (Linux):** prompt on locked wallet; in scope when wallet auto-unlocks at login.
- **Detection signal:** existence of `aws-vault.keychain-db` or `~/.awsvault/` is a strong "this user is doing AWS the right way" hint and means real long-lived IAM creds are likely in the keychain.

### E.3 Kubernetes exec-credential Plugins

- `aws-iam-authenticator` cache: `~/.kube/cache/aws-iam-authenticator/credentials.yaml` (token cache).
- `gke-gcloud-auth-plugin` cache: `~/.kube/cache/gke-gcloud-auth-plugin/`.
- `aws eks get-token` cache embedded in kubeconfig.
- **`kubeconfig` `client-certificate-data` and `client-key-data`:** base64-encoded long-lived X.509 client certs and keys — frequently 1–10 year validity. Reading the kubeconfig (already in skill) yields cluster-admin in many setups.

### E.4 Okta / Duo / Microsoft / Google Persistent State

- **Okta Verify (macOS):** `~/Library/Group Containers/B7F62B65BN.com.okta.mobile/` — secure enclave-bound, out of scope.
- **Duo Mobile:** keychain-backed, biometric-gated typically — out of scope.
- **Azure CLI:** `~/.azure/msal_token_cache.bin` (encrypted on Windows via DPAPI, **plaintext JSON on macOS and Linux** per Microsoft's own documentation). `~/.azure/azureProfile.json` lists subscriptions. Legacy `accessTokens.json` (pre-2.30.0) was always plaintext; if found on a machine that hasn't run `az logout`, contains live refresh tokens. Microsoft confirms on macOS/Linux the MSAL cache is plaintext on disk.
- **Azure PowerShell:** `~/.Azure/AzureRmContext.json`, `~/.Azure/TokenCache.dat`.
- **GCP gcloud:** `~/.config/gcloud/credentials.db` (SQLite) and `~/.config/gcloud/access_tokens.db`, plus `~/.config/gcloud/application_default_credentials.json` (already in skill). All plaintext.
- **AWS CLI `credential_process`:** `~/.aws/config` lines like `credential_process = /path/to/script` are not credentials themselves but reveal where to fetch them — and the script frequently lives in a path the user can read.

### E.5 Long-Lived Cert Material in kubeconfig

Many EKS/GKE/AKS-adjacent kubeconfigs contain inline `client-certificate-data` (base64 PEM). These are functionally permanent until cluster CA rotation. The skill should flag any kubeconfig with non-zero `client-certificate-data` length as critical-severity.

---

## F) Mobile / Messaging / Productivity App Credentials

### F.1 macOS Messages (`chat.db`)

`~/Library/Messages/chat.db` — SQLite, plaintext SMS/iMessage including 2FA codes. Reading triggers the **Full Disk Access TCC prompt** on macOS Mojave+ from a non-FDA process — but: (a) Terminal.app and many shells are commonly granted FDA by users, in which case any child process inherits that; (b) the file is owned by the user and `chmod 0644`-readable by the user under the home directory, so the *file-system permission* check is open — only TCC blocks unprivileged callers. Treat as *conditionally in scope*: the skill should attempt and gracefully detect TCC denial, not assume.

### F.2 Telegram Desktop tdata

- macOS: `~/Library/Application Support/Telegram Desktop/tdata/`
- Windows: `%APPDATA%\Telegram Desktop\tdata\`
- Linux: `~/.local/share/TelegramDesktop/tdata/`

The tdata folder contains `key_*` and `D877F783D5D3EF8C/map*` files. With **no local passcode** set (the default), the directory can be **copied verbatim and dropped into another Telegram Desktop instance to fully impersonate the user — bypassing 2FA and SMS entirely**. This is the single most-targeted artifact in commodity Windows stealers (PupkinStealer, every Russian-speaking variant). When a passcode is set, the keys are encrypted with PBKDF2-SHA512 (100k rounds) but offline-crackable; tools like `tdesktop-decrypter` automate it. **In scope.**

### F.3 Signal Desktop

- macOS: `~/Library/Application Support/Signal/config.json` + `~/Library/Application Support/Signal/sql/db.sqlite`
- Windows: `%APPDATA%\Signal\config.json` + `%APPDATA%\Signal\sql\db.sqlite`
- Linux: `~/.config/Signal/config.json` + `~/.config/Signal/sql/db.sqlite`

**Historic state (pre-Sept 2024):** `config.json` contained the SQLCipher database key in plaintext as the `key` field. Anyone with file-system read could trivially decrypt all messages, attachments, and the registration credentials. **Current state (Sept 2024+):** Signal migrated to Electron `safeStorage`, so `config.json` now contains an `encryptedKey` (base64 DPAPI/Keychain blob) and a `safeStorageBackend` field. On Windows this is DPAPI-protected to the user — still recoverable from user context. On macOS the Keychain item "Signal Safe Storage" is in the login keychain (auto-unlocked, item-ACL gated; Signal's binary is the original creator so it doesn't prompt itself, but a third-party reader will trigger a "wants to access" prompt → out of scope unless the item ACL has been weakened). On Linux without GNOME Keyring/KWallet, the safeStorage falls to `basic_text` and is functionally plaintext. **Skill handling:** record the `safeStorageBackend` value; if `basic_text` flag as recoverable, otherwise mark "key sealed by OS — DB encrypted at rest".

### F.4 WhatsApp Desktop

`~/Library/Group Containers/group.net.whatsapp.WhatsApp.shared/`. Multi-device session uses a Curve25519 noise key sealed with the OS keychain; the local DB (`Documents/`) is SQLCipher-encrypted. The session-replay attack model that worked on Telegram is partially mitigated by per-device protocol — but the *contact database* and recent media are often readable. Out of scope for full session takeover; in scope for content reconnaissance.

### F.5 Outlook / Apple Mail data stores

- Apple Mail: `~/Library/Mail/V<N>/MailData/Accounts.plist` lists IMAP/SMTP servers and usernames; passwords are in the keychain (item ACL typically permits Mail.app; from another binary triggers a prompt). The local mail content (`*.mbox`) is plaintext and contains every received 2FA code and password reset email — high-value but not in the "credential" sense.
- Outlook (legacy macOS): `~/Library/Group Containers/UBF8T346G9.Office/Outlook/Outlook 15 Profiles/<Profile>/Data/`.
- Outlook (Windows): `%LOCALAPPDATA%\Microsoft\Outlook\*.ost` and `*.pst`. Saved server passwords are DPAPI-protected to the user — in scope. PST files themselves can have a password but its check is client-side and offline-removable (ancient `pst19upg` family of tools).

---

## G) Crypto Wallet Files

In scope for *full coverage of stealer behavior*; less directly relevant to SaaS-startup risk but unavoidable since the stealer families' first-class targets are wallets.

| Wallet | Path | Notes |
|---|---|---|
| MetaMask (Chrome ext) | `<Chromium profile>/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/` (LevelDB) | Plaintext leveldb with password-encrypted vault; offline brute-forceable. AMOS specifically calls out "brute-force MetaMask seeds and private keys". |
| Phantom (Solana) | `…/bfnaelmomeimhlpmgjnjophhpkkoljpa/` | Same pattern. |
| Coinbase Wallet ext | `…/hnfanknocfeofbddgcijnmhnfnkdnaad/` | Same. |
| Trust, TronLink, Binance, Rabby, Keplr, OKX, Solflare, Sui, Ronin, etc. | each has a known extension ID; Torg Grabber targets 728 of them | Stealers ship a hardcoded list. |
| Exodus | macOS: `~/Library/Application Support/exodus.wallet/`; Windows: `%APPDATA%\Exodus\` | Encrypted seed file; offline crackable. |
| Electrum | macOS: `~/Library/Application Support/Electrum/wallets/`; Windows: `%APPDATA%\Electrum\wallets\` | Per-wallet password; offline crackable. |
| Atomic Wallet | `~/Library/Application Support/atomic/Local Storage/leveldb/` | leveldb. |
| Ledger Live | `~/Library/Application Support/Ledger Live/` | Companion app data; HW key not on disk but app metadata is. AMOS also reportedly trojanizes Ledger Live in some campaigns (Odyssey). |
| `wallet.dat` (Bitcoin Core, etc.) | `~/Library/Application Support/Bitcoin/wallets/` and similar | Generic name pattern across many forks. |

**Detection regex (filename):** `(?i)(wallet|metamask|phantom|exodus|electrum|atomic|trezor|ledger|keystore|seed|mnemonic).*\.(dat|json|wallet|key|keystore|txt)$` plus the BIP-39 wordlist signature inside files.

---

## H) Infostealer Targeting Behavior 2024–2026

### H.1 macOS — the Atomic family and its forks

**AMOS (Atomic macOS Stealer)** — first observed April 2023, 90% of new macOS malware in 2024 by SentinelOne / Jamf telemetry. By Aug 2025 Jamf+MacPaw recorded "tens of thousands of detections in August 2025 alone." Targets per Trend Micro's Sept 2025 MDR analysis and Huntress's Dec 2025 ChatGPT-poisoning campaign:

- macOS Keychain (full dump via osascript-prompted password phishing — *that* step is out of scope for the skill but the post-extraction artifacts are not).
- Browser data (Chrome/Firefox/Edge/Brave/Safari cookies, autofill, Login Data) for 7+ Chromium variants.
- Crypto wallets: Electrum, Exodus, MetaMask, Ledger Live, Coinbase Wallet, Atomic, Wasabi, Coinomi, Guarda, Trezor PM (~50 desktop wallets + 100s of extensions).
- Apple Notes (`~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`).
- Telegram Desktop tdata.
- OpenVPN profiles (`*.ovpn`), FortiVPN configs.
- File-system grab in Desktop/Documents/Downloads with extensions `.txt .pdf .docx .json .db .wallet .key .keys .doc .jpeg .png` up to ~210 MB total (Poseidon limit).
- KeePass `.kdbx` files and password manager exports.
- Compresses to `/tmp/<random>/out.zip` and POSTs to C2.

**Banshee Stealer** — 2024 paid MaaS ($3000/mo); source leaked Nov 2024 spawning many forks. Per Elastic Security Labs, Check Point, Foresiet, and DeceptIQ: 9 browsers, ~100 extensions, the `Authenticator.cc` 2FA extension specifically, `Wasabi/Exodus/Ledger`, AppleScript fake password prompts, `osascript` prompt for system password to dump keychain. The Chrome Safe Storage keychain entry is its specific value-add target (it's the AES key needed to decrypt the Login Data SQLite offline once they have the system password from the prompt).

**Cthulhu Stealer (Cado/Darktrace 2024 analysis):** Go-based, $500/mo MaaS; uses `Chainbreak` to dump keychain to `/Users/Shared/NW/Keychain.txt`; specifically prompts for MetaMask password as a secondary phish; targets game accounts (Minecraft, Battle.net) on top of the AMOS list.

**Poseidon / Rodrigo Stealer / Odyssey** (Unit 42, eSentire, SentinelOne, Wizard Cyber): ostensibly adds Fortinet/OpenVPN config theft; Odyssey adds LaunchDaemon persistence and SOCKS5 proxy deployment; trojanized Ledger Live distribution.

**Common macOS harvest path list (the union):**

```
~/Library/Application Support/{Google/Chrome,BraveSoftware/Brave-Browser,Microsoft Edge,Firefox,Opera Software/Opera Stable,Vivaldi,Yandex,Arc}
~/Library/Application Support/{Telegram Desktop,Discord,Slack,Signal,WhatsApp,Element,Atomic,Exodus,Electrum,Ledger Live}
~/Library/Group Containers/group.com.apple.notes/
~/Library/Keychains/login.keychain-db (extracted via osascript-phished password)
~/Library/Cookies/
~/Desktop, ~/Documents, ~/Downloads (filtered by extension and ~200MB cap)
~/.ssh/, ~/.aws/, ~/.gcloud/, ~/.config/gcloud/, ~/.kube/
~/.zsh_history, ~/.bash_history, ~/.python_history, ~/.psql_history
```

### H.2 Windows — Lumma / StealC / Vidar / RedLine / Rhadamanthys / Acreed / Void / Torg

**LummaC2** — dominant 2024–mid-2025; Microsoft+Europol takedown of 2,300+ C2 domains in May 2025; the operators rebuilt; doxxed Aug–Oct 2025; lineage continues as **Remus** in early 2026 with the same ABE bypass shellcode. Target list per SpyCloud, Red Canary, Elastic Security Labs ("Katz and Mouse"), GBHackers Remus analysis, Recorded Future 2025 report:

- Chrome/Edge/Brave/Vivaldi/Opera/Firefox: passwords, cookies, autofill, history, **including ABE-protected cookies via shellcode that resolves `os_crypt_async::Encryptor` vtable + `CryptUnprotectMemory`**.
- 100+ wallet extensions; 15+ desktop wallets.
- Telegram tdata, Discord tokens.
- VPN configs (NordVPN, ProtonVPN, OpenVPN).
- FTP clients (FileZilla, WinSCP).
- Email (Thunderbird, Outlook).
- Steam, Battle.net.
- File grabber: documents, `.kdbx`, `.txt` matching `password|secret|wallet|seed|backup` filters, max ~50–200 MB.
- AnyDesk creds, RDP saved creds via DPAPI.

**StealC v2** (Zscaler ThreatLabz, Picus, Morphisec, SOCRadar): MaaS at $200/mo; v2.2.4 as of Nov 2025; 23+ browsers, 100+ extensions, 15+ desktop wallets, Telegram/Discord/Tox/Pidgin, ProtonVPN/OpenVPN, Thunderbird; **server-side credential decryption** (the stealer ships encrypted browser DBs back to the C2 and the panel decrypts) which makes endpoint detection harder; Sophos's Dec 2025 report tied StealC v2 to Qilin ransomware deployments via stolen Fortinet VPN creds.

**Vidar / RedLine / Raccoon:** browser passwords/cookies/autofill, wallets, FTP, email, Steam, Discord; classic; RedLine/Meta law-enforcement-disrupted late 2024.

**Rhadamanthys / Meduza / Phemedrone / WhiteSnake / Lumar / Acreed:** all implement Chrome ABE bypass; broadly equivalent target list.

**Void / VoidStealer (BlackFog, SOCRadar, Kaspersky 2025):** added syscall-level EDR bypass and a novel ABE bypass via reflective DLL injection accessing the IElevator COM interface.

**Torg Grabber (Gen Digital/Bleeping Computer, Mar 2026):** 25 Chromium browsers, 8 Firefox variants, **850 browser extensions including 728 crypto wallets, 103 password managers/2FA extensions** (LastPass, 1Password, Bitwarden, KeePass, NordPass, Dashlane, ProtonPass, Enpass, Psono, Akamai MFA, GAuth, TOTP Authenticator, etc.), 19 note-taking apps. December 2025 added ABE bypass.

**Sryxen (DeceptIQ 2025–26):** uses Chrome DevTools Protocol to ask Chrome to decrypt its own cookies (no key extraction needed).

**Chihuahua Stealer (G DATA May 2025):** .NET, AES-GCM exfiltration, multi-stage PowerShell loader, scheduled task persistence.

**Common Windows harvest list (union):**

```
%LOCALAPPDATA%\{Google\Chrome,Microsoft\Edge,BraveSoftware\Brave-Browser,Vivaldi,Yandex\YandexBrowser,Opera Software\Opera Stable}\User Data\<Profile>\{Login Data,Cookies,Web Data,History,Local State,Network\Cookies}
%APPDATA%\Mozilla\Firefox\Profiles\*\{logins.json,key4.db,cookies.sqlite}
%APPDATA%\{Telegram Desktop\tdata,Discord\Local Storage\leveldb,Signal\config.json,Slack}
%APPDATA%\{Thunderbird\Profiles,FileZilla\sitemanager.xml,Bitcoin\wallets,Electrum,Ethereum}
%LOCALAPPDATA%\Microsoft\Credentials\, %APPDATA%\Microsoft\Credentials\
%LOCALAPPDATA%\Microsoft\Vault\, %APPDATA%\Microsoft\Vault\
%APPDATA%\Microsoft\Protect\<SID>\ (DPAPI master keys)
HKCU\Software\Microsoft\Terminal Server Client\Servers (RDP saved hosts)
HKCU\Software\Martin Prikryl\WinSCP 2\Sessions (encrypted with reversible XOR)
HKCU\Software\SimonTatham\PuTTY\Sessions and \SshHostKeys
%USERPROFILE%\.aws\, .kube\, .gcloud\, .azure\, .ssh\
%USERPROFILE%\.config\github-copilot\, .config\gh\
Shell history: %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### H.3 Emerging categories the skill should add

- **AI tool tokens** (Claude Code, OpenAI/Codex, Cursor, Windsurf, GitHub Copilot, Gemini CLI). Already showing up in Torg Grabber's note-taking apps category and in the OpenClaw "skill"-poisoning AMOS variant from Trend Micro Feb 2026.
- **MCP server config files** (`~/.cursor/mcp.json`, `.mcp.json`, `claude_desktop_config.json` at `~/Library/Application Support/Claude/`) — these increasingly contain bearer tokens for downstream APIs in the `env` field.
- **Container/dev-container secrets** (Cursor Cloud Agents, GitHub Codespaces, devpod, Coder) — `~/.codespaces/`, `.devcontainer/devcontainer.env`.
- **Browser session for AI services** (chat.openai.com, claude.ai, perplexity.ai cookies) — these often include long-lived session cookies that bypass MFA.

---

## I) Windows-Specific Artifacts

The skill is currently macOS/Linux-leaning; this is the Windows extension.

### I.1 DPAPI Blobs Decryptable Silently as the Current User

DPAPI (`CryptProtectData`/`CryptUnprotectData`) is the single most-important Windows credential primitive. From the user's logged-in process context, decryption is **silent and synchronous** — no UI, no prompt. The user's master keys live in `%APPDATA%\Microsoft\Protect\<SID>\<GUID>` and are unlocked at logon using a key derived from the user's password (or, on AD-joined hosts, the domain controller's backup key).

**Locations of DPAPI-encrypted user secrets:**

- `%APPDATA%\Microsoft\Credentials\` and `%LOCALAPPDATA%\Microsoft\Credentials\` — Credential Manager generic credentials (RDP saved passwords, SMB share creds, third-party apps that use `CredWrite`).
- `%APPDATA%\Microsoft\Vault\` and `%LOCALAPPDATA%\Microsoft\Vault\` — IE/Edge Web Credentials and Windows Vault.
- `%LOCALAPPDATA%\Google\Chrome\User Data\Local State` — Chrome's `os_crypt.encrypted_key` (pre-127, or the legacy fallback).
- `%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State` — same.
- `%APPDATA%\Microsoft\Outlook\` — saved IMAP/SMTP passwords.
- `%LOCALAPPDATA%\Microsoft\OneDrive\settings\` — refresh tokens.
- `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\` — Firefox's NSS DB encryption (only DPAPI-derived if no master password).
- `%APPDATA%\WinSCP\` or registry — WinSCP saved sessions (passwords stored with a *known reversible XOR* keyed on hostname+username, not DPAPI — *trivially* recoverable; tools like `winscppasswd` reverse it without the user's password).
- `HKCU\Software\SimonTatham\PuTTY\Sessions\<name>` — saved PuTTY profiles. PuTTY itself does not save passwords; Pageant private keys are in memory only.
- `HKCU\Software\RealVNC\` and similar VNC client password registry (DES-encrypted with a **fixed published key** — recoverable trivially).

**Tooling reality:** `mimikatz dpapi::cred /in:<file>` + `sekurlsa::dpapi` (or `/rpc` for domain) automates this; SharpDPAPI does the same in C# without a driver; both run cleanly from in-user-context with no UI prompt. **In scope.**

### I.2 Windows Credential Manager UI vs. Programmatic Access

The Credential Manager Control Panel UI shows masked passwords until the user re-enters their Windows password — that re-entry is a UX gate, *not* a security boundary. `CredEnumerate` + `CredRead` from the same user session returns plaintext (DPAPI-decrypted) without any prompt. Mark entire `Credentials\` directories as in-scope.

### I.3 Windows Hello / TPM-Bound

Items stored via the **Microsoft Passport / Windows Hello for Business** APIs (TPM key wrapping with biometric/PIN gesture) **do** prompt and **are out of scope**. Specifically: WHfB credentials, FIDO2 keys, modern MS Account "Web Account Manager" tokens used by new Outlook, new Teams. The skill should detect their *existence* (`%LOCALAPPDATA%\Packages\Microsoft.AAD.BrokerPlugin_*`) but not attempt extraction.

### I.4 WSL Credential Leakage

The host Windows user has full file-system access to every WSL distro under `\\wsl$\<DistroName>\` (or `%LOCALAPPDATA%\Packages\<DistroPackage>\LocalState\rootfs\`). This means **every Linux dotfile credential discussed in this report is also reachable from the Windows host without entering the WSL shell**: `\\wsl$\Ubuntu\home\alice\.aws\credentials`, `\\wsl$\Ubuntu\home\alice\.ssh\id_ed25519`, `\\wsl$\Ubuntu\home\alice\.config\gh\hosts.yml`, etc. Skill addition: enumerate WSL distros via `wsl -l` and walk each rootfs.

### I.5 PowerShell History

`%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` — the per-user PowerShell history; persists indefinitely, includes pasted secrets, `Set-AzContext -Token …`, `aws configure --profile`, etc. Also `Microsoft.PowerShell_profile.ps1` may contain `$env:GITHUB_TOKEN = "…"` style hard-coded variables.

### I.6 RDP Saved Credentials

- `.rdp` files in `%USERPROFILE%\Documents\` (filename `Default.rdp` by default) — they encode hostname/username but **not** the password directly. The password is stored in Credential Manager keyed by `TERMSRV/<hostname>` and decrypted via DPAPI from user context. Recoverable: yes (`mimikatz dpapi::cred`).
- `cmdkey /list | findstr target=TERMSRV` enumerates them without admin.
- Tools like RdpThief / SharpRDPThief hook `mstsc.exe` to capture creds in real time, but for the skill the offline recovery from Credential Manager is sufficient.

### I.7 PuTTY / Pageant / WinSCP / FileZilla

- **PuTTY:** `HKCU\Software\SimonTatham\PuTTY\Sessions\*` and `\SshHostKeys`. No saved passwords (good); but `*.ppk` private keys saved to `~\Documents\` are common.
- **Pageant:** keys live in memory only; not on disk.
- **WinSCP:** `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions` or, when configured for INI storage, `WinSCP.ini` in install dir. **Passwords are stored with a hostname-keyed reversible obfuscation** (not DPAPI, not crypto) — every WinSCP password recovery tool on GitHub reproduces this in <100 lines. **In scope, trivially.**
- **FileZilla:** `%APPDATA%\FileZilla\sitemanager.xml`, `recentservers.xml`, `filezilla.xml`. **Passwords stored either as base64 plaintext or, if "Save passwords with master password" is enabled, AES-encrypted with the user-supplied master password.** Without master password (default): plaintext. **In scope.**

### I.8 .git-credential-manager Stores

- `%LOCALAPPDATA%\GitCredentialManager\store\` (when `credential.helper = manager` is set with file-store backend) or DPAPI-stored credentials when default backend.
- Plaintext credentials at `~/.gcm/store/git/https/<host>/<user>.credential` if user chose plaintext backend.

### I.9 Recycle Bin

`C:\$Recycle.Bin\<SID>\` may contain "deleted" credential files (`.env`, `.pem`, KeePass exports). Recovery is trivial via the standard Windows API. Skill should walk the Recycle Bin.

### I.10 PST/OST Stored Passwords

Outlook's saved IMAP/SMTP server passwords live in DPAPI'd registry entries under `HKCU\Software\Microsoft\Office\<ver>\Outlook\Profiles\<profile>\<encoded-account-id>`. Recoverable from user context.

---

## J) "Credential-Adjacent" Artifacts That Give Equivalent Power

These are not credentials per se but compromise the same accounts:

- **Time Machine backups** mounted at `/Volumes/<TM disk>/Backups.backupdb/<host>/` — contain entire historical filesystem trees including past `.env`, prior keychain databases, etc. Reading is in scope when the volume is mounted.
- **`.tar.gz`/`.zip` of home dir in Downloads** — `(?i)(home|backup|laptop|workstation).*\.(tar\.gz|tgz|zip|7z|dmg)$` is a high-signal pattern.
- **Cloud-storage local syncs** (Dropbox `~/Library/CloudStorage/Dropbox*/`, Google Drive `~/Library/CloudStorage/GoogleDrive-*`, OneDrive `~/Library/CloudStorage/OneDrive*/`, iCloud Drive `~/Library/Mobile Documents/com~apple~CloudDocs/`) — frequently a **second location** for KeePass `.kdbx`, 1Password Emergency Kit PDFs, `.env` backups, SSH private keys "for backup", Bitwarden exports. The skill should treat these as additional roots to walk with the Downloads heuristics.
- **Notes apps with plaintext credentials:**
  - Apple Notes: `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` — plaintext SQLite (TCC-gated for FDA on Mojave+; same caveat as Messages).
  - Notion local cache.
  - Obsidian vaults — markdown files; `.obsidian/workspace.json`. Encryption only via plugins (`meld-encrypt`, `cryptsidian`); default vaults are plaintext markdown.
  - Bear, Joplin, Standard Notes (encrypted), Logseq (plaintext), Reflect, Mem.
- **Email clients with cached passwords** — Thunderbird `logins.json` + `key4.db` (same NSS pattern as Firefox).
- **Filename-pattern sweep** in Downloads/Desktop/iCloud/Dropbox/OneDrive/Documents:

  ```
  (?i)(creds?|credentials?|password|passwd|secret|api[_-]?key|token|auth|access[_-]?key|emergency|recovery|backup|export|vault|wallet|seed|mnemonic|private[_-]?key)
  \.(txt|md|csv|json|xlsx?|docx?|pdf|rtf|html?|kdbx|1pif|kdb|key|pem|p12|pfx|jks|ppk)$
  ```

  Combine with image filenames (`*.png`, `*.jpg`, `*.heic`) — many users *photograph* their MFA recovery codes and store them in Photos sync; `ocrmypdf` or Apple's own Vision Framework will pull text out, but that's beyond scope. Filename match alone is an acceptable signal.

---

## K) Unifying Patterns (the most important section)

Rather than maintaining a 1,000-line tool table, the skill should compose seven generalized detectors. Each is a discovery rule + a content-classification rule.

### Pattern 1 — "CLI Tool Dotdir"

> *Any directory of the form `~/.{name}/`, `~/.config/{name}/`, `~/Library/Application Support/{name}/`, `%APPDATA%\{Name}\`, `%LOCALAPPDATA%\{Name}\` whose immediate children include any of the names `credentials`, `credential`, `auth`, `auth.json`, `token`, `tokens`, `access_token`, `refresh_token`, `session`, `config.json`, `config.toml`, `config.yaml`, `config.yml`, `settings.json`, `*.netrc`, `hosts.yml`, `hosts.json` is a candidate.*

For each candidate, read up to ~256 KB and run the regex panel (Pattern 7). This rule alone covers gh, gcloud, aws, azure, vercel, netlify, supabase, railway, firebase, snyk, sentry, datadog, pagerduty, splunk, honeycomb, claude, codex, openai, heroku, jfrog, npm, yarn, pnpm, cargo, gem, pypi, kubectl, helm, terraform, pulumi, nx, turbo, doctl, linode-cli, fly, render, scaleway, hetzner, cloudflared, ngrok, tailscale, 1Password CLI, gh, glab, hub, tea, lab, nektos act, and dozens of others **without naming them**.

### Pattern 2 — "Electron Session Vault"

> *Any directory containing both `Local Storage/leveldb/` and `Cookies` (SQLite) where the parent directory matches `Application Support/<app>/` (macOS) or `%APPDATA%\<app>\` / `%LOCALAPPDATA%\<app>\User Data\` (Windows) is a candidate.*

For each candidate, attempt to grep the leveldb files for the regex panel; for `Cookies`, parse the SQLite and emit (host, name, encrypted_value_present) triples. This covers Slack, Discord, Notion, Linear, Figma, ClickUp, Asana, Zoom, Postman, Insomnia, Microsoft Teams (classic), Signal, Element, Mattermost, Rocket.Chat, Bluesky, plus arbitrary new Electron apps without naming them.

### Pattern 3 — "Vault/Export File"

> *Any file matching `(?i).*\.(kdbx|kdb|1pif|1pux|opvault|aegis|enpass|csv|json|tsv|xml).*` whose path is in `Downloads`, `Desktop`, `Documents`, `iCloud Drive`, `Dropbox`, `OneDrive`, `Google Drive`, or whose filename matches `(?i)(emergency.?kit|recovery|backup|export|vault|secret|password.?list|cred|api.?key|wallet|seed)`.*

This catches all password-manager exports and KeePass databases without naming Bitwarden / 1Password / LastPass / KeePass / KeePassXC / RoboForm / Enpass / Aegis individually.

### Pattern 4 — "Private Key Sweep"

> *Files matching `id_(rsa|ed25519|ecdsa|dsa|xmss)$|^id_[a-z0-9_]+$|.*\.(pem|key|p12|pfx|jks|ppk|p8|pri)$|^(ssh-keys?|server-keys?|bastion|prod|production|deploy|cicd).*\.(pem|key)$` outside of `~/.ssh/` (which is already in skill).*

Particularly Downloads, Desktop, Documents, repo `infra/`, `terraform/`, `ansible/`, `helm/`, `secrets/` subtrees. PEM files start with the literal `-----BEGIN ` — that's the cheapest content fingerprint.

### Pattern 5 — "Embedded Token in Free-Form Text"

> *Any plaintext file (`*.env*`, `*.sh`, `*.zsh`, `*.bash`, `*.fish`, `*.ps1`, `*.psm1`, `*.txt`, `*.md`, `*.yml`, `*.yaml`, `*.toml`, `*.json`, `*.ini`, `*.conf`, `*.properties`, `*.gradle`, `*.tf`, `*.tfvars`, `*_history`) containing a known token-prefix.*

The minimum-viable token-prefix regex panel (compile from gitleaks `config/gitleaks.toml` and trufflehog detectors):

```
(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,255}        # GitHub
glpat-[A-Za-z0-9_-]{20,}                                       # GitLab
xox[baprs]-(?:[A-Za-z0-9-]+-){2,4}[A-Za-z0-9]{24,}             # Slack token
xapp-1-[A-Z0-9]+-[0-9]+-[a-z0-9]+                              # Slack app
xoxc-[A-Za-z0-9-]+                                             # Slack browser cookie token
sk-ant-(?:api03|admin)-[A-Za-z0-9_-]{80,}                      # Anthropic
sk-proj-[A-Za-z0-9_-]{40,}                                     # OpenAI project
sk-[A-Za-z0-9]{20,}                                            # OpenAI legacy
hf_[A-Za-z0-9]{30,}                                            # HuggingFace
nvapi-[A-Za-z0-9_-]{40,}                                       # NVIDIA
gsk_[A-Za-z0-9]{40,}                                           # Groq
AKIA[0-9A-Z]{16}                                               # AWS access key
ASIA[0-9A-Z]{16}                                               # AWS STS
AGPA[0-9A-Z]{16}                                               # AWS group
AIDA[0-9A-Z]{16}                                               # AWS user
[A-Za-z0-9/+=]{40}                                             # AWS secret (entropy-gated, near AWS keyword)
AIza[0-9A-Za-z_-]{35}                                          # Google API
ya29\.[0-9A-Za-z_-]+                                           # Google OAuth
1//0[A-Za-z0-9_-]{40,}                                         # Google refresh
dop_v1_[a-f0-9]{64}                                            # DigitalOcean PAT
shpat_[a-f0-9]{32}                                             # Shopify PAT
shpss_[a-f0-9]{32}                                             # Shopify shared secret
sk_live_[A-Za-z0-9]{24,}|sk_test_[A-Za-z0-9]{24,}|rk_live_…    # Stripe
SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}                       # SendGrid
key-[a-f0-9]{32}                                               # Mailgun
xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}                           # SendinBlue
EAACEdEose0cBA[0-9A-Za-z]+                                     # Facebook access
npm_[A-Za-z0-9]{36}                                            # npm
pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+                             # PyPI
dckr_pat_[A-Za-z0-9_-]+                                        # Docker Hub PAT
[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}   # GUID — context-gated
eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+              # JWT
A3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}  # 1Password Secret Key
-----BEGIN (RSA |OPENSSH |EC |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----  # Private keys
//[^\s]+:_authToken=[A-Za-z0-9_-]{16,}                         # npm registry auth token line
machine [^\s]+ login [^\s]+ password [^\s]+                    # netrc
postgres(ql)?://[^:]+:[^@]+@[^/\s]+                            # DB conn strings
mysql://[^:]+:[^@]+@[^/\s]+
mongodb(\+srv)?://[^:]+:[^@]+@[^/\s]+
amqp(s)?://[^:]+:[^@]+@[^/\s]+
redis://[^:]*:[^@]+@[^/\s]+
```

This is the same approach gitleaks (~150+ rules), trufflehog (~700+ verifiers), detect-secrets (Yelp, plugin-based), Microsoft CredScan, GitGuardian (550+ specific detectors + ML-classified generic), and Mazin Ahmed's Secrets-Patterns-DB (1600+ patterns) all converge on. **The skill should not redefine these regexes from scratch — it should embed gitleaks's `gitleaks.toml` (Apache 2.0) or trufflehog's detector list and call it a day.** Maintenance is then someone else's problem.

### Pattern 6 — "High-Entropy Near a Keyword"

> *Any string of length ≥ 24 whose Shannon entropy ≥ 3.5–4.0 bits/byte that appears within 25 chars of a keyword in `{key, api, token, secret, password, passwd, auth, access, credential, bearer, signature, jwt, session, cookie, refresh}`, in any of the file types from Pattern 5.*

This is gitleaks's `generic-api-key` rule and GitGuardian's "Generic High Entropy Secret" rule. Tunable by entropy threshold; the well-known false-positive sources are public keys, version strings, hex hashes (SHA-256 of build artifacts, etc.), and base64-encoded image data. The accepted mitigations:

- Exclude file paths matching `(?:^|/)(node_modules|vendor|\.venv|venv|dist|build|target|\.next|\.nuxt|coverage|\.git|\.terraform|\.gradle|\.idea|\.vscode|\.dart_tool|Pods|DerivedData)/`.
- Exclude lines matching the public-key, version, hash, and base64-image regexes published in gitleaks's default config.
- Run a "stop word" list: `example|sample|test|fake|dummy|placeholder|xxxxxxxxxxx|0000000000|abcdef1234`.

### Pattern 7 — "Credential Hub Directories"

> *The ten or so specific directory roots that experience says hold credentials disproportionately:*
>
> - `~/Downloads/`, `~/Desktop/`, `~/Documents/`
> - `~/iCloud Drive/`, `~/Dropbox/`, `~/OneDrive/`, `~/Google Drive/` (and their macOS `~/Library/CloudStorage/` and `~/Library/Mobile Documents/` variants)
> - `~/.ssh/` (in skill)
> - `~/.aws/`, `~/.kube/`, `~/.gcloud/`, `~/.config/gcloud/`, `~/.azure/`, `~/.oci/`
> - `%USERPROFILE%\Downloads\`, `Desktop\`, `Documents\`, `OneDrive\`, `Dropbox\`
> - WSL roots: `\\wsl$\<distro>\home\<user>\`
> - Recycle Bin: `C:\$Recycle.Bin\<SID>\`
> - `/tmp/`, `/var/tmp/`, `~/Library/Caches/` (transient; many CLI tools leak token caches here, e.g. `~/Library/Caches/com.cursor.Cursor/Logs/`)
>
> Apply Patterns 3–6 against each.

### Composition

The skill becomes:

```
roots = pattern_7_roots()
candidates = []
candidates += pattern_1_dotdirs(home())
candidates += pattern_2_electron_apps(application_support_roots())
for root in roots:
    candidates += pattern_3_vault_files(root)
    candidates += pattern_4_keys(root)
    candidates += pattern_5_embedded_tokens(root)
    candidates += pattern_6_entropy(root)

for c in candidates:
    if requires_user_prompt(c):    # Touch ID, Hello, master password
        emit_existence_only(c)
    else:
        emit_findings(read_and_scan(c))
```

Adding a new tool is now zero-LOC: as long as it stores its tokens in any of the recognized shapes (a dotfile, an Electron leveldb, a `~/.config/<tool>/` directory, an export in Downloads, or a string with a known prefix or sufficient entropy), the skill catches it.

---

## Per-Category Summary Table (severity + prompt boundary)

| Category | macOS prompt? | Windows prompt? | Linux prompt? | Severity |
|---|---|---|---|---|
| 1Password Emergency Kit PDF | None | None | None | **Critical** |
| Bitwarden/LastPass exports (unencrypted) | None | None | None | **Critical** |
| KeePass `.kdbx` | None to read | None to read | None to read | High (offline crack) |
| JetBrains `c.kdbx` + `pdb.pwd` | None | None | None | **Critical** |
| Browser Login Data (Chromium) | Keychain ACL prompt to a 3rd-party reader (out of scope for *content*) | None (DPAPI pre-127); ABE-bypass needed for cookies post-127 (no UI) | None when keyring auto-unlocks | **Critical** |
| Browser cookies (session theft) | Same | Same | Same | **Critical** |
| Firefox `logins.json`+`key4.db` (no master pwd) | None | None | None | **Critical** |
| Slack/Discord/Teams leveldb | None | None | None | **Critical** |
| Signal `config.json` (legacy) | None | None | None | High |
| Signal post-`safeStorage` | Keychain ACL (Signal-only) | None | None when basic_text | Medium |
| Telegram tdata (no passcode) | None | None | None | **Critical** |
| GitHub CLI `hosts.yml` | None | None | None | **Critical** |
| GitHub Copilot `hosts.json` | None | None | None | High |
| AWS SSO cache | None | None | None | **Critical** |
| aws-vault keychain backend | Prompt (out of scope) | None (DPAPI) | Wallet prompt | High |
| Azure CLI `msal_token_cache.bin` | None (plaintext on macOS) | None (DPAPI) | None (plaintext) | **Critical** |
| gcloud `credentials.db` + `application_default_credentials.json` | None | None | None | **Critical** |
| kubeconfig `client-certificate-data` | None | None | None | **Critical** |
| Apple Notes / Messages chat.db | TCC FDA prompt if not granted | n/a | n/a | High (2FA codes) |
| `.env`, `.netrc`, `.git-credentials` | None | None | None | **Critical** |
| RDP saved (`.rdp` + Credential Manager) | n/a | None | n/a | High |
| WinSCP saved sessions | n/a | None (reversible XOR) | n/a | High |
| FileZilla `sitemanager.xml` | None | None | None | **Critical** when default |
| PuTTY private keys (`*.ppk`) | n/a | None | n/a | High |
| MetaMask / wallet extensions | None | None | None | **Critical** for wallet holders |
| Telegram tdata (with passcode) | Offline crack | Offline crack | Offline crack | High |
| 1Password CLI session token | Biometric on agent ops (out of scope) | Same | Same | Low |
| Touch ID-gated keychain item | **Prompt — out of scope** | n/a | n/a | n/a |
| Windows Hello-protected blob | n/a | **Prompt — out of scope** | n/a | n/a |
| iCloud Keychain `keychain-2.db` | **End-to-end encrypted — out of scope** | n/a | n/a | n/a |
| Safari saved passwords | **Out of scope** | n/a | n/a | n/a |

---

## Caveats

- **Provenance reliability of recent stealer reporting.** Several sources used for the Windows stealer Section H are vendor blog posts (BlackFog on Void, Picus on PupkinStealer/Stealc, SOCRadar on Void/StealC, Foresiet on Banshee/Stealc) — they cite primary IOCs but their narrative descriptions occasionally inflate or repeat each other. The most-rigorous primary analyses are Elastic Security Labs ("Beyond the Wail" on Banshee, "Katz and Mouse Game" on ABE bypass), Zscaler ThreatLabz on StealC v2, Kaspersky on VoidStealer, Red Canary on AMOS and ABE, Trend Micro Research on AMOS / OpenClaw, Check Point on Banshee, SentinelOne on Atomic-family lineage, Unit 42 on Poseidon/Cthulhu/Atomic, Cado/Darktrace on Cthulhu, eSentire on Poseidon, Sophos on StealC+Qilin, CyberArk on C4 Bomb, Recorded Future's 2025 Identity Threat Landscape Report, and Microsoft+Europol's May 2025 LummaC2 takedown announcement. Use those as the authoritative stack.
- **Detection numbers vary widely.** Vectra AI cites "1.8 billion credentials in 2025"; Recorded Future cites "1.95 billion malware combo list credential exposures". These count differently (Recorded Future deduplicates against authentication URLs, Vectra counts raw); treat the order of magnitude (~2 billion/year) as solid, individual figures as approximate.
- **Chrome ABE is a moving target.** The Chrome team has shipped at least three iterations of the elevation service / `PostProcessData` since v127. As of Q1 2026, all major stealer families are confirmed to bypass it from user-context, but Google can and does ship hardening patches; the detection-vs-evasion arms race continues. The skill should not assume cookie/Login-Data extraction is "always silent" on Windows; record the Chrome version and the `Local State`'s `app_bound_encrypted_key` presence so that future runs can adjust.
- **TCC on macOS is real for some artifacts.** `~/Library/Messages/chat.db`, `~/Library/Application Support/AddressBook/`, `~/Library/Calendars/`, `~/Library/Mail/V*/MailData/Envelope Index`, full `~/Library/Application Support/MobileSync/Backup/` (iOS device backups — frequently contain Keychain dumps if encrypted backups were enabled with a known password). On Mojave+ a non-FDA process gets `EPERM` reading these. Many investigation contexts run from a parent (Terminal, an MDM-pushed agent) that *has* FDA, in which case child processes inherit. The skill should `read()` and gracefully record TCC denials as "exists but unreadable from current TCC context".
- **Code-sign-based keychain ACLs are the real macOS prompt boundary.** macOS keychain items have an ACL that lists code-signed binaries permitted to read them silently. A third-party tool reading another app's keychain item triggers the "X wants to access … in your keychain" prompt unless the running binary's code requirement matches. The skill should *not* attempt `security find-generic-password -wa <app>` for items it didn't create — that prompts the user, is out of scope, and is also a noisy IOC. It can use `security dump-keychain` to enumerate item *metadata* (account, service, label, modification time) silently — this gives the existence signal without triggering content-access prompts.
- **The "user-confirmation prompt" boundary itself shifts**. Apple silently moved more keychain accesses to require Touch ID in Sequoia 15.x; the same item that was silent in Ventura may prompt in Sonoma+. The skill should defensively degrade: attempt access; if it observes an `errSecAuthFailed`/`errSecInteractionRequired`-class return code, mark the item as out-of-scope rather than retrying.
- **Some "stealers" claim capabilities they don't fully implement.** Poseidon's marketing claimed Fortinet/OpenVPN credential theft; Intego and others have not seen functional implementations in shipped samples. SOCRadar/BlackFog narratives sometimes describe panel features (server-side decryption, per-victim filtering) as if they were endpoint capabilities. When using stealer behavior to validate the skill's coverage, prefer the path lists from primary reverse-engineering reports (Elastic, Zscaler, Trend Micro, Check Point) over MaaS panel screenshots.
- **Per-tool storage formats change.** GitHub CLI added keyring storage in 2.26.0 (April 2023) but still falls back to plaintext `hosts.yml` on systems without a keyring (issue #7757); JetBrains added native keychain backends after years of KDBX-by-default; Signal's safeStorage migration completed in 2024; Anthropic's Claude Code uses different paths on macOS (Keychain-only) vs. Linux (`.credentials.json`). Pin tool versions and re-validate annually rather than treating any single path as eternal.
- **The "AI tool credential" category is rapidly expanding.** Claude Code, Cursor CLI, Codex CLI, OpenAI CLI, Windsurf, Trae, Kiro, Void, Zed AI, and the increasingly adopted Anthropic / OpenAI / Google MCP ecosystem each store tokens in slightly different ways. As of writing, the OAuth-with-PKCE flow has standardized for *new* MCP servers (March 2025 spec), but the configuration files (`~/.cursor/mcp.json`, `~/.codeium/windsurf/mcp_config.json`, `claude_desktop_config.json`) commonly contain bearer tokens in `env` blocks for stdio servers. Expect this category to grow; Pattern 1 covers it generically.