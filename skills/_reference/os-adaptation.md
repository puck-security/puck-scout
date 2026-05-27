# OS Adaptation Guide

Puck skills are authored in Unix vocabulary (`cat`, `ls`, `find`, `grep`,
`stat`, `head`) because that's the lingua franca for IR scripting. On a
Linux or macOS endpoint those commands run directly. On a Windows
endpoint without Git Bash, the same commands don't exist — but the
*intent* (read a file, list a directory, search a pattern) has direct
PowerShell and native-Windows equivalents that are already admitted by
the policy engine.

When you reach a skill phase that uses Unix tools and the target is
Windows, use this guide to translate before issuing the command.

## How to know the target OS

In rough preference order:

1. **`puck_investigate` overview line `Target OS:`.** The MCP server
   reports this when it knows the OS for the target hostname (the agent
   reports its OS at enrollment and on every poll). Trust this if it's
   present; skip the discovery probe.
2. **`uname -s`** — returns `Darwin` on macOS, `Linux` on Linux,
   `MINGW64_NT-10.0` / `MSYS_NT-10.0` / similar on Git Bash, and
   *errors out entirely* on pure Windows hosts (no Git Bash). An error
   from `uname` is a strong Windows signal.
3. **`whoami`** — output `DOMAIN\user` on Windows; bare `user` on Unix.
   The backslash is the tell.
4. **`powershell -NoProfile -Command Get-ComputerInfo`** — definitive
   but heavyweight; use only if the cheaper probes were ambiguous.

When `puck_investigate` already advertised Windows, don't waste a turn
on `uname` — go straight to the translated commands.

## Unix → Windows native translation

Two columns by intent. PowerShell forms are the primary path (admitted
by `policy/policy.toml`'s `-Command Get-*` glob entries). `findstr` /
`where` / `tasklist` are admitted as their own binaries.

| Intent | Unix | Windows native | Notes |
|---|---|---|---|
| Read a file | `cat <file>` | `powershell -Command Get-Content <file>` | Path is positional. For first-N-lines, add `-TotalCount N`. |
| List a directory | `ls <dir>` | `powershell -Command Get-ChildItem <dir>` | Add `-Force` to include hidden; `-Recurse` to descend. |
| Find files by name | `find <root> -name '*.pem'` | `powershell -Command Get-ChildItem <root> -Recurse -Filter *.pem` | `-Filter` is a single glob; for multiple, use `-Include *.pem,*.key` |
| Find files by content | `grep -r 'AKIA' <dir>` | `findstr /S /I AKIA <dir>` | findstr is much faster than `Get-Content \| Select-String` on large trees. |
| First N lines | `head -n 50 <file>` | `powershell -Command Get-Content <file> -TotalCount 50` | |
| Last N lines | `tail -n 50 <file>` | `powershell -Command Get-Content <file> -Tail 50` | |
| File metadata | `stat <file>` | `powershell -Command Get-Item <file>` | Returns FileInfo with .Length, .LastWriteTime, .Mode. |
| Magic-byte type | `file <file>` | (no direct equivalent) | Read first bytes via `Get-Content <file> -TotalCount 1 -Encoding byte` and inspect. |
| Look up a binary | `which X` | `where X` | `where` is admitted as a positional-string binary. |
| List processes | `ps aux` | `powershell -Command Get-Process` or `tasklist` | tasklist is faster; Get-Process gives richer fields. |
| Net connections | `lsof -i -n -P` / `ss -tnp` | `netstat -ano` | The `-ano` combined form is admitted. |
| Process by image | `pgrep <name>` | `tasklist /FI "IMAGENAME eq <name>.exe"` | |
| Bytes-as-text dump | `strings <file>` | (no native equivalent on stock Windows; install Sysinternals strings.exe or use Git Bash). | |

## Path conventions

Skills use a `<home>` placeholder that the LLM substitutes:

- Linux: `<home>` = `/home/<username>`
- macOS: `<home>` = `/Users/<username>`
- Windows: `<home>` = `C:\Users\<username>`

Get `<username>` from `whoami` (strip any `DOMAIN\` prefix on Windows).

**Forward vs. back slashes in PowerShell.** PowerShell accepts both;
forward-slash is safer in MCP/JSON args because it doesn't need
backslash-escaping. `Get-Content C:/Users/X/.aws/credentials` works
identically to `Get-Content C:\Users\X\.aws\credentials`. Prefer
forward-slash to avoid double-escaping pain.

**Windows-specific roots:**

- `C:\Users\<user>` — user profile (analog of `/home/<user>`)
- `C:\Users\<user>\AppData\Roaming` — `<appdata>` placeholder; analog of `~/Library/Application Support` on macOS or `~/.config` on Linux.
- `C:\Users\<user>\AppData\Local` — `<localappdata>`; volatile cache, app state.
- `C:\ProgramData` — system-wide application config (Windows equivalent of `/etc`).
- `C:\Windows\System32` — Windows binaries. Skill prose should not reach here directly; investigate via `Get-Process` / `Get-Service` instead.

## PowerShell guardrails

### Common mistake — the `Get-X` token is ONE bareword, not a script

The most common reason PowerShell calls reject as `unknown_subcommand`:
the LLM puts an entire PowerShell pipeline inside the `-Command` value
as a single quoted string.  THIS DOES NOT WORK:

```
# ❌  rejects as unknown_subcommand
powershell -Command "Get-Process | Where-Object Name -eq edge"
powershell -Command "Get-ChildItem; Get-Process"
powershell -Command "(Get-Item C:/etc/hosts).Length"
```

The policy admits only a single bareword `Get-<Cmdlet>` token as the
"subcommand", followed by simple positionals and a curated flag set.
Pipelines, semicolons, parentheses, and any other shell-metacharacters
in that token are rejected to prevent script-smuggling.

If you need to combine multiple Get-* calls, **issue them as separate
puck_run_check invocations** and join the results in the analysis.  If
you need post-processing the policy doesn't support (filter by
property, project a column), do it on the puck side after results
return — don't try to express it in `-Command`.

### Supported invocation forms

The policy engine accepts three forms of PowerShell invocation,
longest-first:

```
powershell -NoProfile -NonInteractive -Command Get-<Cmdlet> [args...]
powershell -NoProfile               -Command Get-<Cmdlet> [args...]
powershell                           -Command Get-<Cmdlet> [args...]
```

Prefer the full `-NoProfile -NonInteractive -Command Get-X` form when
possible: `-NoProfile` skips `$PROFILE.*` (which can run arbitrary code
on every invocation); `-NonInteractive` ensures the agent never deadlocks
on a prompt.

**Allowed positional args** (after `Get-X`): up to 4 filesystem paths,
each validated against an allowlist of prefixes that covers Linux,
macOS, and Windows roots. Pass paths positionally rather than via
`-Path` when possible — fewer characters and identical semantics for
most Get-cmdlets.

**Allowed flags after `Get-X`:** `-Recurse`, `-Force`, `-Filter`,
`-Include`, `-Exclude`, `-TotalCount <N>`, `-Tail <N>`, `-Encoding
<kind>`, `-Path <p>`, `-LiteralPath <p>`. Anything else (e.g.
`-Property`, `-ExpandProperty`) is rejected as `unknown_flag` — fall
back to a simpler invocation.

**Required with `-Recurse`: an explicit path.** `Get-ChildItem
-Recurse <path>` works.  `Get-ChildItem -Recurse` alone (no
positional, no `-Path`) is admitted by the policy but defaults to
`$PWD` at runtime, which on Windows under Claude Code's stdio-fork
ends up being the user's home directory.  The result is a noisy
stderr full of access-denied messages for Windows legacy junction
points (`Application Data`, `Cookies`, `My Documents`) under
`C:\Users\<user>`.  Always pass the path you want to recurse.  As
extra protection, `puck-agent` pins its CWD to `/` on Unix and
`C:\Windows\Temp` on Windows before every spawn, so a missed-path
recurse won't leak the operator's home tree — but the noise is still
worth avoiding.

**Paths with spaces are handled automatically.** `puck-agent` wraps
any whitespace-bearing positional argv token in PowerShell single-
quotes before spawn, so `Get-Content C:/Users/X/AppData/Local/Microsoft/Edge/User Data/Default`
goes through cleanly.  You don't need to pre-quote on your end.

**Forbidden constructs:** any `;`, `|`, `&`, `(`, `)`, `{`, `}` inside a
single argv token (script-chaining smuggle); any cmdlet not matching
`Get-*`. To pipe results, run two separate invocations and process the
output server-side.

## What does not translate

Some Unix tools have no clean PowerShell equivalent. Recognise these
and degrade gracefully:

- **`mdfind`** — macOS Spotlight, no Windows equivalent. On Windows,
  fall back to `Get-ChildItem -Recurse -Filter` (slower; budget for it).
- **`journalctl`** — systemd-specific. Windows uses `Get-WinEvent` (not
  yet in policy as of v1.0; surfaces a real ir-triage gap).
- **`crontab`** / **`/etc/cron.*`** — Windows uses `schtasks` (not yet
  in policy). Mention in skill notes; skip the step rather than emit
  garbage.
- **`launchctl`** / `~/Library/LaunchAgents` — macOS-only persistence
  mechanism. No Windows or Linux equivalent.
- **`ss -tnp`** / **`lsof -i -P`** — Linux/macOS network inspection.
  `netstat -ano` is the Windows equivalent (admitted in policy); use
  it.
- **`security` (macOS Keychain)** — macOS-only. Windows DPAPI access is
  handled by `credential-exposure` Phase 15 via cmdkey/reg.

## When Git Bash IS installed

`C:\Program Files\Git\usr\bin\<cmd>.exe` carries `cat`, `ls`, `find`,
`grep`, `head`, `tail`, `stat`, `file`, and friends. These are in the
policy's `canonical_paths` lists as a *fallback*. If the operator
prefers the Unix forms and has Git Bash on every Windows endpoint, the
skill prose works as-written. The translation table above is for the
no-Git-Bash case AND for the case where a native PowerShell form is
faster (e.g., `findstr /S` beats `grep -r` through Git Bash's emulated
filesystem on Windows by 5-10x for large trees).

## When you hit something unmapped

Report it in your analysis. The translation table above is a living
document — operators who hit edge cases (Cyrillic file names, NTFS
junction points, OneDrive shadow paths, WSL passthrough corner cases)
should propose additions via PR to `skills/_reference/os-adaptation.md`.
