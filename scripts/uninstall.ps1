# uninstall.ps1 — remove puck-agent from this Windows endpoint.
#
# Mirrors uninstall.sh for the Unix side.  Stops the Scheduled Task,
# removes config/PKI material, and optionally deletes the binary.
#
# Note: puck-mcp also builds and runs on Windows, but Claude Code itself
# is macOS/Linux-only today, so typical Windows deployments are endpoint-
# only and only need the agent.  If you do run puck-mcp on a Windows
# operator host (e.g., via the Cursor / VS Code MCP-client integration),
# extend this script to also remove that install dir + Scheduled Task.
#
# Usage (PowerShell, no admin needed for user-scope install):
#   ./uninstall.ps1
#   ./uninstall.ps1 -RemoveBinary
#   ./uninstall.ps1 -AgentPrefix "C:\custom\puck-agent"

[CmdletBinding()]
param(
    [switch]$RemoveBinary,
    [string]$AgentPrefix = "$env:USERPROFILE\.config\puck-agent"
)

$ErrorActionPreference = 'Continue'   # keep going even if one step fails

Write-Host "puck-agent: stopping and removing Scheduled Task..."
try {
    Stop-ScheduledTask -TaskName 'puck-agent' -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'puck-agent' -Confirm:$false -ErrorAction Stop
    Write-Host "  removed: Scheduled Task 'puck-agent'"
} catch {
    Write-Host "  (Scheduled Task 'puck-agent' not registered, skipping)"
}

# Best-effort: stop any lingering puck-agent.exe still running (foreground
# `serve` someone may have launched manually outside the task).
$procs = Get-Process -Name 'puck-agent' -ErrorAction SilentlyContinue
if ($procs) {
    Write-Host "puck-agent: killing $($procs.Count) running puck-agent.exe process(es)"
    $procs | Stop-Process -Force -ErrorAction SilentlyContinue
}

# Remove config + cert material + yaml.
if (Test-Path -LiteralPath $AgentPrefix) {
    Write-Host "puck-agent: removing $AgentPrefix"
    # -Force handles read-only attributes; -Recurse removes subdirectories.
    Remove-Item -LiteralPath $AgentPrefix -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  removed: $AgentPrefix"
} else {
    Write-Host "  ($AgentPrefix not found, skipping)"
}

# Optional binary removal.  The PowerShell install block downloads
# puck-agent.exe into $AgentPrefix, so it's already gone above.  We also
# look on PATH in case someone installed it elsewhere.
if ($RemoveBinary) {
    $bin = Get-Command puck-agent -ErrorAction SilentlyContinue
    if ($bin) {
        Write-Host "puck-agent: removing $($bin.Source)"
        Remove-Item -LiteralPath $bin.Source -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "puck-agent: uninstall complete."
if (-not $RemoveBinary) {
    Write-Host "  Binary on PATH (if any) left in place.  Pass -RemoveBinary to also delete it."
}
Write-Host "  To reinstall: re-run the PowerShell block from"
Write-Host "    puck-mcp generate-bootstrap-token --hostname <h> --server <url>"
