#Requires -Version 5.1
<#
.SYNOPSIS
    LLM Security Monitor — Interactive Launcher

.DESCRIPTION
    Menu-driven launcher that configures and starts the proxy in WSL2.
    Handles mode selection, upstream URL, port, and live log streaming.

.PARAMETER BinaryPath
    Path to the compiled binary inside WSL2.
    Default: ./llm-security-monitor (relative to WSL2 home)

.PARAMETER WSLDistro
    WSL2 distribution name. Default: (default distro)

.EXAMPLE
    .\scripts\start.ps1
    .\scripts\start.ps1 -BinaryPath /home/lorenzo/llm-security-monitor/llm-security-monitor

.NOTES
    Author  : Lorenzo (github.com/Lollobar17)
    Project : https://github.com/Lollobar17/llm-security-monitor
#>

[CmdletBinding()]
param(
    [string] $BinaryPath = "./llm-security-monitor",
    [string] $WSLDistro  = ""
)

Set-StrictMode -Version Latest

# ── Helpers ────────────────────────────────────────────────────────────────────

function Write-Header {
    Clear-Host
    Write-Host @"

  ██╗     ██╗     ███╗   ███╗    ███████╗███████╗ ██████╗
  ██║     ██║     ████╗ ████║    ██╔====╝██╔====╝██╔====╝
  ██║     ██║     ██╔████╔██║    ███████╗█████╗  ██║
  ██║     ██║     ██║╚██╔╝██║    ╚====██║██╔==╝  ██║
  ███████╗███████╗██║ ╚=╝ ██║    ███████║███████╗╚██████╗
  ╚======╝╚======╝╚=╝     ╚=╝    ╚======╝╚======╝ ╚=====╝

  Interactive Launcher  |  STI-001 + NLI-001
"@ -ForegroundColor Cyan
}

function Write-Menu([string]$title, [string[]]$options) {
    Write-Host "`n  $title" -ForegroundColor White
    Write-Host "  $('─' * 45)" -ForegroundColor DarkGray
    for ($i = 0; $i -lt $options.Count; $i++) {
        Write-Host "  [$($i+1)] $($options[$i])" -ForegroundColor Yellow
    }
    Write-Host ""
}

function Read-Choice([int]$max) {
    do {
        $raw = Read-Host "  Choice (1-$max)"
        $n   = 0
    } until ([int]::TryParse($raw, [ref]$n) -and $n -ge 1 -and $n -le $max)
    return $n
}

function Test-WSL {
    try { $null = wsl --status 2>&1; return $true }
    catch { return $false }
}

function Invoke-WSL([string]$cmd) {
    if ($WSLDistro) {
        return wsl -d $WSLDistro -- bash -c $cmd
    }
    return wsl -- bash -c $cmd
}

# ── Main ───────────────────────────────────────────────────────────────────────

Write-Header

# Check WSL2 availability
if (-not (Test-WSL)) {
    Write-Host "  [FAIL] WSL2 not found. Install WSL2 and rebuild the binary." -ForegroundColor Red
    exit 1
}

# ── Step 1: Operation mode ─────────────────────────────────────────────────────
Write-Menu "Operation Mode" @(
    "Alert-only     — log detections, never block (safe for testing)"
    "Block mode     — return 403 on HIGH-confidence attacks"
    "Sanitize mode  — clean injections and forward sanitized body"
)
$mode = Read-Choice 3

$blockMode    = "false"
$sanitizeMode = "false"
$modeLabel    = "alert-only"

switch ($mode) {
    2 { $blockMode    = "true"; $modeLabel = "BLOCK" }
    3 { $sanitizeMode = "true"; $modeLabel = "SANITIZE" }
}

# ── Step 2: Upstream URL ───────────────────────────────────────────────────────
Write-Menu "Upstream LLM Backend" @(
    "Ollama (default)  http://localhost:11434"
    "vLLM              http://localhost:8000"
    "Custom URL"
)
$upstreamChoice = Read-Choice 3

$upstreamURL = switch ($upstreamChoice) {
    1 { "http://localhost:11434" }
    2 { "http://localhost:8000" }
    3 { Read-Host "  Enter upstream URL" }
}

# ── Step 3: Port ───────────────────────────────────────────────────────────────
$portRaw = Read-Host "`n  Proxy port [8080]"
$proxyPort = if ($portRaw -match '^\d+$') { $portRaw } else { "8080" }

# ── Step 4: Log level ─────────────────────────────────────────────────────────
Write-Menu "Log Level" @("INFO — standard output", "DEBUG — per-finding detail")
$logLevel = if ((Read-Choice 2) -eq 2) { "DEBUG" } else { "INFO" }

# ── Step 5: SIEM webhook (optional) ───────────────────────────────────────────
$webhookRaw = Read-Host "`n  SIEM webhook URL (leave empty to skip)"
$siemEnv    = if ($webhookRaw) { "SIEM_WEBHOOK='$webhookRaw'" } else { "" }

# ── Summary ────────────────────────────────────────────────────────────────────
Write-Host "`n  $('─' * 50)" -ForegroundColor DarkGray
Write-Host "  Configuration:" -ForegroundColor White
Write-Host "    Mode       : $modeLabel"     -ForegroundColor Green
Write-Host "    Upstream   : $upstreamURL"   -ForegroundColor Green
Write-Host "    Port       : $proxyPort"     -ForegroundColor Green
Write-Host "    Log level  : $logLevel"      -ForegroundColor Green
if ($webhookRaw) { Write-Host "    Webhook    : $webhookRaw" -ForegroundColor Green }
Write-Host "  $('─' * 50)" -ForegroundColor DarkGray

$confirm = Read-Host "`n  Start proxy? [Y/n]"
if ($confirm -match '^[Nn]') { Write-Host "  Aborted." -ForegroundColor Yellow; exit 0 }

# ── Build env string ───────────────────────────────────────────────────────────
$envVars = "UPSTREAM_URL='$upstreamURL' BLOCK_MODE=$blockMode SANITIZE_MODE=$sanitizeMode " +
           "PROXY_PORT=$proxyPort LOG_LEVEL=$logLevel $siemEnv"

$wslCmd  = "$envVars $BinaryPath"

Write-Host "`n  >> Starting proxy in WSL2..." -ForegroundColor Cyan
Write-Host "  Listening on http://localhost:$proxyPort" -ForegroundColor White
Write-Host "  Press Ctrl+C to stop.`n" -ForegroundColor DarkGray

# Stream proxy output with colour coding
try {
    Invoke-WSL $wslCmd | ForEach-Object {
        $line = $_
        # Parse JSON log lines for colour coding
        try {
            $obj = $line | ConvertFrom-Json -ErrorAction Stop
            $level = $obj.level
            $color = switch ($level) {
                "WARN"  { "Yellow" }
                "ERROR" { "Red" }
                "DEBUG" { "DarkGray" }
                default { "White" }
            }
            # Highlight STI/NLI alerts
            if ($obj.msg -match "STI-001 FIRED|NLI-001 FIRED") { $color = "Red" }
            $ts  = if ($obj.time) { "[{0}]" -f ([datetime]$obj.time).ToString("HH:mm:ss") } else { "" }
            $msg = $obj.msg
            Write-Host "$ts $msg" -ForegroundColor $color
        } catch {
            # Non-JSON line — print as-is
            Write-Host $line -ForegroundColor DarkGray
        }
    }
} catch {
    Write-Host "`n  Proxy stopped." -ForegroundColor Yellow
}
