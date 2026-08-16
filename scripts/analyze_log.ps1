#Requires -Version 5.1
<#
.SYNOPSIS
    LLM Security Monitor — Log Analyzer

.DESCRIPTION
    Parses the proxy's structured JSON log output and produces a formatted
    security summary: alert counts, confidence breakdown, top source IPs,
    attack type distribution, and a timeline.

    Accepts input from a file or from a pipeline (live log streaming).

.PARAMETER LogFile
    Path to a saved proxy log file (.log or .jsonl).
    If omitted, reads from stdin (pipeline mode).

.PARAMETER Last
    Only analyze the last N log entries. 0 = all (default).

.PARAMETER ExportHtml
    Save an HTML summary report to this path.
    E.g.: C:\Users\MPC\Desktop\report.html

.EXAMPLE
    # Analyze a saved log file
    .\scripts\analyze_log.ps1 -LogFile C:\Users\MPC\Desktop\proxy.log

    # Live streaming from WSL2 (Ctrl+C to stop)
    wsl -- bash -c "cd ~/llm-security-monitor && ./llm-security-monitor" | .\scripts\analyze_log.ps1

    # Last 500 lines only
    .\scripts\analyze_log.ps1 -LogFile proxy.log -Last 500

    # Export HTML report
    .\scripts\analyze_log.ps1 -LogFile proxy.log -ExportHtml C:\Users\MPC\Desktop\report.html

.NOTES
    Author  : Lorenzo (github.com/Lollobar17)
    Project : https://github.com/Lollobar17/llm-security-monitor
#>

[CmdletBinding()]
param(
    [string] $LogFile   = "",
    [int]    $Last      = 0,
    [string] $ExportHtml = ""
)

Set-StrictMode -Version Latest

# ── State ──────────────────────────────────────────────────────────────────────

$stats = @{
    TotalLines    = 0
    ParseErrors   = 0
    STIAlerts     = [System.Collections.Generic.List[PSCustomObject]]::new()
    NLIAlerts     = [System.Collections.Generic.List[PSCustomObject]]::new()
    Blocked       = 0
    Sanitized     = 0
    Requests      = 0
    StartTime     = $null
    EndTime       = $null
}

$ipCounts      = @{}
$confidenceCounts = @{ "HIGH"=0; "MEDIUM"=0; "LOW"=0 }
$nliCategories = @{}
$stiTokens     = @{}
$timeline      = [System.Collections.Generic.List[PSCustomObject]]::new()

# ── Log line parser ────────────────────────────────────────────────────────────

function Parse-LogLine([string]$line) {
    try { return $line | ConvertFrom-Json -ErrorAction Stop }
    catch { return $null }
}

function Process-Entry([PSCustomObject]$entry) {
    if (-not $entry -or -not $entry.time) { return }

    $ts = try { [datetime]$entry.time } catch { $null }
    if ($ts) {
        if (-not $stats.StartTime -or $ts -lt $stats.StartTime) { $stats.StartTime = $ts }
        if (-not $stats.EndTime   -or $ts -gt $stats.EndTime)   { $stats.EndTime   = $ts }
    }

    $msg = "$($entry.msg)"

    # Count requests (any log line from handler is a request proxy attempt)
    if ($msg -match "FORWARD|sanitized|blocked") { $stats.Requests++ }

    # STI alert
    if ($msg -match "STI-001 FIRED") {
        $stats.STIAlerts.Add([PSCustomObject]@{
            Time       = $ts
            SourceIP   = "$($entry.src)"
            Confidence = "$($entry.confidence)"
            Findings   = [int]"$($entry.findings)"
            Model      = "$($entry.model)"
        })
        $conf = "$($entry.confidence)"
        if ($confidenceCounts.ContainsKey($conf)) { $confidenceCounts[$conf]++ }
        $ip = "$($entry.src)"
        if ($ip) { $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1 }

        $timeline.Add([PSCustomObject]@{
            Time = $ts; Rule = "STI-001"; Confidence = $conf; IP = $ip })
    }

    # NLI alert
    if ($msg -match "NLI-001 FIRED") {
        $stats.NLIAlerts.Add([PSCustomObject]@{
            Time       = $ts
            SourceIP   = "$($entry.src)"
            Confidence = "$($entry.confidence)"
            Findings   = [int]"$($entry.findings)"
            Model      = "$($entry.model)"
        })
        $conf = "$($entry.confidence)"
        if ($confidenceCounts.ContainsKey($conf)) { $confidenceCounts[$conf]++ }
        $ip = "$($entry.src)"
        if ($ip) { $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1 }

        $timeline.Add([PSCustomObject]@{
            Time = $ts; Rule = "NLI-001"; Confidence = $conf; IP = $ip })
    }

    # NLI finding detail (DEBUG level)
    if ($msg -eq "nli-finding" -and $entry.category) {
        $cat = "$($entry.category)"
        $nliCategories[$cat] = ($nliCategories[$cat] ?? 0) + 1
    }

    # STI finding detail (DEBUG level)
    if ($msg -eq "sti-finding" -and $entry.token) {
        $tok = "$($entry.token)"
        $stiTokens[$tok] = ($stiTokens[$tok] ?? 0) + 1
    }

    # Block / sanitize tracking
    if ("$($entry.level)" -eq "WARN" -and $msg -match "blocked") { $stats.Blocked++ }
    if ($msg -eq "request sanitized") { $stats.Sanitized++ }
}

# ── Read input ─────────────────────────────────────────────────────────────────

Write-Host "`n  LLM Security Monitor — Log Analyzer" -ForegroundColor Cyan
Write-Host "  $('─' * 50)" -ForegroundColor DarkGray

if ($LogFile) {
    if (-not (Test-Path $LogFile)) {
        Write-Host "  [FAIL] File not found: $LogFile" -ForegroundColor Red; exit 1
    }
    Write-Host "  Reading: $LogFile" -ForegroundColor DarkGray
    $lines = Get-Content $LogFile -Encoding UTF8
    if ($Last -gt 0 -and $lines.Count -gt $Last) {
        $lines = $lines | Select-Object -Last $Last
    }
    foreach ($line in $lines) {
        if (-not $line.Trim()) { continue }
        $stats.TotalLines++
        $entry = Parse-LogLine $line
        if ($entry) { Process-Entry $entry }
        else { $stats.ParseErrors++ }
    }
} else {
    Write-Host "  Reading from stdin (Ctrl+C to stop and show report)..." -ForegroundColor DarkGray
    $count = 0
    try {
        foreach ($line in $input) {
            if (-not $line.Trim()) { continue }
            $stats.TotalLines++
            $count++
            $entry = Parse-LogLine $line
            if ($entry) {
                Process-Entry $entry
                # Live alert indicator
                if ("$($entry.msg)" -match "FIRED") {
                    Write-Host "  [HIGH] ALERT: $($entry.msg) | src=$($entry.src) conf=$($entry.confidence)" `
                        -ForegroundColor Red
                }
            } else { $stats.ParseErrors++ }
        }
    } catch { }
}

# ── Report ─────────────────────────────────────────────────────────────────────

$totalAlerts = $stats.STIAlerts.Count + $stats.NLIAlerts.Count
$duration    = if ($stats.StartTime -and $stats.EndTime) {
    ($stats.EndTime - $stats.StartTime).ToString("hh\:mm\:ss")
} else { "N/A" }

Write-Host "`n"
Write-Host "  ╔==================================================╗" -ForegroundColor White
Write-Host "  ║          SECURITY SUMMARY REPORT                 ║" -ForegroundColor White
Write-Host "  ╚==================================================╝" -ForegroundColor White
Write-Host ""

# Overview
Write-Host "  OVERVIEW" -ForegroundColor White
Write-Host "  $('─' * 50)" -ForegroundColor DarkGray
Write-Host ("  {0,-28} {1}" -f "Log entries processed:",   $stats.TotalLines)   -ForegroundColor Gray
Write-Host ("  {0,-28} {1}" -f "Duration:",                $duration)            -ForegroundColor Gray
Write-Host ("  {0,-28} {1}" -f "Parse errors:",            $stats.ParseErrors)   -ForegroundColor $(if($stats.ParseErrors -gt 0){"Yellow"}else{"Gray"})
Write-Host ("  {0,-28} {1}" -f "Total alerts:",            $totalAlerts)         -ForegroundColor $(if($totalAlerts -gt 0){"Red"}else{"Green"})
Write-Host ("  {0,-28} {1}" -f "  STI-001 alerts:",        $stats.STIAlerts.Count) -ForegroundColor Gray
Write-Host ("  {0,-28} {1}" -f "  NLI-001 alerts:",        $stats.NLIAlerts.Count) -ForegroundColor Gray
Write-Host ("  {0,-28} {1}" -f "Requests blocked:",        $stats.Blocked)       -ForegroundColor $(if($stats.Blocked -gt 0){"Red"}else{"Gray"})
Write-Host ("  {0,-28} {1}" -f "Requests sanitized:",      $stats.Sanitized)     -ForegroundColor $(if($stats.Sanitized -gt 0){"Yellow"}else{"Gray"})
Write-Host ""

# Confidence breakdown
if ($totalAlerts -gt 0) {
    Write-Host "  CONFIDENCE BREAKDOWN" -ForegroundColor White
    Write-Host "  $('─' * 50)" -ForegroundColor DarkGray
    foreach ($conf in @("HIGH","MEDIUM","LOW")) {
        $n     = $confidenceCounts[$conf]
        $color = switch ($conf) { "HIGH"{"Red"} "MEDIUM"{"Yellow"} "LOW"{"DarkCyan"} }
        $bar   = "█" * [Math]::Min($n, 40)
        Write-Host ("  {0,-8} {1,4}  {2}" -f $conf, $n, $bar) -ForegroundColor $color
    }
    Write-Host ""

    # Top source IPs
    if ($ipCounts.Count -gt 0) {
        Write-Host "  TOP SOURCE IPs" -ForegroundColor White
        Write-Host "  $('─' * 50)" -ForegroundColor DarkGray
        $ipCounts.GetEnumerator() |
            Sort-Object Value -Descending |
            Select-Object -First 10 |
            ForEach-Object {
                $bar = "█" * [Math]::Min($_.Value, 30)
                Write-Host ("  {0,-22} {1,4}  {2}" -f $_.Key, $_.Value, $bar) -ForegroundColor Yellow
            }
        Write-Host ""
    }

    # NLI category breakdown
    if ($nliCategories.Count -gt 0) {
        Write-Host "  NLI-001 ATTACK CATEGORIES" -ForegroundColor White
        Write-Host "  $('─' * 50)" -ForegroundColor DarkGray
        $nliCategories.GetEnumerator() |
            Sort-Object Value -Descending |
            ForEach-Object {
                Write-Host ("  {0,-35} {1}" -f $_.Key, $_.Value) -ForegroundColor DarkCyan
            }
        Write-Host ""
    }

    # STI token breakdown
    if ($stiTokens.Count -gt 0) {
        Write-Host "  STI-001 TOKENS DETECTED" -ForegroundColor White
        Write-Host "  $('─' * 50)" -ForegroundColor DarkGray
        $stiTokens.GetEnumerator() |
            Sort-Object Value -Descending |
            Select-Object -First 10 |
            ForEach-Object {
                Write-Host ("  {0,-35} {1}" -f $_.Key, $_.Value) -ForegroundColor Magenta
            }
        Write-Host ""
    }

    # Recent alerts timeline
    if ($timeline.Count -gt 0) {
        Write-Host "  ALERT TIMELINE (last 10)" -ForegroundColor White
        Write-Host "  $('─' * 50)" -ForegroundColor DarkGray
        $timeline |
            Sort-Object Time -Descending |
            Select-Object -First 10 |
            ForEach-Object {
                $ts  = if ($_.Time) { $_.Time.ToString("HH:mm:ss") } else { "??:??:??" }
                $col = if ($_.Rule -eq "STI-001") { "Magenta" } else { "DarkCyan" }
                Write-Host ("  {0}  {1,-8}  {2,-6}  {3}" -f $ts, $_.Rule, $_.Confidence, $_.IP) -ForegroundColor $col
            }
        Write-Host ""
    }
}

# ── HTML export ────────────────────────────────────────────────────────────────

if ($ExportHtml) {
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>LLM Security Monitor — Log Report</title>
<style>
  body { font-family: 'Consolas', monospace; background: #0d1117; color: #c9d1d9; padding: 2em; }
  h1   { color: #58a6ff; }
  h2   { color: #8b949e; border-bottom: 1px solid #30363d; padding-bottom: .3em; }
  table{ border-collapse: collapse; width: 100%; margin-bottom: 2em; }
  th   { background: #161b22; color: #58a6ff; padding: .5em 1em; text-align: left; }
  td   { padding: .4em 1em; border-bottom: 1px solid #21262d; }
  .HIGH   { color: #f85149; font-weight: bold; }
  .MEDIUM { color: #e3b341; }
  .LOW    { color: #3fb950; }
</style>
</head>
<body>
<h1>LLM Security Monitor LLM Security Monitor — Security Report</h1>
<p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

<h2>Overview</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Log entries</td><td>$($stats.TotalLines)</td></tr>
<tr><td>Duration</td><td>$duration</td></tr>
<tr><td>Total alerts</td><td class="HIGH">$totalAlerts</td></tr>
<tr><td>STI-001 alerts</td><td>$($stats.STIAlerts.Count)</td></tr>
<tr><td>NLI-001 alerts</td><td>$($stats.NLIAlerts.Count)</td></tr>
<tr><td>Blocked</td><td>$($stats.Blocked)</td></tr>
<tr><td>Sanitized</td><td>$($stats.Sanitized)</td></tr>
</table>

<h2>Confidence Breakdown</h2>
<table>
<tr><th>Confidence</th><th>Count</th></tr>
$(($confidenceCounts.GetEnumerator() | ForEach-Object {
    "<tr><td class='$($_.Key)'>$($_.Key)</td><td>$($_.Value)</td></tr>"
}) -join "`n")
</table>

<h2>Alert Timeline</h2>
<table>
<tr><th>Time</th><th>Rule</th><th>Confidence</th><th>Source IP</th></tr>
$(($timeline | Sort-Object Time -Descending | Select-Object -First 50 | ForEach-Object {
    $ts = if($_.Time){$_.Time.ToString("HH:mm:ss")}else{"N/A"}
    "<tr><td>$ts</td><td>$($_.Rule)</td><td class='$($_.Confidence)'>$($_.Confidence)</td><td>$($_.IP)</td></tr>"
}) -join "`n")
</table>
</body></html>
"@
    $html | Out-File -FilePath $ExportHtml -Encoding UTF8
    Write-Host "  Saved: HTML report saved to: $ExportHtml" -ForegroundColor DarkCyan
}

Write-Host "  Analysis complete." -ForegroundColor Green
