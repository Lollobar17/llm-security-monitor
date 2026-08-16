#Requires -Version 5.1
<#
.SYNOPSIS
    LLM Security Monitor — Benchmark Runner

.DESCRIPTION
    Runs go test -bench against all packages via WSL2 and formats the output
    as a color-coded performance table. Highlights regressions (> threshold)
    in red and fast paths in green.

.PARAMETER ProjectPath
    WSL2 path to the project root.
    Default: ~/llm-security-monitor

.PARAMETER BenchTime
    Time per benchmark. Default: 3s

.PARAMETER WarnThresholdMs
    Benchmarks over this many milliseconds are highlighted yellow. Default: 1

.PARAMETER FailThresholdMs
    Benchmarks over this many milliseconds are highlighted red. Default: 10

.PARAMETER OutputCsv
    Optional path to save results as CSV (e.g. C:\Users\MPC\Desktop\bench.csv)

.EXAMPLE
    .\scripts\bench.ps1
    .\scripts\bench.ps1 -BenchTime 5s -OutputCsv C:\Users\MPC\Desktop\bench.csv

.NOTES
    Author  : Lorenzo (github.com/Lollobar17)
    Project : https://github.com/Lollobar17/llm-security-monitor
#>

[CmdletBinding()]
param(
    [string] $ProjectPath      = "~/llm-security-monitor",
    [string] $BenchTime        = "3s",
    [double] $WarnThresholdMs  = 1.0,
    [double] $FailThresholdMs  = 10.0,
    [string] $OutputCsv        = ""
)

Set-StrictMode -Version Latest

# ── Header ─────────────────────────────────────────────────────────────────────

Write-Host @"

  LLM Security Monitor — Benchmark Suite
  ─────────────────────────────────────────────────
  Project  : $ProjectPath
  BenchTime: $BenchTime
  Warn  >  : ${WarnThresholdMs} ms (yellow)
  Fail  >  : ${FailThresholdMs} ms (red)
"@ -ForegroundColor Cyan

# ── Run benchmarks via WSL2 ────────────────────────────────────────────────────

Write-Host "`n  Running benchmarks..." -ForegroundColor DarkGray

$cmd = "cd $ProjectPath && go test -bench=. -benchmem -benchtime=$BenchTime -run='^$' ./... 2>&1"

try {
    $rawLines = wsl -- bash -c $cmd
} catch {
    Write-Host "  [FAIL] WSL2 error: $_" -ForegroundColor Red
    exit 1
}

# ── Parse benchmark output ─────────────────────────────────────────────────────

# Format: BenchmarkName-N   iterations   ns/op   B/op   allocs/op
$benchRegex = '^(Benchmark\S+)\s+(\d+)\s+([\d.]+)\s+ns/op(?:\s+([\d.]+)\s+B/op\s+(\d+)\s+allocs/op)?'

$results = @()

foreach ($line in $rawLines) {
    if ($line -match $benchRegex) {
        $nsPerOp  = [double]$Matches[3]
        $msPerOp  = $nsPerOp / 1e6
        $bPerOp   = if ($Matches[4]) { [long]$Matches[4] } else { 0 }
        $allocs   = if ($Matches[5]) { [int]$Matches[5]  } else { 0 }

        $results += [PSCustomObject]@{
            Name      = $Matches[1] -replace '-\d+$', ''   # strip -8 suffix
            Iters     = [long]$Matches[2]
            NsPerOp   = $nsPerOp
            MsPerOp   = $msPerOp
            BPerOp    = $bPerOp
            AllocsOp  = $allocs
        }
    }
}

if ($results.Count -eq 0) {
    Write-Host "  No benchmark results found. Check WSL2 path and Go installation." -ForegroundColor Yellow
    Write-Host ""
    $rawLines | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    exit 1
}

# ── Display table ──────────────────────────────────────────────────────────────

Write-Host ""
$hdr = "  {0,-48} {1,10} {2,10} {3,8} {4,8}" -f "BENCHMARK", "ms/op", "ns/op", "B/op", "allocs"
Write-Host $hdr -ForegroundColor White
Write-Host "  $('─' * 88)" -ForegroundColor DarkGray

foreach ($r in $results | Sort-Object MsPerOp -Descending) {
    $color = if     ($r.MsPerOp -gt $FailThresholdMs) { "Red"    }
             elseif ($r.MsPerOp -gt $WarnThresholdMs)  { "Yellow" }
             else                                       { "Green"  }

    $msStr = "{0:F4}" -f $r.MsPerOp
    $nsStr = "{0:N0}" -f $r.NsPerOp
    $bStr  = "{0:N0}" -f $r.BPerOp
    $aStr  = "{0}" -f $r.AllocsOp

    $icon = if ($r.MsPerOp -gt $FailThresholdMs) { "[HIGH]" }
            elseif ($r.MsPerOp -gt $WarnThresholdMs) { "[WARN]" }
            else { "[OK]" }

    $line = "  $icon {0,-46} {1,10} {2,10} {3,8} {4,8}" -f `
        $r.Name, $msStr, $nsStr, $bStr, $aStr
    Write-Host $line -ForegroundColor $color
}

Write-Host "  $('─' * 88)" -ForegroundColor DarkGray

# ── Summary ────────────────────────────────────────────────────────────────────

$fast  = ($results | Where-Object { $_.MsPerOp -le $WarnThresholdMs }).Count
$warn  = ($results | Where-Object { $_.MsPerOp -gt $WarnThresholdMs -and $_.MsPerOp -le $FailThresholdMs }).Count
$slow  = ($results | Where-Object { $_.MsPerOp -gt $FailThresholdMs }).Count

Write-Host ""
Write-Host "  Summary: " -NoNewline -ForegroundColor White
Write-Host "[OK] $fast fast  " -NoNewline -ForegroundColor Green
Write-Host "[WARN] $warn warn  " -NoNewline -ForegroundColor Yellow
Write-Host "[HIGH] $slow slow"  -ForegroundColor Red
Write-Host ""

if ($slow -gt 0) {
    Write-Host "  [!]  Slow benchmarks (> ${FailThresholdMs}ms): consider optimization." -ForegroundColor Yellow
}

# ── CSV export ─────────────────────────────────────────────────────────────────

if ($OutputCsv) {
    $results | Select-Object Name, MsPerOp, NsPerOp, BPerOp, AllocsOp |
        Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Host "  Saved: Results saved to: $OutputCsv" -ForegroundColor DarkCyan
}
