#Requires -Version 5.1
<#
    Report.ps1 - Render findings to console / HTML / JSON / CSV

    Cross-DC views (the per-DC scorecard) are rebuilt here by grouping findings by Target,
    the flat modules just emit findings and the report reconstructs the big picture
#>

$script:ADTSeverityColor = @{
    'Critical'='Red';
    'High'='Red';
    'Medium'='Yellow';
    'Low'='DarkYellow';
    'Info'='Cyan';
    'OK'='Green';
    'Error'='Magenta';
}

function Write-ADTConsoleReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Findings, $Context, $Drift)

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkGray
    Write-Host "  AD-Toolbox Report" -ForegroundColor White
    if ($Context) { Write-Host "  Forest: $($Context.Forest)   Domain: $($Context.Domain)" -ForegroundColor Gray }
    Write-Host ("  {0}    Findings: {1}" -f (Get-Date), @($Findings).Count) -ForegroundColor Gray
    Write-Host ("=" * 70) -ForegroundColor DarkGray

    # Severity tally
    Write-Host "`n  Severity summary:" -ForegroundColor White
    foreach ($sev in 'Critical','High','Medium','Low','Info','OK','Error') {
        $n = @($Findings | Where-Object Severity -eq $sev).Count
        if ($n -gt 0) { Write-Host ("    {0,-9} {1}" -f $sev, $n) -ForegroundColor $script:ADTSeverityColor[$sev] }
    }

    # Per-DC scorecard
    $cards = Get-ADTScorecard -Findings $Findings
    if ($cards) {
        Write-Host "`n  Per-target scorecard:" -ForegroundColor White
        Write-Host ("    {0,-24} {1,-9} {2,5} {3,5} {4,5} {5,5}" -f 'Target','Status','Crit','High','Med','Low') -ForegroundColor DarkGray
        foreach ($c in $cards) {
            Write-Host ("    {0,-24} {1,-9} {2,5} {3,5} {4,5} {5,5}" -f $c.Target,$c.Status,$c.Critical,$c.High,$c.Medium,$c.Low) -ForegroundColor $script:ADTSeverityColor[$c.Status]
        }
    }

    # Actionable findings (anything worse than Info), grouped by area
    $actionable = $Findings | Where-Object { $_.Rank -ge 2 } | Sort-Object -Property @{Expression='Rank';Descending=$true}, Area
    if ($actionable) {
        Write-Host "`n  Findings:" -ForegroundColor White
        foreach ($f in $actionable) {
            Write-Host ("`n  [{0}] {1}  ({2} / {3})" -f $f.Severity, $f.Title, $f.Area, $f.Target) -ForegroundColor $script:ADTSeverityColor[$f.Severity]
            if ($f.RootCause)   { Write-Host "      Cause: $($f.RootCause)" -ForegroundColor Gray }
            if ($f.Impact)      { Write-Host "      Impact: $($f.Impact)" -ForegroundColor Gray }
            if ($f.Remediation) {
                $fix = if ($f.Remediation.Text) { $f.Remediation.Text } else { $f.Remediation }
                Write-Host "      Fix: $fix" -ForegroundColor Green
                if ($f.Remediation.ActionId) { Write-Host "      -> Remediation action: $($f.Remediation.ActionId)" -ForegroundColor Green }
            }
        }
    } else {
        Write-Host "`n  No actionable findings. Healthy." -ForegroundColor Green
    }

    if ($Drift) { Write-ADTConsoleDrift -Drift $Drift }
    Write-Host ""
}

function Write-ADTConsoleDrift {
    param($Drift)
    Write-Host "`n  Drift vs baseline ($($Drift.BaselineTime)):" -ForegroundColor White
    Write-Host ("    New: {0}   Resolved: {1}   Changed: {2}" -f @($Drift.Added).Count, @($Drift.Resolved).Count, @($Drift.Changed).Count) -ForegroundColor Gray
    foreach ($a in $Drift.Added)    { Write-Host "    + NEW      [$($a.Severity)] $($a.Title) ($($a.Target))" -ForegroundColor Yellow }
    foreach ($r in $Drift.Resolved) { Write-Host "    - RESOLVED  [$($r.Severity)] $($r.Title) ($($r.Target))" -ForegroundColor Green }
    foreach ($c in $Drift.Changed)  { Write-Host "    ~ CHANGED   $($c.Title) ($($c.Target)): $($c.From) -> $($c.To)" -ForegroundColor Cyan }
}

function Export-ADTReport {
    # Dispatch to the right emitter; returns the output file path (or $null for console)
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Findings,
        $Context,
        $Drift,
        [ValidateSet('Console','Html','Json','Csv')][string]$Format = 'Console',
        [string]$OutputPath = (Join-Path $PSScriptRoot '..\output')
    )
    if ($Format -eq 'Console') { Write-ADTConsoleReport -Findings $Findings -Context $Context -Drift $Drift; return $null }

    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $file  = Join-Path $OutputPath ("ADToolbox-report-$stamp." + $Format.ToLower())

    switch ($Format) {
        'Json' { $Findings | ConvertTo-Json -Depth 6 | Set-Content -Path $file -Encoding UTF8 }
        'Csv'  {
            $Findings | Select-Object Severity,Area,Target,Title,RootCause,Impact,
                @{N='Fix';E={ if ($_.Remediation.Text) { $_.Remediation.Text } else { $_.Remediation } }},
                @{N='ActionId';E={ $_.Remediation.ActionId }},Source,Timestamp |
                Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
        }
        'Html' { (Get-ADTHtmlReport -Findings $Findings -Context $Context -Drift $Drift) | Set-Content -Path $file -Encoding UTF8 }
    }
    Write-ADTLog -Level Success -Message "Report written: $file"
    return $file
}

function Get-ADTHtmlReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Findings, $Context, $Drift)

    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $cards = Get-ADTScorecard -Findings $Findings
    $counts = @{}
    foreach ($sev in 'Critical','High','Medium','Low','Info','OK','Error') {
        $counts[$sev] = @($Findings | Where-Object Severity -eq $sev).Count
    }
    $worst = Get-ADTWorstSeverity -Findings $Findings

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8"><title>AD-Toolbox Report</title>')
    [void]$sb.AppendLine(@'
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}
 .wrap{max-width:1100px;margin:0 auto;padding:24px}
 h1{font-size:22px;margin:0 0 4px} .sub{color:#9aa4ad;font-size:13px;margin-bottom:18px}
 .pills span{display:inline-block;padding:6px 12px;border-radius:14px;margin:3px;font-size:13px;font-weight:600}
 .Critical,.High{background:#5a1a1a;color:#ff8a8a} .Medium{background:#5a4a14;color:#ffd479}
 .Low{background:#4a4214;color:#e8d488} .Info{background:#14405a;color:#8ad4ff}
 .OK{background:#1a4a2a;color:#8affb0} .Error{background:#4a1a4a;color:#ff8aff}
 table{border-collapse:collapse;width:100%;margin:10px 0;font-size:13px}
 th,td{border:1px solid #2a323a;padding:6px 8px;text-align:left} th{background:#1a2129}
 .card{border:1px solid #2a323a;border-radius:8px;padding:12px 14px;margin:10px 0;background:#151b22}
 .card .t{font-weight:600;font-size:14px} .card .meta{color:#9aa4ad;font-size:12px;margin:2px 0 8px}
 .card .lbl{color:#9aa4ad;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
 .badge{font-size:11px;padding:2px 8px;border-radius:10px;font-weight:700}
 h2{font-size:16px;border-bottom:1px solid #2a323a;padding-bottom:6px;margin-top:28px}
 code{background:#0b0f14;padding:1px 5px;border-radius:4px}
</style></head><body><div class="wrap">
'@)
    [void]$sb.AppendLine('<h1>AD-Toolbox Report</h1>')
    [void]$sb.AppendLine("<div class='sub'>Forest: <b>$(& $enc $Context.Forest)</b> &nbsp; Domain: <b>$(& $enc $Context.Domain)</b> &nbsp; Generated: $(Get-Date) &nbsp; Overall: <span class='badge $worst'>$worst</span></div>")

    [void]$sb.AppendLine('<div class="pills">')
    foreach ($sev in 'Critical','High','Medium','Low','Info','OK','Error') {
        if ($counts[$sev] -gt 0) { [void]$sb.AppendLine("<span class='$sev'>${sev}: $($counts[$sev])</span>") }
    }
    [void]$sb.AppendLine('</div>')

    # Scorecard
    if ($cards) {
        [void]$sb.AppendLine('<h2>Per-target scorecard</h2><table><tr><th>Target</th><th>Status</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>')
        foreach ($c in $cards) {
            [void]$sb.AppendLine("<tr><td>$(& $enc $c.Target)</td><td><span class='badge $($c.Status)'>$($c.Status)</span></td><td>$($c.Critical)</td><td>$($c.High)</td><td>$($c.Medium)</td><td>$($c.Low)</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    }

    # Drift
    if ($Drift) {
        [void]$sb.AppendLine("<h2>Drift vs baseline ($(& $enc $Drift.BaselineTime))</h2>")
        [void]$sb.AppendLine("<p>New: $(@($Drift.Added).Count) &nbsp; Resolved: $(@($Drift.Resolved).Count) &nbsp; Changed: $(@($Drift.Changed).Count)</p>")
    }

    # Findings grouped by area
    [void]$sb.AppendLine('<h2>Findings</h2>')
    $byArea = $Findings | Where-Object { $_.Rank -ge 1 } | Group-Object Area | Sort-Object Name
    if (-not $byArea) { [void]$sb.AppendLine('<p class="OK">No actionable findings.</p>') }
    foreach ($g in $byArea) {
        [void]$sb.AppendLine("<h3>$(& $enc $g.Name)</h3>")
        foreach ($f in ($g.Group | Sort-Object -Property @{Expression='Rank';Descending=$true})) {
            [void]$sb.AppendLine('<div class="card">')
            [void]$sb.AppendLine("<div class='t'><span class='badge $($f.Severity)'>$($f.Severity)</span> $(& $enc $f.Title)</div>")
            [void]$sb.AppendLine("<div class='meta'>Target: $(& $enc $f.Target) &middot; Source: $(& $enc $f.Source)</div>")
            if ($f.RootCause) { [void]$sb.AppendLine("<div class='lbl'>Root cause</div><div>$(& $enc $f.RootCause)</div>") }
            if ($f.Impact)    { [void]$sb.AppendLine("<div class='lbl'>Impact</div><div>$(& $enc $f.Impact)</div>") }
            if ($f.Remediation) {
                $fix = if ($f.Remediation.Text) { $f.Remediation.Text } else { $f.Remediation }
                [void]$sb.AppendLine("<div class='lbl'>Remediation</div><div>$(& $enc $fix)")
                if ($f.Remediation.ActionId) { [void]$sb.AppendLine(" &nbsp;<code>action: $(& $enc $f.Remediation.ActionId)</code>") }
                if ($f.Remediation.Reference) { [void]$sb.AppendLine(" &nbsp;<a href='$(& $enc $f.Remediation.Reference)' style='color:#8ad4ff'>ref</a>") }
                [void]$sb.AppendLine('</div>')
            }
            [void]$sb.AppendLine('</div>')
        }
    }

    [void]$sb.AppendLine('</div></body></html>')
    return $sb.ToString()
}
