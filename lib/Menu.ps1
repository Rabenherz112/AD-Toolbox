#Requires -Version 5.1
<#
    Menu.ps1 - Interactive menu navigation

    Main menu lists diagnostic Areas (from the registry) plus Utilities, Actions/Maintenance,
    Full health check, Drift, last report, settings, quit. After any run, the console report
    is shown and the user can export it or jump to a finding's linked remediation Action
#>

function Show-ADTMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Registry,
        [string]$OutputPath
    )

    $script:ADTLastFindings = @()
    $diagnostics = $Registry | Where-Object Kind -eq 'Diagnostic'
    $areas = @($diagnostics | Select-Object -ExpandProperty Area -Unique | Sort-Object)

    while ($true) {
        Clear-Host
        Write-Host ""
        Write-Host "  +----------------------------------------------------------+" -ForegroundColor Cyan
        Write-Host "  |                  A D - T O O L B O X                     |" -ForegroundColor Cyan
        Write-Host "  |          Universal AD Troubleshooting Toolkit            |" -ForegroundColor Cyan
        Write-Host "  +----------------------------------------------------------+" -ForegroundColor Cyan
        Write-Host ("   Forest: {0}   Domain: {1}" -f $Context.Forest, $Context.Domain) -ForegroundColor DarkGray
        if ($Context.DiscoveryError) {
            Write-Host "   (limited context: $($Context.DiscoveryError))" -ForegroundColor Yellow
        }
        Write-Host ("   DCs discovered: {0}   Discovery: {1}" -f @($Context.DomainControllers).Count, $Context.DiscoveryMethod) -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "   Diagnostic areas:" -ForegroundColor White
        for ($i=0; $i -lt $areas.Count; $i++) {
            $n = @($diagnostics | Where-Object Area -eq $areas[$i]).Count
            Write-Host ("     {0,2}. {1,-20} ({2} checks)" -f ($i+1), $areas[$i], $n) -ForegroundColor Gray
        }
        Write-Host ""
        Write-Host "     F. Full health check (all diagnostics)" -ForegroundColor Green
        Write-Host "     U. Utilities (interactive tools)" -ForegroundColor Cyan
        Write-Host "     A. Actions / Maintenance (make changes)" -ForegroundColor Yellow
        Write-Host "     D. Drift vs a saved baseline" -ForegroundColor Cyan
        Write-Host "     R. Re-show last report" -ForegroundColor Gray
        Write-Host "     L. List all modules" -ForegroundColor Gray
        Write-Host "     Q. Quit" -ForegroundColor Gray
        Write-Host ""
        $choice = (Read-Host "   Select").Trim()

        switch -Regex ($choice) {
            '^[Qq]$' { return }
            '^[Ff]$' {
                $mods = Select-ADTFullTestModules -Registry $Registry
                Invoke-ADTMenuRun -Modules $mods -Context $Context -Registry $Registry -OutputPath $OutputPath -Interactive
            }
            '^[Uu]$' { Show-ADTKindMenu -Kind 'Utility'  -Context $Context -Registry $Registry -OutputPath $OutputPath }
            '^[Aa]$' { Show-ADTKindMenu -Kind 'Action'   -Context $Context -Registry $Registry -OutputPath $OutputPath }
            '^[Rr]$' {
                if (@($script:ADTLastFindings).Count) {
                    Write-ADTConsoleReport -Findings $script:ADTLastFindings -Context $Context
                    Pause-ADT
                }
                else {
                    Write-Host "   No report yet." -ForegroundColor Yellow
                    Start-Sleep 1
                }
            }
            '^[Ll]$' { Show-ADTModuleList -Registry $Registry; Pause-ADT }
            '^[Dd]$' {
                $p = Read-Host "   Path to baseline run JSON"
                if (Test-Path $p) {
                    $mods = Select-ADTFullTestModules -Registry $Registry
                    Invoke-ADTMenuRun -Modules $mods -Context $Context -Registry $Registry -OutputPath $OutputPath -Interactive -BaselinePath $p
                } else {
                    Write-Host "   File not found." -ForegroundColor Yellow
                    Start-Sleep 1
                }
            }
            '^\d+$' {
                $idx = [int]$choice - 1
                if ($idx -ge 0 -and $idx -lt $areas.Count) {
                    Show-ADTAreaMenu -Area $areas[$idx] -Context $Context -Registry $Registry -OutputPath $OutputPath
                }
            }
            default { }
        }
    }
}

function Show-ADTAreaMenu {
    param(
        [string]$Area,
        $Context,
        $Registry,
        [string]$OutputPath
    )
    $mods = @($Registry | Where-Object { $_.Kind -eq 'Diagnostic' -and $_.Area -eq $Area } | Sort-Object Name)
    while ($true) {
        Clear-Host
        Write-Host "`n   $Area diagnostics:`n" -ForegroundColor White
        for ($i=0; $i -lt $mods.Count; $i++) {
            Write-Host ("     {0,2}. {1}" -f ($i+1), $mods[$i].Name) -ForegroundColor Gray
            if ($mods[$i].Synopsis) {
                Write-Host ("         {0}" -f $mods[$i].Synopsis) -ForegroundColor DarkGray
            }
        }
        Write-Host "`n     *. Run all in this area    B. Back`n" -ForegroundColor DarkGray
        $sel = (Read-Host "   Select (e.g. 1,3 or *)").Trim()
        if ($sel -match '^[Bb]$') { return }
        $chosen = Resolve-ADTSelection -Selection $sel -Modules $mods
        if ($chosen) { Invoke-ADTMenuRun -Modules $chosen -Context $Context -Registry $Registry -OutputPath $OutputPath -Interactive }
    }
}

function Show-ADTKindMenu {
    param(
        [string]$Kind,
        $Context,
        $Registry,
        [string]$OutputPath
    )
    $mods = @($Registry | Where-Object Kind -eq $Kind | Sort-Object Area, Name)
    while ($true) {
        Clear-Host
        Write-Host "`n   $Kind`s:`n" -ForegroundColor White
        for ($i=0; $i -lt $mods.Count; $i++) {
            $risk = if ($mods[$i].RiskLevel -ne 'ReadOnly') {
                " [$($mods[$i].RiskLevel)]"
            } else { '' }
            $col  = if ($mods[$i].RiskLevel -eq 'HighRisk') {'Red' } elseif ($mods[$i].RiskLevel -eq 'Disruptive') { 'Yellow' } else { 'Gray' }
            Write-Host ("     {0,2}. {1,-14} {2}{3}" -f ($i+1), $mods[$i].Area, $mods[$i].Name, $risk) -ForegroundColor $col
            if ($mods[$i].Synopsis) { Write-Host ("         {0}" -f $mods[$i].Synopsis) -ForegroundColor DarkGray }
        }
        Write-Host "`n     B. Back`n" -ForegroundColor DarkGray
        $sel = (Read-Host "   Select").Trim()
        if ($sel -match '^[Bb]$') { return }
        $chosen = Resolve-ADTSelection -Selection $sel -Modules $mods
        if ($chosen) {
            Invoke-ADTMenuRun -Modules $chosen -Context $Context -Registry $Registry -OutputPath $OutputPath -Interactive
        }
    }
}

function Resolve-ADTSelection {
    param(
        [string]$Selection,
        $Modules
    )
    if ($Selection -match '^\*$') { return $Modules }
    $out = @()
    foreach ($tok in ($Selection -split '[,\s]+' | Where-Object { $_ })) {
        if ($tok -match '^\d+$') {
            $i = [int]$tok - 1
            if ($i -ge 0 -and $i -lt $Modules.Count) { $out += $Modules[$i] }
        }
    }
    return $out
}

function Invoke-ADTMenuRun {
    param(
        $Modules,
        $Context,
        $Registry,
        [string]$OutputPath,
        [switch]$Interactive,
        [string]$BaselinePath
    )
    if (-not $Modules -or @($Modules).Count -eq 0) {
        Write-Host "   Nothing selected." -ForegroundColor Yellow
        Start-Sleep 1
        return
    }

    Write-Host "`n   Running $(@($Modules).Count) module(s)...`n" -ForegroundColor Cyan
    $findings = Invoke-ADTModules -Modules $Modules -Context $Context -Interactive:$Interactive
    $script:ADTLastFindings = $findings

    $drift = $null
    if ($BaselinePath) {
        try {
            $drift = Compare-ADTRun -Current $findings -BaselinePath $BaselinePath
        } catch {
            Write-Host "   Drift compare failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-ADTConsoleReport -Findings $findings -Context $Context -Drift $drift #TODO: We should create a report; To be implemented

    # Offer linked remediation modules (an ActionId may point to an Action OR a guided Utility)
    $remActions = @($findings | Where-Object { $_.Remediation.ActionId } | Select-Object -ExpandProperty Remediation | Select-Object -ExpandProperty ActionId -Unique)
    if ($remActions) {
        Write-Host "   Suggested remediation modules: $($remActions -join ', ')" -ForegroundColor Green
        if (Read-ADTYesNo "   Run a remediation module now?") {
            $aid = (Read-Host "   Module id").Trim()
            $act = $Registry | Where-Object { $_.Kind -in 'Action','Utility' -and $_.Id -eq $aid } | Select-Object -First 1
            if ($act) {
                $tgt = Read-Host "   Target (DC/empty for domain)"
                $r = Invoke-ADTModule -Module $act -Context $Context -Target $tgt -Interactive
                Write-ADTConsoleReport -Findings $r -Context $Context
            } else {
                Write-Host "   No such action." -ForegroundColor Yellow
            }
        }
    }

    if (Read-ADTYesNo "   Export this report to HTML?") {
        $f = Export-ADTReport -Findings $findings -Context $Context -Drift $drift -Format Html -OutputPath $OutputPath
        if ($f) { Write-Host "   Saved: $f" -ForegroundColor Green }
    }
    Pause-ADT
}

function Show-ADTModuleList {
    param($Registry)
    Clear-Host
    $Registry | Sort-Object Kind, Area, Id |
        Format-Table @{N='Kind';E={$_.Kind}}, @{N='Id';E={$_.Id}}, @{N='Area';E={$_.Area}}, @{N='Risk';E={$_.RiskLevel}}, @{N='FullTest';E={$_.IncludeInFullTest}} -AutoSize |
        Out-Host
}

function Pause-ADT { Write-Host ""; Read-Host "   Press Enter to continue" | Out-Null }
