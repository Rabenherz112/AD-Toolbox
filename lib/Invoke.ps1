#Requires -Version 5.1
<#
    Invoke.ps1 - The module runner

    Runs a single module isolated in try/catch (one bad module never aborts a run), tags the
    findings it returns with the module id, and enforces prerequisites. Also provides the
    Full-Test selector and a generic "run these modules" aggregator
#>

function Invoke-ADTModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Module,
        [Parameter(Mandatory)]$Context,
        $Target,
        [switch]$Interactive,
        [switch]$Force,
        [switch]$IUnderstand,
        [switch]$ConfirmDisabled
    )

    Write-ADTLog -Level Info -Message "Running [$($Module.Kind)] $($Module.Id) - $($Module.Name)"

    # Prerequisite check -> emit an informational finding instead of failing hard
    if (-not (Test-ADTRequires -Requires $Module.Requires -Tools $Context.Tools)) {
        $missing = @($Module.Requires | Where-Object { -not $Context.Tools[$_] }) -join ', '
        return (New-ADTFinding -Severity Info -Area $Module.Area -Target 'Toolkit' -Source $Module.Id `
                -Title "$($Module.Name) skipped (missing prerequisite: $missing)" `
                -RootCause "Required tooling not present on this host: $missing" `
                -Remediation "Install RSAT / the required feature, or run from a host that has it.")
    }

    # Load any required PowerShell (RSAT) modules centrally, so individual modules never need to Import-Module themselves. Availability was just verified by Test-ADTRequires above; PowerShell would also auto-load on first cmdlet use
    foreach ($req in @($Module.Requires)) {
        if ($req -in @('ActiveDirectory','DnsServer','GroupPolicy') -and -not (Get-Module -Name $req)) {
            try { Import-Module $req -ErrorAction Stop } catch { }
        }
    }

    # A writing diagnostic (e.g. the replication canary) gets a confirmation when run interactively. Unattended -FullTest is opt-in by design (use -ReadOnly to exclude)
    if ($Module.Kind -ne 'Action' -and $Module.Writes -and $Interactive -and -not $Context.WhatIf) {
        if (-not (Read-ADTYesNo "  '$($Module.Name)' writes a transient object to AD. Proceed?" -DefaultYes)) {
            return (New-ADTFinding -Severity Info -Area $Module.Area -Target 'Toolkit' -Source $Module.Id `
                    -Title "$($Module.Name) skipped (write declined)")
        }
    }

    # Actions pass through the risk-tier confirmation gate
    if ($Module.Kind -eq 'Action') {
        $ok = Confirm-ADTAction -Module $Module -Target ([string]($Target | Select-Object -First 1)) `
                -Interactive:$Interactive -Force:$Force -IUnderstand:$IUnderstand `
                -ConfirmDisabled:$ConfirmDisabled -WhatIf:$Context.WhatIf
        if (-not $ok) {
            return (New-ADTFinding -Severity Info -Area $Module.Area -Target 'Toolkit' -Source $Module.Id `
                    -Title "$($Module.Name) not run (confirmation declined)" `
                    -RootCause 'The action was not confirmed.')
        }
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        # Run modules with EAP=Continue (function-scoped). The entry script uses 'Stop' for its own setup, but under 'Stop' a native tool writing to stderr (repadmin/dcdiag/nltest/w32tm/setspn ...) raises a terminating NativeCommandError in PS 5.1 (which would falsely fail a module). Modules still opt into try/catch via explicit -ErrorAction Stop, and the engine's catch below still handles real exceptions
        $ErrorActionPreference = 'Continue'
        $raw = if ($PSBoundParameters.ContainsKey('Target') -and $null -ne $Target) {
            & $Module.Run $Context $Target
        } else {
            & $Module.Run $Context
        }
    }
    catch {
        $sw.Stop()
        Write-ADTLog -Level Error -Message "Module '$($Module.Id)' threw: $($_.Exception.Message)"
        return (New-ADTFinding -Severity Error -Area $Module.Area -Target 'Toolkit' -Source $Module.Id `
                -Title "$($Module.Name) failed to run" `
                -RootCause $_.Exception.Message `
                -Evidence ($_.ScriptStackTrace) `
                -Remediation 'This is a toolkit/module error, not necessarily an AD problem. Review the stack trace.')
    }
    $sw.Stop()

    # Normalize output to ADT.Finding[]; tag Source; ignore non-findings
    $findings = @()
    foreach ($item in @($raw)) {
        if ($null -eq $item) { continue }
        if ($item.PSObject.TypeNames -contains 'ADT.Finding') {
            if (-not $item.Source) { $item.Source = $Module.Id }
            $findings += $item
        }
    }
    Write-ADTLog -Level Debug -Message "  -> $($findings.Count) finding(s) in $([int]$sw.Elapsed.TotalMilliseconds) ms"
    return $findings
}

function Select-ADTFullTestModules {
    # The Full-Test set: diagnostics flagged IncludeInFullTest, optionally read-only
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Registry, [switch]$ReadOnly)
    $set = $Registry | Where-Object { $_.Kind -eq 'Diagnostic' -and $_.IncludeInFullTest }
    if ($ReadOnly) { $set = $set | Where-Object { -not $_.Writes } }
    return $set
}

function Invoke-ADTModules {
    # Run a set of modules and return all aggregated findings
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Modules,
        [Parameter(Mandatory)]$Context,
        [switch]$Interactive,
        [switch]$Force,
        [switch]$IUnderstand,
        [switch]$ConfirmDisabled
    )
    $all = @()
    foreach ($m in $Modules) {
        $all += Invoke-ADTModule -Module $m -Context $Context `
                    -Interactive:$Interactive -Force:$Force -IUnderstand:$IUnderstand -ConfirmDisabled:$ConfirmDisabled
    }
    return $all
}
