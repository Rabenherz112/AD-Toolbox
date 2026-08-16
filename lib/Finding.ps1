#Requires -Version 5.1
<#
    Finding.ps1 - The actionable unit produced by every diagnostic

    A Finding is richer than pass/fail: it carries a Severity, the affected Target,
    the interpreted RootCause, the Impact, and a concrete Remediation (optionally a
    one-click linked Action). Modules emit 0..n findings, including 'OK' findings so
    reports can show "checked & healthy" coverage
#>

# Severity ranking: higher = worse. Used for "worst wins" rollups and exit codes
$script:ADTSeverityRank = [ordered]@{
    'OK'       = 0
    'Info'     = 1
    'Low'      = 2
    'Medium'   = 3
    'High'     = 4
    'Critical' = 5
    'Error'    = 6
}

function Get-ADTSeverityRank {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Severity
    )

    if ($script:ADTSeverityRank.Contains($Severity)){
        return [int]$script:ADTSeverityRank[$Severity]
    }
    return 1
}

function New-ADTFinding {
    <#
        .SYNOPSIS
        Build a normalized Finding object. Call this from a diagnostic's Run block
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Critical','High','Medium','Low','Info','OK','Error')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Title,
        [string]$Area = 'General',
        # The DC / site / domain / object the finding is about. Drives the per-DC scorecard
        [string]$Target = 'Domain',
        # Raw data/lines that prove the finding (objects or strings)
        $Evidence,
        # Plain-English interpreted cause (usually from Get-ADTKnowledge)
        [string]$RootCause,
        # What breaks because of this
        [string]$Impact,
        # Hashtable @{Text;ActionId;Manual;Reference} or a plain string
        $Remediation,

        # Stable id for this finding type (defaults to a slug of the title)
        [string]$Id,
        # The module id that emitted it (set by the engine if omitted)
        [string]$Source
    )

    if (-not $Id) {
        $Id = ($Title -replace '[^A-Za-z0-9]+','-').Trim('-').ToLower()
    }

    # Normalize remediation to a consistent shape.
    $rem = $null
    if ($Remediation -is [string]) {
        $rem = [pscustomobject]@{ Text = $Remediation; ActionId = $null; Manual = $null; Reference = $null }
    }
    elseif ($Remediation -is [hashtable] -or $Remediation -is [System.Collections.IDictionary]) {
        $rem = [pscustomobject]@{
            Text      = $Remediation['Text']
            ActionId  = $Remediation['ActionId']
            Manual    = $Remediation['Manual']
            Reference = $Remediation['Reference']
        }
    }
    elseif ($Remediation) {
        $rem = $Remediation
    }

    [pscustomobject]@{
        PSTypeName  = 'ADT.Finding'
        Id          = $Id
        Source      = $Source
        Severity    = $Severity
        Rank        = (Get-ADTSeverityRank -Severity $Severity)
        Area        = $Area
        Target      = $Target
        Title       = $Title
        Evidence    = $Evidence
        RootCause   = $RootCause
        Impact      = $Impact
        Remediation = $rem
        Timestamp   = (Get-Date)
    }
}

function Get-ADTWorstSeverity {
    <# Return the worst severity string across a set of findings. #>
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Findings)
    begin { $worst = -1; $name = 'OK' }
    process {
        foreach ($f in $Findings) {
            if ($null -eq $f) { continue }
            $r = if ($f.PSObject.Properties['Rank']) { [int]$f.Rank } else { Get-ADTSeverityRank -Severity $f.Severity }
            if ($r -gt $worst) { $worst = $r; $name = $f.Severity }
        }
    }
    end { if ($worst -lt 0) { 'OK' } else { $name } }
}

function Get-ADTExitCode {
    <# Map the worst finding severity to a process exit code for unattended use. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Findings)
    $rank = (Get-ADTSeverityRank -Severity (Get-ADTWorstSeverity -Findings $Findings))
    switch ($rank) {
        { $_ -le 1 } { return 0 }   # OK / Info
        { $_ -le 3 } { return 1 }   # Low / Medium
        { $_ -le 5 } { return 2 }   # High / Critical
        default      { return 3 }   # Error
    }
}

function Get-ADTScorecard {
    <#
        Rebuild the cross-DC view at report time by grouping findings by Target.
        Returns one row per target with its worst severity and a severity breakdown
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Findings)

    $Findings | Group-Object -Property Target | ForEach-Object {
        $items = $_.Group
        [pscustomobject]@{
            Target   = $_.Name
            Status   = (Get-ADTWorstSeverity -Findings $items)
            Critical = @($items | Where-Object Severity -eq 'Critical').Count
            High     = @($items | Where-Object Severity -eq 'High').Count
            Medium   = @($items | Where-Object Severity -eq 'Medium').Count
            Low      = @($items | Where-Object Severity -eq 'Low').Count
            Issues   = @($items | Where-Object { $_.Rank -ge 2 }).Count
            Findings = $items
        }
    } | Sort-Object -Property @{ Expression = { Get-ADTSeverityRank -Severity $_.Status }; Descending = $true }, Target
}
