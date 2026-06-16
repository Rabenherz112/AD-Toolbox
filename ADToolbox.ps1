#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Toolbox - one universal, modular Active Directory troubleshooting toolkit

.DESCRIPTION
    A self-contained diagnostic / action / utility script that collects its own data,
    interpret it (root cause + fix), and emit actionable findings. With no parameters it opens
    an interactive, by-area menu. With parameters it runs unattended (CLI) for reporting.

.EXAMPLE
    .\ADToolbox.ps1
    Runs the interactive menu

.EXAMPLE
    .\ADToolbox.ps1 -FullTest -Format Html
    Run the full health check and write an HTML report.

.NOTES
    Exit codes:  0 OK/Info  |  1 Low/Medium  |  2 High/Critical  |  3 engine error
#>
[CmdletBinding()]
param(
    [switch]$FullTest,
    [string[]]$Run,
    [string[]]$Area,
    [switch]$List,
    [switch]$ReadOnly,

    [string]$Server,
    [string]$Domain,
    [switch]$Forest,
    [System.Management.Automation.PSCredential]$Credential,
    [System.Management.Automation.PSCredential]$TestCredential,

    [switch]$SaveRun,
    [string]$CompareTo,

    [ValidateSet('Console','Html','Json','Csv')]
    [string]$Format = 'Console',
    [string]$OutputPath,
    [switch]$Quiet,

    [switch]$WhatIf,
    [switch]$Force,
    [switch]$IUnderstand,
    [switch]$NoConfirm
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

#region Initialization

# Load engine
Get-ChildItem -Path (Join-Path $root 'lib') -Filter '*.ps1' -File | ForEach-Object { . $_.FullName }

# Load config
$config = $null
$cfgPath = Join-Path $root 'config\settings.json'
try { if (Test-Path $cfgPath) { $config = Get-Content $cfgPath -Raw | ConvertFrom-Json } } catch { }
if (-not $config) { $config = [pscustomobject]@{} }

if (-not $OutputPath) {
    $OutputPath = if ($config.PSObject.Properties['OutputPath'] -and $config.OutputPath) {
        $p = $config.OutputPath
        if ($p -like '.*') { Join-Path $root ($p -replace '^[./\\]+','') } else { $p }
    } else { Join-Path $root 'output' }
}

# Initialize logging
Initialize-ADTLog -OutputPath $OutputPath -Quiet:$Quiet | Out-Null
Write-ADTLog -Level Info -Message "AD-Toolbox starting (PS $($PSVersionTable.PSVersion))"

# Probe tooling
$tools = Get-ADTTools
Write-ADTLog -Level Debug -Message "Tooling available: $(($tools.Keys -join ', '))"

# Get context of the domain
$ctx = Initialize-ADTContext -Config $config -Tools $tools -Server $Server -Domain $Domain `
        -Credential $Credential -TestCredential $TestCredential -ScanForest:$Forest -WhatIf:$WhatIf
if ($ctx.ScanForest) { Write-ADTLog -Level Info -Message "Forest scan: $(@($ctx.Domains).Count) domain(s), $(@($ctx.DomainControllers).Count) DC(s)." }

#endregion Initialization
#region Main Execution

# Require a usable AD domain context
# Everything below this point cannot work without a domain context, so continuing would be pointless
if (-not $ctx.Domain) {
    Write-ADTLog -Level Error -Message 'No Active Directory domain context could be established.'
    if (-not $tools['DomainJoined']) {
        Write-ADTLog -Level Error -Message 'This device is not joined to an AD domain. Run AD-Toolbox on a domain controller, or on a domain-joined admin workstation with RSAT installed.'
    } else {
        Write-ADTLog -Level Error -Message "This device is domain-joined but a DC/AD context could not be reached$(if ($ctx.DiscoveryError) { ": $($ctx.DiscoveryError)" } else { '.' })"
        Write-ADTLog -Level Error -Message 'Check connectivity/DNS to a domain controller, or pass -Server/-Domain (and -Credential if needed).'
    }
    exit 3
}

# ToDo: First check CLI, if not CLI build an interactive menu

#endregion Main Execution
