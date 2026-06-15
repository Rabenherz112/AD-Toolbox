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

#endregion Initialization

Initialize-ADTLog -OutputPath (Join-Path $root 'output') -Quiet:$Quiet | Out-Null
Write-ADTLog -Level Info -Message "AD-Toolbox starting (PS $($PSVersionTable.PSVersion))"
