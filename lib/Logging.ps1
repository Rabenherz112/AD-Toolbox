#Requires -Version 5.1
<#
    Logging.ps1 - Lightweight logging + transcript for the toolkit

    Write-ADTLog writes to the console (unless -Quiet) and appends to a log file under the
    output directory. Levels: Debug, Info, Warn, Error, Success
#>

$script:ADTLogPath = $null
$script:ADTQuiet   = $false

function Initialize-ADTLog {
    [CmdletBinding()]
    param(
        [string]$OutputPath = (Join-Path $PSScriptRoot '..\output'),
        [switch]$Quiet
    )
    $script:ADTQuiet = [bool]$Quiet
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:ADTLogPath = Join-Path $OutputPath "ADToolbox-$stamp.log"
    Write-ADTLog -Level Info -Message "Log started: $script:ADTLogPath"
    return $script:ADTLogPath
}

function Write-ADTLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position=0)][string]$Message,
        [ValidateSet('Debug','Info','Warn','Error','Success')][string]$Level = 'Info'
    )
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level.ToUpper(), $Message

    if ($script:ADTLogPath) {
        try { Add-Content -Path $script:ADTLogPath -Value $line -Encoding UTF8 } catch { }
    }

    if ($script:ADTQuiet -and $Level -in @('Debug','Info','Success')) { return }

    switch ($Level) {
        'Debug'   { Write-Verbose $Message }
        'Info'    { Write-Host $Message -ForegroundColor Gray }
        'Warn'    { Write-Host $Message -ForegroundColor Yellow }
        'Error'   { Write-Host $Message -ForegroundColor Red }
        'Success' { Write-Host $Message -ForegroundColor Green }
    }
}

function Get-ADTLogPath { $script:ADTLogPath }
