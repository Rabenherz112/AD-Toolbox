#Requires -Version 5.1
<#
    Persistence.ps1 - Opt-in run persistence + drift comparison

    A "run" is the set of findings (plus light meta) from one invocation. Saving it as JSON
    lets you later answer "what changed since last run?" (drift / baseline). Default off;
    enabled with -SaveRun, compared with -CompareTo <file>
#>

function Save-ADTRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Findings,
        [Parameter(Mandatory)]$Context,
        [string]$OutputPath = (Join-Path $PSScriptRoot '..\output'),
        [string]$Path
    )
    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null }
    if (-not $Path) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $Path  = Join-Path $OutputPath "run-$stamp.json"
    }

    $doc = [pscustomobject]@{
        Meta = [pscustomobject]@{
            Forest    = $Context.Forest
            Domain    = $Context.Domain
            RunTime   = (Get-Date).ToString('o')
            RunBy     = "$env:USERDOMAIN\$env:USERNAME"
            Host      = $env:COMPUTERNAME
            Worst     = (Get-ADTWorstSeverity -Findings $Findings)
        }
        Findings = @($Findings | Select-Object Id,Source,Severity,Rank,Area,Target,Title,RootCause,Impact)
    }
    $doc | ConvertTo-Json -Depth 6 | Set-Content -Path $Path -Encoding UTF8
    Write-ADTLog -Level Success -Message "Run saved: $Path"
    return $Path
}

function Import-ADTRun {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "Run file not found: $Path" }
    return (Get-Content -Path $Path -Raw | ConvertFrom-Json)
}

function Compare-ADTRun {
    <#
        Diff the current findings against a saved baseline. Key = Source|Target|Title.
        Returns Added (new), Resolved (gone), and Changed (severity differs)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Current,
        [Parameter(Mandatory)][string]$BaselinePath
    )
    $base = Import-ADTRun -Path $BaselinePath

    $key = { param($f) "$($f.Source)|$($f.Target)|$($f.Title)" }
    $baseMap = @{}
    foreach ($b in @($base.Findings)) { $baseMap[(& $key $b)] = $b }
    $curMap = @{}
    foreach ($c in @($Current))       { $curMap[(& $key $c)]  = $c }

    $added = @(); $resolved = @(); $changed = @()
    foreach ($k in $curMap.Keys) {
        if (-not $baseMap.ContainsKey($k)) { $added += $curMap[$k] }
        elseif ($baseMap[$k].Severity -ne $curMap[$k].Severity) {
            $changed += [pscustomobject]@{ Title=$curMap[$k].Title; Target=$curMap[$k].Target; From=$baseMap[$k].Severity; To=$curMap[$k].Severity }
        }
    }
    foreach ($k in $baseMap.Keys) {
        if (-not $curMap.ContainsKey($k)) { $resolved += $baseMap[$k] }
    }

    [pscustomobject]@{
        BaselineTime = $base.Meta.RunTime
        Added        = $added
        Resolved     = $resolved
        Changed      = $changed
    }
}
