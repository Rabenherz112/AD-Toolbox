#Requires -Version 5.1
<#
    Runner.ps1 - Concurrency and remote-execution helpers (PowerShell 5.1 compatible).
#>

function Invoke-ADTRemote {
    <#
        .SYNOPSIS
        Run a scriptblock ON each target over PowerShell remoting, one result row per target

        .DESCRIPTION
        Returns one row per requested computer, in the order requested:
            ComputerName - the target as it was passed in
            Success      - did the scriptblock run and return something
            Result       - whatever the scriptblock returned (deserialized)
            Error        - why it did not, when Success is false

        A target that refuses remoting is a ROW, not a silent omission: callers report it as an
        unchecked target rather than mistaking it for a clean result
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$ComputerName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @(),
        [int]$OpenTimeoutMs = 15000,
        [int]$OperationTimeoutMs = 90000
    )

    $targets = @($ComputerName | Where-Object { $_ })
    if ($targets.Count -eq 0) { return @() }

    $opt = New-PSSessionOption -OpenTimeout $OpenTimeoutMs -OperationTimeout $OperationTimeoutMs
    $raw = @()
    $errs = @()
    try {
        $raw = @(Invoke-Command -ComputerName $targets -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList `
                    -SessionOption $opt -ErrorAction SilentlyContinue -ErrorVariable errs)
    } catch {
        # Whole-call failure (bad parameters, no WinRM client at all) - every target is unreachable
        $errs = @($_)
    }

    # Remoting connection errors carry the host in TargetObject; anything unattributed is shared
    $errByHost = @{}
    $general   = @()
    foreach ($e in @($errs)) {
        $h = $null
        if ($e.TargetObject -is [string]) { $h = $e.TargetObject }
        elseif ($e.OriginInfo -and $e.OriginInfo.PSComputerName) { $h = [string]$e.OriginInfo.PSComputerName }
        if ($h) { $errByHost[$h] = $e.Exception.Message } else { $general += $e.Exception.Message }
    }

    $byHost = @{}
    foreach ($r in $raw) { if ($r.PSComputerName) { $byHost[[string]$r.PSComputerName] = $r } }

    $out = @()
    foreach ($t in $targets) {
        if ($byHost.ContainsKey($t)) {
            $out += [pscustomobject]@{ ComputerName = $t; Success = $true; Result = $byHost[$t]; Error = $null }
        } else {
            $msg = if ($errByHost.ContainsKey($t)) { $errByHost[$t] }
                    elseif ($general.Count -gt 0)   { $general -join '; ' }
                    else                            { 'No result was returned and no error was reported.' }
            $out += [pscustomobject]@{ ComputerName = $t; Success = $false; Result = $null; Error = $msg }
        }
    }
    return $out
}

function Invoke-ADTParallel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Items,
        [Parameter(Mandatory)][scriptblock]$Script,
        [int]$Throttle = 8,
        # Extra arguments appended after the item on every invocation.
        [object[]]$Arguments = @(),
        [int]$TimeoutSeconds = 120
    )

    if (-not $Items -or $Items.Count -eq 0) { return @() }
    if ($Throttle -lt 1) { $Throttle = 1 }

    # Single item or throttle 1 -> run inline (easier to debug, no pool overhead).
    if ($Items.Count -eq 1 -or $Throttle -eq 1) {
        $out = @()
        foreach ($it in $Items) {
            try { $out += & $Script $it @Arguments }
            catch { $out += [pscustomobject]@{ ADTItem = $it; ADTError = $_.Exception.Message } }
        }
        return $out
    }

    $pool = [runspacefactory]::CreateRunspacePool(1, $Throttle)
    $pool.ApartmentState = 'MTA'
    $pool.Open()
    $jobs = @()

    try {
        foreach ($it in $Items) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($Script.ToString())
            [void]$ps.AddArgument($it)
            foreach ($a in $Arguments) { [void]$ps.AddArgument($a) }
            $jobs += [pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Item = $it }
        }

        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $results = @()
        foreach ($j in $jobs) {
            $remaining = [int]([Math]::Max(0, ($deadline - (Get-Date)).TotalMilliseconds))
            if (-not $j.Handle.AsyncWaitHandle.WaitOne($remaining)) {
                $results += [pscustomobject]@{ ADTItem = $j.Item; ADTError = "Timed out after $TimeoutSeconds s" }
                try { $j.PS.Stop() } catch { }
                $j.PS.Dispose()
                continue
            }
            try { $results += $j.PS.EndInvoke($j.Handle) }
            catch { $results += [pscustomobject]@{ ADTItem = $j.Item; ADTError = $_.Exception.Message } }
            finally { $j.PS.Dispose() }
        }
        return $results
    }
    finally {
        $pool.Close()
        $pool.Dispose()
    }
}
