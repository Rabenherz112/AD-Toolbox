#Requires -Version 5.1
<#
    Prereqs.ps1 - Probe what tooling is available so modules can degrade gracefully

    Returns a hashtable of capability flags. Modules declare Requires=@('repadmin',...)
    and the engine can skip/flag them if a prerequisite is missing rather than crashing
#>

function Get-ADTTools {
    [CmdletBinding()]
    param()

    $native = 'repadmin','dcdiag'
    $tools = [ordered]@{}

    foreach ($n in $native) {
        $tools[$n] = [bool](Get-Command $n -ErrorAction SilentlyContinue)
    }

    # PowerShell modules (RSAT)
    foreach ($m in 'ActiveDirectory','DnsServer','GroupPolicy') {
        $tools[$m] = [bool](Get-Command -Module $m -ErrorAction SilentlyContinue) -or [bool](Get-Module -ListAvailable -Name $m -ErrorAction SilentlyContinue)
    }

    # Are we elevated?
    $tools['Elevated'] = $false
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
        $tools['Elevated'] = $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }

    # Are we running on a DC? (ProductType 2 = domain controller)
    $tools['IsOnDC'] = $false
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $tools['IsOnDC'] = ($os.ProductType -eq 2)
    } catch {
        try { $tools['IsOnDC'] = ((Get-WmiObject Win32_OperatingSystem).ProductType -eq 2) } catch { }
    }

    return $tools
}
