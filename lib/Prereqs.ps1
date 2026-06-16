#Requires -Version 5.1
<#
    Prereqs.ps1 - Probe what tooling is available so modules can degrade gracefully

    Returns a hashtable of capability flags. Modules declare Requires=@('repadmin',...)
    and the engine can skip/flag them if a prerequisite is missing rather than crashing
#>

function Get-ADTTools {
    [CmdletBinding()]
    param()

    $native = 'repadmin','dcdiag','nltest','netdom','w32tm','dfsrdiag','dnscmd','setspn','ntdsutil'
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
        $tools['IsOnDC'] = ((Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).ProductType -eq 2)
    } catch { }

    # Is this device joined to an AD domain?
    # PartOfDomain is also true for Azure AD-joined; DomainRole 4/5 = DC, 1/3 = domain member
    $tools['DomainJoined'] = $false
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $tools['DomainJoined'] = ([bool]$cs.PartOfDomain -and ($cs.DomainRole -ge 1))
    } catch { }

    return $tools
}

function Test-ADTRequires {
    <# True if all of a module's declared prerequisites are present #>
    [CmdletBinding()]
    param(
        [string[]]$Requires,
        [hashtable]$Tools
    )
    if (-not $Requires) { return $true }
    foreach ($r in $Requires) {
        if (-not $Tools.Contains($r) -or -not $Tools[$r]) { return $false }
    }
    return $true
}
