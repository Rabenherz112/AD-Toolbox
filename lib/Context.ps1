#Requires -Version 5.1
<#
    Context.ps1 - Build the runtime $Context: discover the forest/domain/DCs/FSMO/sites
    and attach config + capability flags. This is the ONLY data gathered before modules
    run (targets + environment). All *diagnostic* data is still collected inside each module

    By default it discovers the current (or -Domain) domain. With -ScanForest it enumerates
    DCs across EVERY domain in the forest in one run; each DC is tagged with its .Domain

    Discovery prefers the ActiveDirectory module; falls back to System.DirectoryServices
    (.NET) so the toolkit still works on a DC without RSAT, and still produces a
    (mostly empty) context off-domain so that -List / menu work anywhere
#>

function Initialize-ADTContext {
    [CmdletBinding()]
    param(
        $Config,
        [hashtable]$Tools,
        [string]$Server,
        [string]$Domain,
        [System.Management.Automation.PSCredential]$Credential,
        [System.Management.Automation.PSCredential]$TestCredential,
        [switch]$ScanForest,
        [switch]$WhatIf
    )

    if (-not $Tools)  { $Tools  = Get-ADTTools }
    if (-not $Config) { $Config = @{} }

    $ctx = [ordered]@{
        Forest            = $null
        Domain            = $null
        DomainDN          = $null
        ForestRootDomain  = $null
        Domains           = @()
        DomainControllers = @()
        Fsmo              = [ordered]@{}
        Sites             = @()
        TargetServer      = $Server
        TargetDomain      = $Domain
        Credential        = $Credential
        TestCredential    = $TestCredential
        ScanForest        = [bool]$ScanForest
        Config            = $Config
        Tools             = $Tools
        WhatIf            = [bool]$WhatIf
        IsOnDC            = [bool]$Tools['IsOnDC']
        HasADModule       = [bool]$Tools['ActiveDirectory']
        DiscoveryMethod   = 'None'
        DiscoveryError    = $null
        StartTime         = (Get-Date)
    }

    try {
        if ($Tools['ActiveDirectory']) {
            Import-Module ActiveDirectory -ErrorAction Stop
            $ctx = Initialize-ADTContextFromModule -Context $ctx -Domain $Domain -Credential $Credential -ScanForest:$ScanForest
            $ctx.DiscoveryMethod = 'ActiveDirectory'
        }
        else {
            $ctx = Initialize-ADTContextFromDotNet -Context $ctx -ScanForest:$ScanForest
            $ctx.DiscoveryMethod = 'DotNet'
        }
    }
    catch {
        $ctx.DiscoveryError = $_.Exception.Message
        Write-ADTLog -Level Warn -Message "Domain discovery failed: $($_.Exception.Message). Toolkit will run with limited context."
    }

    # If a single -Server was supplied, narrow the target set to it
    if ($Server) {
        $match = $ctx.DomainControllers | Where-Object { $_.HostName -like "$Server*" -or $_.Name -eq $Server }
        if ($match) { $ctx.DomainControllers = @($match) }
    }

    return [pscustomobject]$ctx
}

function New-ADTDcObject {
    param([string]$Name, [string]$HostName, [string]$Site, [string]$IPv4, [string]$OS, $IsGC, $IsRODC, [string]$DomainName)
    [pscustomobject]@{
        Name            = $Name
        HostName        = $HostName
        Site            = $Site
        IPv4            = $IPv4
        OperatingSystem = $OS
        IsGlobalCatalog = $IsGC
        IsRODC          = $IsRODC
        Domain          = $DomainName
        IsReachable     = $null
    }
}

function Initialize-ADTContextFromModule {
    param($Context, [string]$Domain, [System.Management.Automation.PSCredential]$Credential, [switch]$ScanForest)

    $common = @{}
    if ($Credential) { $common['Credential'] = $Credential }

    $domParams = @{} + $common
    if ($Domain) { $domParams['Server'] = $Domain }

    $dom    = Get-ADDomain @domParams -ErrorAction Stop
    $forest = Get-ADForest @common -ErrorAction SilentlyContinue

    $Context.Domain           = $dom.DNSRoot
    $Context.DomainDN         = $dom.DistinguishedName
    $Context.Forest           = if ($forest) { $forest.Name } else { $dom.Forest }
    $Context.ForestRootDomain = if ($forest) { $forest.RootDomain } else { $dom.Forest }
    $Context.Domains          = if ($forest) { @($forest.Domains) } else { @($dom.DNSRoot) }

    $Context.Fsmo = [ordered]@{
        PDCEmulator         = $dom.PDCEmulator
        RIDMaster           = $dom.RIDMaster
        InfrastructureMaster= $dom.InfrastructureMaster
        SchemaMaster        = if ($forest) { $forest.SchemaMaster } else { $null }
        DomainNamingMaster  = if ($forest) { $forest.DomainNamingMaster } else { $null }
    }

    # Which domains to enumerate DCs from
    $scanDomains = if ($ScanForest -and $forest) { @($forest.Domains) } else { @($dom.DNSRoot) }

    $dcs = @()
    foreach ($d in $scanDomains) {
        try {
            $dcParams = @{ Filter = '*'; Server = $d } + $common
            foreach ($dc in (Get-ADDomainController @dcParams -ErrorAction Stop)) {
                $dcs += New-ADTDcObject -Name $dc.Name -HostName $dc.HostName -Site $dc.Site -IPv4 $dc.IPv4Address `
                        -OS $dc.OperatingSystem -IsGC $dc.IsGlobalCatalog -IsRODC $dc.IsReadOnly -DomainName $d
            }
        } catch {
            Write-ADTLog -Level Warn -Message "Could not enumerate DCs for domain '$d': $($_.Exception.Message)"
        }
    }
    $Context.DomainControllers = $dcs
    $Context.Sites = @($dcs | Select-Object -ExpandProperty Site -Unique)
    return $Context
}

function Initialize-ADTContextFromDotNet {
    param($Context, [switch]$ScanForest)

    $dom    = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $forest = $dom.Forest

    $Context.Domain           = $dom.Name
    $Context.Forest           = $forest.Name
    $Context.ForestRootDomain = $forest.RootDomain.Name
    $Context.Domains          = @($forest.Domains | ForEach-Object { $_.Name })

    try {
        $Context.Fsmo = [ordered]@{
            PDCEmulator          = ($dom.PdcRoleOwner).Name
            RIDMaster            = ($dom.RidRoleOwner).Name
            InfrastructureMaster = ($dom.InfrastructureRoleOwner).Name
            SchemaMaster         = ($forest.SchemaRoleOwner).Name
            DomainNamingMaster   = ($forest.NamingRoleOwner).Name
        }
    } catch { }

    $scanDomains = if ($ScanForest) { @($forest.Domains) } else { @($dom) }

    $dcs = @()
    foreach ($d in $scanDomains) {
        try {
            foreach ($dc in $d.DomainControllers) {
                $dcs += New-ADTDcObject -Name (($dc.Name -split '\.')[0]) -HostName $dc.Name -Site $dc.SiteName `
                        -IPv4 $dc.IPAddress -OS $dc.OSVersion -IsGC $null -IsRODC $null -DomainName $d.Name
            }
        } catch { }
    }
    $Context.DomainControllers = $dcs
    $Context.Sites = @($dcs | Select-Object -ExpandProperty Site -Unique)
    return $Context
}
