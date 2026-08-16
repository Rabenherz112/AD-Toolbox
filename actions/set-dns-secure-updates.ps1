#Requires -Version 5.1
<#
    Action (Disruptive): Set a DNS zone to Secure-only dynamic updates

    Changes an AD-integrated primary zone's dynamic update mode to "Secure only". Disruptive
    because any non-domain-joined host relying on nonsecure dynamic updates would stop updating
    its record. Linked from dns-configuration-hygiene
#>
@{
    Kind              = 'Action'
    Id                = 'set-dns-secure-updates'
    Name              = 'Set DNS zone to Secure dynamic updates'
    Area              = 'DNS'
    Synopsis          = 'Set a zone DynamicUpdate to Secure on a DNS server'
    RiskLevel         = 'Disruptive'
    RequiresElevation = $true
    Requires          = @('DnsServer')
    Tags              = @('dns','hardening','remediation')

    Run = {
        param($Context, $Target)
        # DnsServer is loaded centrally by the engine (declared via Requires)

        $dc = if ($Target) {
            $Target
        } elseif ($Context.Fsmo.PDCEmulator) {
            $Context.Fsmo.PDCEmulator
        } else {
            ($Context.DomainControllers | Select-Object -First 1).HostName # first DC
        }
        $zone = Read-Host "   Zone to secure [default: $($Context.Domain)]"
        if (-not $zone) { $zone = $Context.Domain }
        if (-not $dc -or -not $zone) { return (New-ADTFinding -Severity Info -Area DNS -Target 'Domain' -Title 'No DNS server / zone specified') }

        if ($Context.WhatIf) {
            return (New-ADTFinding -Severity Info -Area DNS -Target $zone -Title "WhatIf: would set zone '$zone' to Secure dynamic updates on $dc")
        }
        try {
            Set-DnsServerPrimaryZone -Name $zone -ComputerName $dc -DynamicUpdate 'Secure' -ErrorAction Stop
            return (New-ADTFinding -Severity OK -Area DNS -Target $zone -Title "Zone '$zone' set to Secure dynamic updates")
        } catch {
            return (New-ADTFinding -Severity High -Area DNS -Target $zone -Title "Failed to set Secure updates on '$zone'" -Evidence $_.Exception.Message)
        }
    }
}
