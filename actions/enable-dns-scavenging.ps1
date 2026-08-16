#Requires -Version 5.1
<#
    Action (Disruptive): Enable DNS scavenging + zone aging

    Enables server-level scavenging on a DNS server and aging on the domain zone. Disruptive
    because scavenging will, over time, DELETE stale records - intervals must be sane.
    Linked from dns-configuration-hygiene
#>
@{
    Kind              = 'Action'
    Id                = 'enable-dns-scavenging'
    Name              = 'Enable DNS Scavenging + Aging'
    Area              = 'DNS'
    Synopsis          = 'Enable server scavenging and zone aging on a DNS server'
    RiskLevel         = 'Disruptive'
    RequiresElevation = $true
    Requires          = @('DnsServer')
    Tags              = @('dns','scavenging','remediation')

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
        if (-not $dc) { return (New-ADTFinding -Severity Info -Area DNS -Target 'Domain' -Title 'No DNS server specified') }

        if ($Context.WhatIf) {
            return (New-ADTFinding -Severity Info -Area DNS -Target $dc -Title "WhatIf: would enable scavenging on $dc and aging on zone '$($Context.Domain)'")
        }
        try {
            Set-DnsServerScavenging -ComputerName $dc -ScavengingState $true -ErrorAction Stop
            $aged = ''
            try {
                Set-DnsServerZoneAging -ComputerName $dc -Name $Context.Domain -Aging $true -ErrorAction Stop
                $aged = "; aging enabled on $($Context.Domain)"
            } catch { }
            return (New-ADTFinding -Severity OK -Area DNS -Target $dc -Title "DNS scavenging enabled on $dc$aged" `
                    -RootCause 'Confirm RefreshInterval/NoRefreshInterval are appropriate before stale records age out.')
        } catch {
            return (New-ADTFinding -Severity High -Area DNS -Target $dc -Title "Failed to enable scavenging on $dc" -Evidence $_.Exception.Message)
        }
    }
}
