#Requires -Version 5.1
<#
    Action (Disruptive): Enable DNS scavenging + zone aging

    Enables server-level scavenging on ONE designated DNS server, or enables aging on a single
    zone. Disruptive because scavenging will, over time, DELETE stale records - intervals must be sane.
    Linked from dns-configuration-hygiene

    Target resolution (findings from that diagnostic target either a server or a zone):
      * a known DC name/hostname -> designate that server as the scavenging server
      * anything else that resolves to a zone -> enable aging on that zone only
      * empty -> the PDC emulator, plus aging on the domain zone
#>
@{
    Kind              = 'Action'
    Id                = 'enable-dns-scavenging'
    Name              = 'Enable DNS Scavenging + Aging'
    Area              = 'DNS'
    Synopsis          = 'Designate a scavenging DNS server, or enable aging on a zone'
    RiskLevel         = 'Disruptive'
    RequiresElevation = $true
    Requires          = @('DnsServer')
    Tags              = @('dns','scavenging','remediation')

    Run = {
        param($Context, $Target)
        # DnsServer is loaded centrally by the engine (declared via Requires)

        $pdc = if ($Context.Fsmo.PDCEmulator) {
            $Context.Fsmo.PDCEmulator
        } else {
            ($Context.DomainControllers | Select-Object -First 1).HostName # first DC
        }
        if (-not $pdc) { return (New-ADTFinding -Severity Info -Area DNS -Target 'Domain' -Title 'No DNS server available') }

        $Target = [string]($Target | Select-Object -First 1)

        # Is the target one of our DCs, or a zone name?
        $dcMatch = $Context.DomainControllers | Where-Object { $_.Name -eq $Target -or $_.HostName -eq $Target } | Select-Object -First 1
        $zoneName = $null
        if ($Target -and -not $dcMatch) {
            try {
                $zoneName = (Get-DnsServerZone -ComputerName $pdc -Name $Target -ErrorAction Stop).ZoneName
            } catch {
                return (New-ADTFinding -Severity Info -Area DNS -Target $Target `
                        -Title "'$Target' is neither a known DC nor a DNS zone" -Evidence $_.Exception.Message)
            }
        }

        # Zone-only mode: aging is a replicated zone property, so it is set once on any writable server
        if ($zoneName) {
            if ($Context.WhatIf) {
                return (New-ADTFinding -Severity Info -Area DNS -Target $zoneName -Title "WhatIf: would enable aging on zone '$zoneName'")
            }
            try {
                Set-DnsServerZoneAging -ComputerName $pdc -Name $zoneName -Aging $true -ErrorAction Stop
                return (New-ADTFinding -Severity OK -Area DNS -Target $zoneName -Title "Aging enabled on zone '$zoneName'" `
                        -RootCause 'Records only start carrying timestamps from now on; nothing is scavenged until a designated scavenging server runs the sweep.')
            } catch {
                return (New-ADTFinding -Severity High -Area DNS -Target $zoneName -Title "Failed to enable aging on zone '$zoneName'" -Evidence $_.Exception.Message)
            }
        }

        # Server mode: designate a scavenging server. RODCs cannot scavenge an AD-integrated zone
        $dc = if ($dcMatch) { $dcMatch.HostName } else { $pdc }
        if ($dcMatch -and $dcMatch.IsRODC) {
            return (New-ADTFinding -Severity Info -Area DNS -Target $dcMatch.Name `
                    -Title "$($dcMatch.Name) is an RODC and cannot scavenge AD-integrated zones" `
                    -Remediation 'Designate a writable DC (the PDC emulator is the usual choice) as the scavenging server instead.')
        }

        # ScavengingInterval is the timer that actually runs the sweep - setting ScavengingState
        # alone leaves the server doing nothing, so both are set here. 7 days is the DNS default
        $interval = [timespan]::FromDays(7)
        if ($Context.WhatIf) {
            return (New-ADTFinding -Severity Info -Area DNS -Target $dc -Title "WhatIf: would designate $dc as scavenging server (interval $interval) and enable aging on zone '$($Context.Domain)'")
        }
        try {
            Set-DnsServerScavenging -ComputerName $dc -ScavengingState $true -ScavengingInterval $interval -ErrorAction Stop
            $aged = ''
            try {
                Set-DnsServerZoneAging -ComputerName $dc -Name $Context.Domain -Aging $true -ErrorAction Stop
                $aged = "; aging enabled on $($Context.Domain)"
            } catch { }
            return (New-ADTFinding -Severity OK -Area DNS -Target $dc -Title "DNS scavenging enabled on $dc (interval $interval)$aged" `
                    -RootCause 'Confirm RefreshInterval/NoRefreshInterval are appropriate before stale records age out. One designated scavenging server is enough - its deletions replicate to the other DCs.')
        } catch {
            return (New-ADTFinding -Severity High -Area DNS -Target $dc -Title "Failed to enable scavenging on $dc" -Evidence $_.Exception.Message)
        }
    }
}
