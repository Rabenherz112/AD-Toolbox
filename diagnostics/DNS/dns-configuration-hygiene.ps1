#Requires -Version 5.1
<#
    Diagnostic: DNS Configuration Hygiene

    Flags DNS settings that SHOULD be configured but are commonly forgotten:
      * AD-integrated zones (especially the zone the DCs live in) accepting NONSECURE dynamic updates - any host can overwrite records, including DC records (spoofing risk)
      * DNS server scavenging disabled - stale records accumulate forever
      * Zone aging disabled - scavenging cannot age out records without it

    Zone-level settings (dynamic update, aging) are read once from a reference DNS server since they are AD-replicated; scavenging is checked per server (it is a per-server setting)
#>
@{
    Kind              = 'Diagnostic'
    Id                = 'dns-configuration-hygiene'
    Name              = 'DNS Configuration Hygiene'
    Area              = 'DNS'
    Synopsis          = 'Secure dynamic updates, scavenging, and zone aging best practices'
    Writes            = $false
    IncludeInFullTest = $true
    Requires          = @('DnsServer')
    Tags              = @('dns','hardening','best-practice')

    Run = {
        param($Context)

        # DnsServer is loaded centrally by the engine (declared via Requires)

        if (-not $Context.DomainControllers) {
            return (New-ADTFinding -Severity Info -Area DNS -Target 'Domain' -Title 'No DCs discovered to check')
        }
        $domainZone = $Context.Domain
        $findings = @()

        # Per-server: scavenging enabled?
        $reference = $null
        foreach ($dc in $Context.DomainControllers) {
            try {
                $scv = Get-DnsServerScavenging -ComputerName $dc.HostName -ErrorAction Stop
                if (-not $scv.ScavengingState) {
                    $findings += New-ADTFinding -Severity Medium -Area DNS -Target $dc.Name `
                        -Title "DNS scavenging is disabled on $($dc.Name)" `
                        -RootCause 'Server-level scavenging (ScavengingState) is off, so stale/tombstoned DNS records are never removed.' `
                        -Impact 'Stale records accumulate (e.g. old DC/host A records) and can misdirect clients.' `
                        -Remediation @{ Text='Enable scavenging on the DNS server and aging on the zones.'; ActionId='enable-dns-scavenging' }
                } else {
                    $findings += New-ADTFinding -Severity OK -Area DNS -Target $dc.Name -Title "DNS scavenging enabled on $($dc.Name)"
                }
                if (-not $reference) { $reference = $dc.HostName }
            } catch { }  # not a DNS server / unreachable
        }
        if (-not $reference) {
            return @($findings + (New-ADTFinding -Severity Info -Area DNS -Target 'Domain' -Title 'No DNS servers responded for configuration review'))
        }

        # Zone-level (read once from the reference DNS server; AD-integrated zones replicate)
        try {
            $zones = @(Get-DnsServerZone -ComputerName $reference -ErrorAction Stop | Where-Object { $_.ZoneType -eq 'Primary' -and -not $_.IsReverseLookupZone -and -not $_.IsAutoCreated })
            foreach ($zone in $zones) {
                $isDcZone = ($zone.ZoneName -eq $domainZone) # zone the DCs register in

                if ($zone.DynamicUpdate -eq 'NonsecureAndSecure') {
                    $sev = if ($isDcZone) { 'High' } else { 'Medium' }
                    $findings += New-ADTFinding -Severity $sev -Area DNS -Target $zone.ZoneName `
                        -Title "Zone '$($zone.ZoneName)' accepts NONSECURE dynamic updates" `
                        -Evidence "DynamicUpdate = $($zone.DynamicUpdate)" `
                        -RootCause ('The zone allows unauthenticated dynamic updates' + $(if ($isDcZone) { ' - and this is the zone the DCs register in, so any host could overwrite DC records.' } else { '.' })) `
                        -Impact 'Record spoofing / hijack of host (and potentially DC locator) records.' `
                        -Remediation @{ Text='Set the zone dynamic updates to "Secure only".'; ActionId='set-dns-secure-updates' }
                }

                if ($zone.IsDsIntegrated) {
                    try {
                        $aging = Get-DnsServerZoneAging -ComputerName $reference -Name $zone.ZoneName -ErrorAction Stop
                        if (-not $aging.AgingEnabled) {
                            $findings += New-ADTFinding -Severity Low -Area DNS -Target $zone.ZoneName `
                                -Title "Aging is not enabled on zone '$($zone.ZoneName)'" `
                                -RootCause 'Record aging is off, so scavenging cannot remove stale records in this zone.' `
                                -Remediation @{ Text='Enable aging on the zone alongside server scavenging.'; ActionId='enable-dns-scavenging' }
                        }
                    } catch { }
                }
            }
        } catch {
            $findings += New-ADTFinding -Severity Low -Area DNS -Target 'Domain' -Title 'Could not read zone configuration' -Evidence $_.Exception.Message
        }
        return $findings
    }
}
