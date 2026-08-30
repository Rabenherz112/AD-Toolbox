#Requires -Version 5.1
<#
    Diagnostic: DNS Configuration Hygiene

    Flags DNS settings that SHOULD be configured but are commonly forgotten:
      * AD-integrated zones (especially the zone the DCs live in) accepting NONSECURE dynamic updates - any host can overwrite records, including DC records (spoofing risk)
      * No DNS server in the domain actually running the scavenging sweep - stale records accumulate forever
      * Zone aging disabled on a zone that DOES accept dynamic updates - scavenging cannot age out records without it
      * A file-based (standard) primary zone accepting dynamic updates - those can never be made "Secure only"
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

        # Zones that exist for the DNS service itself - aging/scavenging is meaningless on them
        $systemZones = @('TrustAnchors','RootHints','.')
        $reference    = $null
        $serverState  = @()   # every writable DC we could query
        $unreachable  = @()   # writable DCs that did not answer (NOT silently dropped)
        foreach ($dc in $Context.DomainControllers) {
            if ($dc.IsRODC) { continue }
            try {
                $scv = Get-DnsServerScavenging -ComputerName $dc.HostName -ErrorAction Stop
                $interval = if ($null -ne $scv.ScavengingInterval) { [timespan]$scv.ScavengingInterval } else { [timespan]::Zero }
                $serverState += [pscustomobject]@{
                    Name     = $dc.Name
                    State    = [bool]$scv.ScavengingState
                    Interval = $interval
                    LastScavenge = $scv.LastScavengeTime
                    Sweeps   = ($interval.TotalHours -gt 0)
                }
                if (-not $reference) { $reference = $dc.HostName }
            } catch {
                $unreachable += "$($dc.Name) ($($_.Exception.Message))"
            }
        }
        if (-not $reference) {
            return @($findings + (New-ADTFinding -Severity Info -Area DNS -Target 'Domain' `
                -Title 'No writable DNS servers responded for configuration review' `
                -Evidence (@($unreachable) -join '; ')))
        }
        if ($unreachable.Count -gt 0) {
            $findings += New-ADTFinding -Severity Low -Area DNS -Target 'Domain' `
                -Title "Could not read the DNS configuration of $($unreachable.Count) DC(s)" `
                -Evidence (@($unreachable) -join '; ') `
                -RootCause 'The DNS server RPC/CIM query failed, so these servers were not included in the scavenging assessment.' `
                -Remediation 'Confirm the DNS Server role and remote management are reachable on these DCs, then re-run.'
        }

        # Zone-level (read once from the reference DNS server; AD-integrated zones replicate)
        $agingZones = @()
        try {
            $zones = @(Get-DnsServerZone -ComputerName $reference -ErrorAction Stop | Where-Object {
                $_.ZoneType -eq 'Primary' -and -not $_.IsReverseLookupZone -and -not $_.IsAutoCreated -and $systemZones -notcontains $_.ZoneName
            })
            foreach ($zone in $zones) {
                # the zone the DCs register in - _msdcs holds the locator records and counts too
                $isDcZone = ($zone.ZoneName -eq $domainZone -or $zone.ZoneName -eq "_msdcs.$($Context.ForestRootDomain)")

                if ($zone.DynamicUpdate -eq 'NonsecureAndSecure') {
                    $sev = if ($isDcZone) { 'High' } else { 'Medium' }
                    if ($zone.IsDsIntegrated) {
                        $findings += New-ADTFinding -Severity $sev -Area DNS -Target $zone.ZoneName `
                            -Title "Zone '$($zone.ZoneName)' accepts NONSECURE dynamic updates" `
                            -Evidence "DynamicUpdate = $($zone.DynamicUpdate)" `
                            -RootCause ('The zone allows unauthenticated dynamic updates' + $(if ($isDcZone) { ' - and this is the zone the DCs register in, so any host could overwrite DC records.' } else { '.' })) `
                            -Impact 'Record spoofing / hijack of host (and potentially DC locator) records.' `
                            -Remediation @{ Text='Set the zone dynamic updates to "Secure only".'; ActionId='set-dns-secure-updates' }
                    } else {
                        $findings += New-ADTFinding -Severity $sev -Area DNS -Target $zone.ZoneName `
                            -Title "File-based zone '$($zone.ZoneName)' accepts dynamic updates and cannot be made secure" `
                            -Evidence "DynamicUpdate = $($zone.DynamicUpdate); IsDsIntegrated = False" `
                            -RootCause 'The zone is a standard (file-based) primary, so secure dynamic update is not available - any host can register or overwrite records in it.' `
                            -Impact 'Record spoofing / hijack of host records, with no way to restrict updates while the zone stays file-based.' `
                            -Remediation 'Convert the zone to AD-integrated and then set dynamic updates to "Secure only", or turn dynamic updates off if the zone is maintained by hand.'
                    }
                }

                # Aging only matters where records are registered dynamically
                if ($zone.DynamicUpdate -ne 'None') {
                    try {
                        $aging = Get-DnsServerZoneAging -ComputerName $reference -Name $zone.ZoneName -ErrorAction Stop
                        if ($aging.AgingEnabled) {
                            $agingZones += $zone.ZoneName
                        } else {
                            $sev = if ($isDcZone) { 'Medium' } else { 'Low' }
                            $findings += New-ADTFinding -Severity $sev -Area DNS -Target $zone.ZoneName `
                                -Title "Aging is not enabled on zone '$($zone.ZoneName)'" `
                                -Evidence "DynamicUpdate = $($zone.DynamicUpdate)" `
                                -RootCause 'The zone accepts dynamic updates but record aging is off, so registered records never carry a refreshable timestamp and scavenging can never remove them once stale.' `
                                -Impact 'Stale host records accumulate and can misdirect clients to decommissioned hosts.' `
                                -Remediation @{ Text='Enable aging on the zone alongside a designated scavenging server.'; ActionId='enable-dns-scavenging' }
                        }
                    } catch { }
                }
            }
        } catch {
            $findings += New-ADTFinding -Severity Low -Area DNS -Target 'Domain' -Title 'Could not read zone configuration' -Evidence $_.Exception.Message
        }

        $allState = (@($serverState | ForEach-Object {
            "$($_.Name): interval=$(if ($_.Interval.TotalHours -gt 0) { $_.Interval } else { 'off' }), lastScavenge=$(if ($_.LastScavenge) { $_.LastScavenge } else { 'never' })"
        }) -join ' | ')
        $scavengers = @($serverState | Where-Object { $_.Sweeps })

        if ($scavengers.Count -gt 0) {
            $findings += New-ADTFinding -Severity OK -Area DNS -Target 'Domain' -Title "DNS scavenging is performed by $($scavengers.Count) server(s)" -Evidence $allState

            $stalled = @($scavengers | Where-Object {
                (-not $_.LastScavenge) -or ($_.LastScavenge -lt (Get-Date).Add(-$_.Interval).Add(-$_.Interval).Add(-$_.Interval))
            })
            if ($stalled.Count -eq $scavengers.Count) {
                $findings += New-ADTFinding -Severity Low -Area DNS -Target 'Domain' `
                    -Title 'Scavenging is configured but has not run recently on any server' `
                    -Evidence (@($stalled | ForEach-Object { "$($_.Name): interval=$($_.Interval), lastScavenge=$(if ($_.LastScavenge) { $_.LastScavenge } else { 'never' })" }) -join ' | ') `
                    -RootCause 'A scavenging interval is set but the last recorded sweep is far older than that interval (or has never happened), so the timer is not completing.' `
                    -Impact 'Scavenging looks configured but stale records are not actually being removed.' `
                    -Remediation 'Check the DNS event log on that server for scavenging events (2501/2502) and confirm the zones have aging enabled - a sweep with nothing to do still records a time.'
            }

            if ($scavengers.Count -gt 2) {
                $findings += New-ADTFinding -Severity Info -Area DNS -Target 'Domain' `
                    -Title "Scavenging is enabled on $($scavengers.Count) DNS servers" `
                    -Evidence (@($scavengers.Name) -join ', ') `
                    -RootCause 'Every enabled server sweeps the same AD-replicated zones independently.' `
                    -Impact 'Not harmful, but it makes "which server deleted this record" much harder to answer from the DNS event logs.' `
                    -Remediation 'Consider designating one or two scavenging servers, or restricting it per zone with Set-DnsServerZoneAging -ScavengeServers.'
            }
        }
        else {
            $sev = if ($agingZones.Count -gt 0) { 'Medium' } else { 'Low' }
            $findings += New-ADTFinding -Severity $sev -Area DNS -Target 'Domain' `
                -Title 'No DNS server in the domain performs scavenging' `
                -Evidence ($allState + " | Zones with aging enabled: $($agingZones.Count)") `
                -RootCause 'Server-level scavenging is off on every writable DNS server that answered, so nothing ever runs the sweep that deletes stale/tombstoned records.' `
                -Impact 'Stale records accumulate (e.g. old DC/host A records) and can misdirect clients.' `
                -Remediation @{ Text='Enable scavenging on ONE designated DNS server (the PDC emulator is the usual choice) rather than on every DC, and enable aging on the zones that take dynamic updates.'; ActionId='enable-dns-scavenging' }
        }

        return $findings
    }
}
