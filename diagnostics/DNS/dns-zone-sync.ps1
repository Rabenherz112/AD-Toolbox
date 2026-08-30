#Requires -Version 5.1
<#
    Diagnostic: DNS Zone Synchronization

    Compares the zone inventory across every DC DNS server to catch DNS sync problems:
        * An AD-INTEGRATED zone present on some DNS servers but missing on others (replication-scope or not-converged)
        * A local file-based primary zone, which does not replicate via AD at all
        * The same zone name served AD-integrated on some servers and file-based on others
        * Replication-scope mismatches for the same zone
#>
@{
    Kind              = 'Diagnostic'
    Id                = 'dns-zone-sync'
    Name              = 'DNS Zone Synchronization'
    Area              = 'DNS'
    Synopsis          = 'Compare AD-integrated zone presence/scope across all DNS servers'
    Writes            = $false
    IncludeInFullTest = $true
    Requires          = @('DnsServer')
    Tags              = @('dns','replication','sync')

    Run = {
        param($Context)

        # DnsServer is loaded centrally by the engine (declared via Requires)

        if (-not $Context.DomainControllers) {
            return (New-ADTFinding -Severity Info -Area DNS -Target 'Domain' -Title 'No DCs discovered to check')
        }

        # Collect Primary forward zones from each DC that runs DNS
        $servers = @()
        foreach ($dc in $Context.DomainControllers) {
            try {
                $zones = @(Get-DnsServerZone -ComputerName $dc.HostName -ErrorAction Stop | Where-Object { $_.ZoneType -eq 'Primary' -and -not $_.IsReverseLookupZone -and -not $_.IsAutoCreated })
                $servers += [pscustomobject]@{ DC = $dc.Name; Zones = $zones }
            } catch { }  # not a DNS server / unreachable
        }
        if ($servers.Count -lt 1) {
            return (New-ADTFinding -Severity Info -Area DNS -Target 'Domain' -Title 'No DNS servers responded' -RootCause 'None of the DCs answered DNS server queries (DnsServer RPC).')
        }

        $findings = @()
        $allZoneNames = @($servers | ForEach-Object { $_.Zones.ZoneName } | Sort-Object -Unique)

        foreach ($zn in $allZoneNames) {
            $present = @($servers | Where-Object { $_.Zones.ZoneName -contains $zn })
            $missing = @($servers | Where-Object { $_.Zones.ZoneName -notcontains $zn })

            # Inspect the zone instances that DO exist, keeping the DC each one came from
            $instances = foreach ($s in $present) {
                [pscustomobject]@{ DC = $s.DC; Zone = ($s.Zones | Where-Object ZoneName -eq $zn | Select-Object -First 1) }
            }
            $dsInst   = @($instances | Where-Object { $_.Zone.IsDsIntegrated })
            $fileInst = @($instances | Where-Object { -not $_.Zone.IsDsIntegrated })

            # Classify the zone BEFORE judging its absence elsewhere
            if ($fileInst.Count -gt 0 -and $dsInst.Count -eq 0) {
                $hosts = (@($fileInst.DC) -join ', ')
                $copies = if ($fileInst.Count -gt 1) { " Each hosting server keeps its own independent copy, so they drift apart silently." } else { '' }
                $findings += New-ADTFinding -Severity Medium -Area DNS -Target $zn `
                    -Title "Zone '$zn' is a local file-based zone on $hosts" `
                    -Evidence ("Hosted on: $hosts | Not present on: " + (@($missing.DC) -join ', ') + ' (expected for a local zone)') `
                    -RootCause 'This is a standard (file-based) primary stored on the hosting server''s disk instead of in AD, so it exists only where it is hosted. Its absence on the other DNS servers is expected and is NOT an AD replication failure.' `
                    -Impact ('The zone does not replicate: it is a single point of failure, clients querying any other DNS server cannot resolve the namespace, and it cannot enforce secure dynamic updates.' + $copies) `
                    -Remediation 'Convert the zone to AD-integrated so it replicates with AD and can enforce secure dynamic updates. If it is deliberately local, confirm that only clients pointed at the hosting server need it.'
            }
            elseif ($fileInst.Count -gt 0) {
                # same zone name served from AD on some servers and from a local file on others
                $findings += New-ADTFinding -Severity High -Area DNS -Target $zn `
                    -Title "Zone '$zn' exists as both an AD-integrated and a file-based primary" `
                    -Evidence ('AD-integrated on: ' + (@($dsInst.DC) -join ', ') + ' | file-based on: ' + (@($fileInst.DC) -join ', ')) `
                    -RootCause 'The same zone name is served from AD on some DNS servers and from a local zone file on others. The two copies are unrelated and diverge silently.' `
                    -Impact 'Resolution depends on which DNS server a client happens to ask, and updates written to one copy never reach the other.' `
                    -Remediation 'Decide which copy is authoritative, delete the other, and keep the zone AD-integrated.'
            }
            # All instances AD-integrated: now absence elsewhere really does mean replication/scope
            elseif ($missing.Count -gt 0) {
                $findings += New-ADTFinding -Severity High -Area DNS -Target $zn `
                    -Title "Zone '$zn' is missing on $($missing.Count) of $($servers.Count) DNS server(s)" `
                    -Evidence ("Present: " + (@($present.DC) -join ', ') + " | Missing: " + (@($missing.DC) -join ', ')) `
                    -RootCause 'The zone is AD-integrated and exists on some DNS servers but not others - AD replication of the zone partition has not converged, or the zone replication scope excludes those DCs.' `
                    -Impact 'Clients using a DNS server that lacks the zone get resolution failures for that namespace.' `
                    -Remediation @{ Text='Confirm the zone is AD-integrated with the right replication scope (Forest/Domain), then let AD replication converge or force it.'; ActionId='force-replication' }
            }

            # Replication scope is an AD-integrated concept, so only compare those instances
            $scopes = @($dsInst | ForEach-Object { [string]$_.Zone.ReplicationScope } | Sort-Object -Unique)
            if ($scopes.Count -gt 1) {
                $findings += New-ADTFinding -Severity Medium -Area DNS -Target $zn `
                    -Title "Zone '$zn' has inconsistent replication scope across DNS servers" -Evidence ($scopes -join ', ') `
                    -RootCause 'The same zone reports different replication scopes on different servers.' `
                    -Remediation 'Set a single, intended replication scope for the zone.'
            }
        }

        if (-not ($findings | Where-Object { $_.Rank -ge 2 })) {
            $findings += New-ADTFinding -Severity OK -Area DNS -Target 'Domain' -Title "All $($allZoneNames.Count) primary zone(s) consistent across $($servers.Count) DNS server(s)"
        }
        return $findings
    }
}
