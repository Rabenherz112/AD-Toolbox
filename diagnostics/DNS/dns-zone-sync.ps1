#Requires -Version 5.1
<#
    Diagnostic: DNS Zone Synchronization

    Compares the zone inventory across every DC DNS server to catch DNS sync problems:
        * A zone present on some DNS servers but missing on others (replication-scope or not-converged)
        * A Primary zone that is NOT AD-integrated (so it does not replicate via AD at all)
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

            # Present on some but not all DNS servers -> replication-scope or convergence problem
            if ($missing.Count -gt 0) {
                $findings += New-ADTFinding -Severity High -Area DNS -Target $zn `
                    -Title "Zone '$zn' is missing on $($missing.Count) of $($servers.Count) DNS server(s)" `
                    -Evidence ("Present: " + (@($present.DC) -join ', ') + " | Missing: " + (@($missing.DC) -join ', ')) `
                    -RootCause 'The zone exists on some DNS servers but not others - AD replication of the zone partition has not converged, or the zone replication scope excludes those DCs.' `
                    -Impact 'Clients using a DNS server that lacks the zone get resolution failures for that namespace.' `
                    -Remediation @{ Text='Confirm the zone is AD-integrated with the right replication scope (Forest/Domain), then let AD replication converge or force it.'; ActionId='force-replication' }
            }

            # Inspect the zone instances that DO exist
            $instances = foreach ($s in $present) { $s.Zones | Where-Object ZoneName -eq $zn | Select-Object -First 1 }
            $notDs = @($instances | Where-Object { -not $_.IsDsIntegrated })
            if ($notDs.Count -gt 0) {
                $findings += New-ADTFinding -Severity Medium -Area DNS -Target $zn `
                    -Title "Zone '$zn' is a file-based primary (not AD-integrated)" `
                    -RootCause 'A standard (file-based) primary zone does not replicate through AD - it is a single point of failure and will not stay in sync across DCs.' `
                    -Impact 'If that DNS server is lost the zone is lost; other DCs never receive updates.' `
                    -Remediation 'Convert the zone to an AD-integrated zone so it replicates with AD.'
            }
            $scopes = @($instances | ForEach-Object { [string]$_.ReplicationScope } | Sort-Object -Unique)
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
