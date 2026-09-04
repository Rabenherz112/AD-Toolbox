#Requires -Version 5.1
<#
    Diagnostic: DC Locator / SRV Record Integrity

    Resolves the DNS records AD depends on and pinpoints missing/stale ones:
      * the domain _ldap/_kerberos SRV records (presence)
      * orphaned LDAP SRV targets (point at hosts that are not DCs)
      * DCs missing from the LDAP SRV set (incomplete Netlogon registration)
      * every DC's A record (duplicate/stale registrations)
      * each DC's GUID._msdcs CNAME
#>
@{
    Kind              = 'Diagnostic'
    Id                = 'dns-dc-srv-record'
    Name              = 'DC Locator / SRV Record Integrity'
    Area              = 'DNS'
    Synopsis          = 'Resolve the SRV/A/_msdcs records DCs rely on; flag missing/stale/orphaned ones'
    Writes            = $false
    IncludeInFullTest = $true
    Tags              = @('dns','locator','core')

    Run = {
        param($Context)

        if (-not $Context.Domain) {
            return (New-ADTFinding -Severity Info -Area DNS -Target 'Domain' -Title 'Domain unknown - cannot check DC locator/SRV records')
        }
        $domain = $Context.Domain
        $forest = if ($Context.Forest) { $Context.Forest } else { $domain }
        $findings = @()

        $resolveDns = {
            param($Name, $Type)
            try { return @(Resolve-DnsName -Name $Name -Type $Type -DnsOnly -NoHostsFile -ErrorAction Stop) }
            catch { return $null }
        }

        $normalizeHost = {
            param($Name)
            if (-not $Name) { return '' }
            return ([string]$Name).TrimEnd('.').ToLowerInvariant()
        }

        # Every name a DC may legitimately appear under in an SRV NameTarget
        $dcNames = {
            param($DC, $DomainName)
            @(
                (& $normalizeHost $DC.HostName)
                (& $normalizeHost $DC.Name)
                (& $normalizeHost "$($DC.Name).$DomainName")
            ) | Where-Object { $_ } | Select-Object -Unique
        }

        $dcSet     = Get-ADTDomainControllerSet -Context $Context -Domain $domain
        $domainDCs = @($dcSet.DomainControllers)

        # 1) Domain-wide locator SRV records
        $srvChecks = @(
            @{ Name = "_ldap._tcp.dc._msdcs.$domain";     Label = 'LDAP DC locator';        Severity = 'Critical'; CheckMembership = $true;  MembershipSeverity = 'High' },
            @{ Name = "_kerberos._tcp.dc._msdcs.$domain"; Label = 'Kerberos KDC locator';   Severity = 'High';     CheckMembership = $false; MembershipSeverity = $null },
            @{ Name = "_gc._tcp.$forest";                 Label = 'Global Catalog locator'; Severity = 'High';     CheckMembership = $false; MembershipSeverity = $null }
        )
        foreach ($srvCheck in $srvChecks) {
            $srvRecords = & $resolveDns $srvCheck.Name 'SRV'
            if (-not $srvRecords) {
                $findings += New-ADTFinding -Severity $srvCheck.Severity -Area DNS -Target 'Domain' `
                    -Title "$($srvCheck.Label) SRV record missing: $($srvCheck.Name)" `
                    -RootCause "The SRV record $($srvCheck.Name) did not resolve from this host's DNS." `
                    -Impact 'Clients/DCs cannot locate the service; logons, replication topology, or GC lookups fail.' `
                    -Remediation @{ Text='Ensure DCs register their SRV records (restart Netlogon) and that this host queries an AD DNS server.'; ActionId='register-dc-dns' }
                continue
            }

            if (-not $srvCheck.CheckMembership) {
                $findings += New-ADTFinding -Severity OK -Area DNS -Target 'Domain' `
                    -Title "$($srvCheck.Label) SRV present ($(@($srvRecords).Count) record(s))"
                continue
            }

            $targets = @($srvRecords | Where-Object { $_.Type -eq 'SRV' } |
                            ForEach-Object { & $normalizeHost $_.NameTarget } |
                            Where-Object { $_ } | Select-Object -Unique)

            # Calling a target orphaned, or a DC unregistered, is only valid against every DC in the domain
            if ($domainDCs.Count -eq 0 -or -not $dcSet.IsComplete) {
                $findings += New-ADTFinding -Severity Info -Area DNS -Target 'Domain' `
                    -Title "$($srvCheck.Label) SRV present, but its targets were not compared against the DC list" `
                    -Evidence ("Targets: " + ($targets -join ', ') + " | DC list: $($dcSet.Source)") `
                    -RootCause 'Flagging orphaned or missing SRV targets needs the full DC list for this domain, and this run does not have one - the DC list was narrowed to a single -Server target, or discovery returned no DCs for this domain.' `
                    -Impact 'The record exists, but a demoted DC still listed here, or a live DC that never registered, would go unnoticed.' `
                    -Remediation 'Re-run without -Server, or from a host with the ActiveDirectory RSAT module, to compare SRV targets against every DC in the domain.'
                continue
            }

            $ownerByName = @{}
            foreach ($dc in $domainDCs) {
                foreach ($n in (& $dcNames $dc $domain)) { $ownerByName[$n] = $dc }
            }

            $orphans    = @($targets | Where-Object { -not $ownerByName.ContainsKey($_) })
            $registered = @{}
            foreach ($t in $targets) {
                if ($ownerByName.ContainsKey($t)) { $registered[$ownerByName[$t].HostName] = $true }
            }
            $missingDCs = @($domainDCs | Where-Object { -not $registered.ContainsKey($_.HostName) })

            if ($orphans.Count -gt 0) {
                $findings += New-ADTFinding -Severity $srvCheck.MembershipSeverity -Area DNS -Target 'Domain' `
                    -Title "$($srvCheck.Label) SRV has $($orphans.Count) orphaned target(s)" `
                    -Evidence ("Orphans: " + ($orphans -join ', ') + " | All targets: " + ($targets -join ', ') + " | DC list: $($dcSet.Source)") `
                    -RootCause 'One or more SRV NameTargets do not match any domain controller in this domain - usually a demoted or renamed DC whose records were never scavenged.' `
                    -Impact 'Clients may try to authenticate or locate services on a dead host and fail or time out.' `
                    -Remediation @{ Text='Remove stale SRV records for demoted DCs (or enable scavenging/aging) and restart Netlogon on live DCs to re-register.'; ActionId='register-dc-dns' }
            }

            if ($missingDCs.Count -gt 0) {
                # An RODC registers through a read-only zone rather than a direct dynamic update
                $missingText = @($missingDCs | ForEach-Object { "$($_.HostName)$(if ($_.IsRODC) { ' (RODC)' })" })
                $findings += New-ADTFinding -Severity $srvCheck.MembershipSeverity -Area DNS -Target 'Domain' `
                    -Title "$($missingDCs.Count) DC(s) missing from $($srvCheck.Label) SRV" `
                    -Evidence ("Missing: " + ($missingText -join ', ') + " | SRV targets: " + ($targets -join ', ') + " | DC list: $($dcSet.Source)") `
                    -RootCause "Live domain controller(s) do not appear as NameTargets on $($srvCheck.Name) - either Netlogon registration is incomplete, or the zone copy this host's resolver answered from has not converged." `
                    -Impact 'Clients will not discover those DCs via the DNS locator; load is skewed and the missing DCs look "down" to DNS-based discovery.' `
                    -Remediation @{ Text='On each missing DC restart Netlogon (or run nltest /dsregdns) and confirm dynamic updates succeed on the zone. If the same query against another DNS server does list them, the fault is zone replication rather than registration.'; ActionId='register-dc-dns' }
            }

            if ($orphans.Count -eq 0 -and $missingDCs.Count -eq 0) {
                $findings += New-ADTFinding -Severity OK -Area DNS -Target 'Domain' `
                    -Title "$($srvCheck.Label) SRV present and targets match all $($domainDCs.Count) DC(s)" `
                    -Evidence ($targets -join ', ')
            }
        }

        # 2) Per-DC A records and the GUID._msdcs CNAME
        foreach ($dc in $Context.DomainControllers) {
            $aRecords = & $resolveDns $dc.HostName 'A'
            if (-not $aRecords) {
                $findings += New-ADTFinding -Severity High -Area DNS -Target $dc.Name `
                    -Title "DC A record does not resolve: $($dc.HostName)" `
                    -RootCause "Host record for $($dc.HostName) did not resolve." `
                    -Impact 'This DC cannot be located by name; replication/auth to it will fail.' `
                    -Remediation @{ Text='Re-register the DC host record (ipconfig /registerdns) and check the forward zone.'; ActionId='register-dc-dns' }
            }
            else {
                $resolvedIps = @($aRecords | Where-Object { $_.Type -eq 'A' -and $_.IPAddress } |
                                    ForEach-Object { [string]$_.IPAddress } | Select-Object -Unique)

                # The address left behind by an IP change is the stale registration that actually breaks things
                if ($resolvedIps.Count -gt 1) {
                    $findings += New-ADTFinding -Severity High -Area DNS -Target $dc.Name `
                        -Title "$($dc.HostName) resolves to $($resolvedIps.Count) addresses" `
                        -Evidence ("DNS A: " + ($resolvedIps -join ', ') + $(if ($dc.IPv4) { " | AD reports: $($dc.IPv4)" })) `
                        -RootCause 'The DC host name has more than one A record. Unless this DC is deliberately multi-homed, the extra addresses are registrations left behind by an IP change that dynamic updates never scavenged.' `
                        -Impact 'Clients and replication partners round-robin across every listed address, so a share of connections goes to an address that no longer answers - intermittent failures that look host-specific.' `
                        -Remediation @{ Text='Delete the A records that do not match the address configured on the DC, then re-register DNS on it. If the DC really is multi-homed, restrict DNS registration to the domain-facing NIC.'; ActionId='register-dc-dns' }
                }
                elseif ($dc.IPv4 -and $resolvedIps.Count -eq 1 -and $resolvedIps[0] -ne $dc.IPv4) {
                    $findings += New-ADTFinding -Severity Medium -Area DNS -Target $dc.Name `
                        -Title "DC A record and AD disagree on the address of $($dc.Name)" `
                        -Evidence ("DNS A: " + ($resolvedIps -join ', ') + " | AD reports: $($dc.IPv4)") `
                        -RootCause 'The A record this host resolves and the address AD reports for the DC differ. Both are ultimately read from DNS, so the disagreement means two resolvers (or two cache entries) answered differently for the same name.' `
                        -Impact 'Clients reach different addresses for this DC depending on which resolver they ask, so connectivity to it is inconsistent across the network.' `
                        -Remediation @{ Text='Compare both answers against the IP actually configured on the DC (dc-dns-client-settings reports it), delete whichever record is stale, then re-register DNS on the DC.'; ActionId='register-dc-dns' }
                }
            }

            # DSA GUID is in the context object; this can only be checked if the ActiveDirectory discovery path is used, so this check is skipped under .NET discovery
            if ($dc.ObjectGuid) {
                $msdcsCname = "$($dc.ObjectGuid)._msdcs.$forest"
                $cnameRecords = & $resolveDns $msdcsCname 'CNAME'
                if (-not $cnameRecords) {
                    $findings += New-ADTFinding -Severity High -Area DNS -Target $dc.Name `
                        -Title "Missing _msdcs CNAME for $($dc.Name)" -Evidence $msdcsCname `
                        -RootCause "The DSA GUID alias $msdcsCname did not resolve - other DCs cannot find this DC as a replication source." `
                        -Impact 'Replication FROM this DC fails with error 8524 (DNS lookup failure).' `
                        -Remediation @{ Text="On $($dc.HostName) restart Netlogon to re-register _msdcs records; verify _msdcs.$forest delegation/zone."; ActionId='register-dc-dns' }
                }
            }
        }
        return $findings
    }
}
