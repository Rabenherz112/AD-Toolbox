#Requires -Version 5.1
<#
    Diagnostic: DC DNS Client Settings

    A DC has to resolve through DNS that serves the AD zones.
    Hard faults - the DC cannot reliably resolve AD names:
      * no DNS servers configured on any connected interface
      * well-known public resolvers (8.8.8.8, 1.1.1.1, ...) on the DNS client list
      * DNS servers that could not be shown to serve the AD zones
      * pointing only at itself while other DCs exist (DNS island)

    Recommendations:
      * running DNS but never listing itself, so a partner outage takes name resolution with it
      * a single entry on an interface, with nothing to fall back to
      * loopback as the PREFERRED entry (the finding says why this one is contested)
#>
@{
    Kind              = 'Diagnostic'
    Id                = 'dc-dns-client-settings'
    Name              = 'DC DNS Client Settings'
    Area              = 'DomainController'
    Synopsis          = 'Verify each DC points its DNS client at AD DNS, in a sane order (not public/empty/self-only)'
    Writes            = $false
    IncludeInFullTest = $true
    Tags              = @('dns','domaincontroller','client','core')

    Run = {
        param($Context)

        if (-not $Context.DomainControllers) {
            return (New-ADTFinding -Severity Info -Area DomainController -Target 'Domain' -Title 'No DCs discovered to check DNS client settings')
        }

        # Normalize IPv6 adresses which can have % zone indices
        $normIp = {
            param($Ip)
            $s = (([string]$Ip) -split '%')[0].Trim()
            if (-not $s) { return '' }
            $parsed = [System.Net.IPAddress]::Loopback
            if ([System.Net.IPAddress]::TryParse($s, [ref]$parsed)) { return $parsed.ToString() }
            return $s.ToLowerInvariant()
        }

        # Public recursive resolvers
        $publicDns = @{}
        foreach ($ip in @(
            '8.8.8.8','8.8.4.4','2001:4860:4860::8888','2001:4860:4860::8844',      # Google
            '1.1.1.1','1.0.0.1','2606:4700:4700::1111','2606:4700:4700::1001',      # Cloudflare
            '9.9.9.9','149.112.112.112','2620:fe::fe','2620:fe::9',                 # Quad9
            '208.67.222.222','208.67.220.220','2620:119:35::35','2620:119:53::53',  # OpenDNS
            '4.2.2.1','4.2.2.2','4.2.2.3','4.2.2.4','4.2.2.5','4.2.2.6'            # Level3

        )) { $publicDns[(& $normIp $ip)] = $true }

        # Windows legacy site-local IPv6 placeholders
        $defaultIpv6Dns = @{}
        foreach ($ip in @('fec0:0:0:ffff::1','fec0:0:0:ffff::2','fec0:0:0:ffff::3')) {
            $defaultIpv6Dns[(& $normIp $ip)] = $true
        }

        # Returns the client DNS list per interface and in order (index 0 is the preferred server), plus the host's own addresses so "is this entry itself?" can be answered from the box rather than from a DNS lookup that may itself be stale
        $probeOnDC = {
            $report = [pscustomobject]@{ Interfaces = @(); LocalIPs = @(); HasDnsRole = $false; Error = $null }
            try {
                if (-not (Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue)) {
                    throw 'Get-DnsClientServerAddress is not available on this host (Windows Server 2012 or later required).'
                }

                # Get-DnsClientServerAddress returns disabled or unplugged NICs.. Thats obviously not what this DC resolves with
                $connected = @{}
                foreach ($nic in @(Get-NetIPInterface -ErrorAction Stop | Where-Object { $_.ConnectionState -eq 'Connected' })) {
                    $connected[[int]$nic.InterfaceIndex] = $true
                }

                $rows = @()
                foreach ($entry in @(Get-DnsClientServerAddress -ErrorAction Stop)) {
                    if (-not $connected.ContainsKey([int]$entry.InterfaceIndex)) { continue }
                    $servers = @($entry.ServerAddresses | Where-Object { $_ -and $_ -ne '0.0.0.0' -and $_ -ne '::' })
                    if ($servers.Count -eq 0) { continue }
                    $rows += [pscustomobject]@{
                        Alias   = [string]$entry.InterfaceAlias
                        Index   = [int]$entry.InterfaceIndex
                        Servers = $servers
                    }
                }
                $report.Interfaces = $rows

                $report.LocalIPs = @(Get-NetIPAddress -ErrorAction Stop |
                    Where-Object { $_.AddressState -ne 'Invalid' } |
                    ForEach-Object { [string]$_.IPAddress })
                $report.HasDnsRole = [bool](Get-Service -Name DNS -ErrorAction SilentlyContinue)
            } catch {
                $report.Error = $_.Exception.Message
            }
            $report
        }

        $dcSet     = Get-ADTDomainControllerSet -Context $Context -Domain $Context.Domain
        $domainDCs = @($dcSet.DomainControllers)
        $hasPeers  = $domainDCs.Count -gt 1

        # AD only reports IPv4Address, however AAAA is resolved too, so we need to check both
        $dcByIp = @{}
        foreach ($dc in $domainDCs) {
            if ($dc.IPv4) { $dcByIp[(& $normIp $dc.IPv4)] = $dc.Name }
            foreach ($type in 'A','AAAA') {
                try {
                    foreach ($rec in @(Resolve-DnsName -Name $dc.HostName -Type $type -DnsOnly -NoHostsFile -ErrorAction Stop)) {
                        if ($rec.IPAddress) { $dcByIp[(& $normIp $rec.IPAddress)] = $dc.Name }
                    }
                } catch { }
            }
        }

        $remoteRows = Invoke-ADTRemote -ComputerName @($Context.DomainControllers | ForEach-Object { $_.HostName }) -ScriptBlock $probeOnDC
        $rowByHost = @{}
        foreach ($remoteRow in $remoteRows) { $rowByHost[[string]$remoteRow.ComputerName] = $remoteRow }

        $findings = @()

        # If we don't have the full DC list, this could accuse healthy partners. Public resolvers are obviously still wrong regardless of who else is a DC
        if (-not $dcSet.IsComplete) {
            $findings += New-ADTFinding -Severity Info -Area DomainController -Target 'Domain' `
                -Title 'DNS entries were not compared against the full DC list' `
                -Evidence "DC list: $($dcSet.Source)" `
                -RootCause 'Reporting a DNS server as "not a domain controller" needs every DC in the domain, and this run does not have that list - the DC list was narrowed to a single -Server target and the ActiveDirectory module was not available to re-enumerate.' `
                -Impact 'Public resolvers, empty lists, and ordering are still checked; a DNS server that is simply not a DC is not.' `
                -Remediation 'Re-run without -Server, or from a host with the ActiveDirectory RSAT module.'
        }

        foreach ($dc in $Context.DomainControllers) {
            $row = $rowByHost[$dc.HostName]
            if (-not $row -or -not $row.Success) {
                $findings += New-ADTFinding -Severity Low -Area DomainController -Target $dc.Name `
                    -Title "DNS client settings on $($dc.Name) could not be checked" `
                    -Evidence $(if ($row) { [string]$row.Error } else { 'No result row was produced for this DC.' }) `
                    -RootCause 'The check runs on the DC over PowerShell remoting, and this DC could not be reached.' `
                    -Impact 'DNS client misconfiguration on this DC is invisible to this check - treat it as unverified, not healthy.' `
                    -Remediation 'Enable PowerShell remoting to this DC (or run the toolkit from it), then re-run.'
                continue
            }

            $dcReport = $row.Result
            if ($dcReport.Error) {
                $kb = Get-ADTKnowledge -Message ([string]$dcReport.Error)
                $findings += New-ADTFinding -Severity Low -Area DomainController -Target $dc.Name `
                    -Title "Could not read DNS client settings on $($dc.Name)" -Evidence ([string]$dcReport.Error) `
                    -RootCause "Reading the DNS client configuration on the DC failed: $($kb.RootCause)" `
                    -Impact 'DNS client misconfiguration on this DC is invisible to this check - treat it as unverified, not healthy.' `
                    -Remediation $kb.Fix
                continue
            }

            $localIps = @{}
            foreach ($ip in @($dcReport.LocalIPs)) {
                $n = & $normIp $ip
                if ($n) { $localIps[$n] = $true }
            }

            # Classify every entry, keeping its position (rank 1 is the preferred server)
            $views = @()
            foreach ($iface in @($dcReport.Interfaces)) {
                $entries = @()
                $rank = 0
                foreach ($raw in @($iface.Servers)) {
                    $ip = & $normIp $raw
                    if (-not $ip) { continue }
                    $rank++
                    $class = if ($defaultIpv6Dns.ContainsKey($ip))              { 'Default'  }
                                elseif ($ip -eq '127.0.0.1' -or $ip -eq '::1')     { 'Loopback' }
                                elseif ($localIps.ContainsKey($ip))                { 'Self'     }
                                elseif ($dcByIp.ContainsKey($ip))                  { 'DC'       }
                                elseif ($publicDns.ContainsKey($ip))               { 'Public'   }
                                else                                              { 'Unknown'  }
                    $entries += [pscustomobject]@{
                        Ip    = $ip
                        Rank  = $rank
                        Class = $class
                        Owner = $dcByIp[$ip]
                    }
                }

                # An interface carrying only Windows IPv6 placeholders is unconfigured
                if ($entries.Count -eq 0 -or @($entries | Where-Object { $_.Class -ne 'Default' }).Count -eq 0) { continue }

                $views += [pscustomobject]@{
                    Alias   = [string]$iface.Alias
                    Entries = $entries
                    Summary = ("$($iface.Alias): " + (@($entries | ForEach-Object { "$($_.Ip)[$($_.Class)$(if ($_.Owner) { "=$($_.Owner)" })]" }) -join ' > '))
                }
            }

            $evidence   = if ($views.Count -gt 0) { (@($views.Summary) -join ' | ') } else { '(no DNS servers on any connected interface)' }
            $allEntries = @($views | ForEach-Object { $_.Entries })

            if ($allEntries.Count -eq 0) {
                $findings += New-ADTFinding -Severity High -Area DomainController -Target $dc.Name `
                    -Title "$($dc.Name) has no DNS servers configured" -Evidence $evidence `
                    -RootCause 'No connected interface on this DC has a DNS server configured, so it cannot resolve AD locator records reliably.' `
                    -Impact 'Logon, replication, and DC locator lookups from this DC fail or fall back unpredictably.' `
                    -Remediation 'Set this DC''s preferred DNS to a healthy partner DC (or its own static IP) and an alternate to another DC; avoid public resolvers.'
                continue
            }

            $issues   = 0
            $publics  = @($allEntries | Where-Object { $_.Class -eq 'Public'  })
            $unknowns = @($allEntries | Where-Object { $_.Class -eq 'Unknown' })

            if ($publics.Count -gt 0) {
                $preferred = @($publics | Where-Object { $_.Rank -eq 1 })
                $issues++
                $findings += New-ADTFinding -Severity High -Area DomainController -Target $dc.Name `
                    -Title "$($dc.Name) uses public DNS server(s) as a client resolver$(if ($preferred.Count -gt 0) { ' - as its preferred server' })" `
                    -Evidence "$evidence | public: $(@($publics.Ip) -join ', ')" `
                    -RootCause 'A domain controller is configured to query a well-known public resolver. Those servers do not host the AD zones or the locator SRV records.' `
                    -Impact $(if ($preferred.Count -gt 0) {
                        'Every lookup this DC makes goes to the public resolver first, so it cannot locate other DCs or register its own records; replication and authentication break in ways that look intermittent.'
                    } else {
                        'Whenever the entries ahead of it stop answering, this DC falls back to a resolver that knows nothing about AD, and locator lookups start failing.'
                    }) `
                    -Remediation 'Replace public DNS entries with domain controllers only. Internet names belong on the DNS *server* role as forwarders, never on a DC''s DNS *client* list.'
            }

            # If the DC list is incomplete, we can't tell if these are DCs or not
            if ($unknowns.Count -gt 0 -and $dcSet.IsComplete) {
                $preferred = @($unknowns | Where-Object { $_.Rank -eq 1 })
                $issues++
                $findings += New-ADTFinding -Severity $(if ($preferred.Count -gt 0) { 'High' } else { 'Medium' }) -Area DomainController -Target $dc.Name `
                    -Title "$($dc.Name) points DNS at $($unknowns.Count) address(es) that are not a DC$(if ($preferred.Count -gt 0) { ' - including its preferred server' })" `
                    -Evidence "$evidence | not a DC: $(@($unknowns.Ip) -join ', ') | DC list: $($dcSet.Source)" `
                    -RootCause 'Configured DNS servers match neither this host nor any domain controller in the domain. They may be a non-DC DNS server that holds the AD zones, or they may be an appliance or ISP resolver that does not.' `
                    -Impact 'If those hosts are not authoritative for the AD zones, locator lookups and secure dynamic registration from this DC fail.' `
                    -Remediation 'Point the DC DNS client at domain controllers that host the AD DNS zones. If a non-DC DNS server is authoritative for those zones by design, confirm it and treat this finding as expected.'
            }
            elseif ($unknowns.Count -gt 0) {
                # These are unknown, so this DC is unverified - and must not fall through to the OK finding below
                $issues++
                $findings += New-ADTFinding -Severity Info -Area DomainController -Target $dc.Name `
                    -Title "$($dc.Name) has $($unknowns.Count) DNS entry/entries that could not be classified" `
                    -Evidence "$evidence | unclassified: $(@($unknowns.Ip) -join ', ') | DC list: $($dcSet.Source)" `
                    -RootCause 'These DNS servers are neither this host nor a well-known public resolver, and the full DC list needed to tell whether they are domain controllers was not available on this run.' `
                    -Impact 'Treat this DC as unverified rather than healthy: a resolver that knows nothing about AD would look exactly the same here.' `
                    -Remediation 'Re-run without -Server, or from a host with the ActiveDirectory RSAT module, to classify these entries.'
            }

            # Order checks. Loopback resolves before the DNS service has finished loading its zones at boot, so it belongs last, not first
            $loopbackFirst = @($views | Where-Object { $_.Entries[0].Class -eq 'Loopback' })
            if ($loopbackFirst.Count -gt 0) {
                $issues++
                $findings += New-ADTFinding -Severity Low -Area DomainController -Target $dc.Name `
                    -Title "$($dc.Name) lists loopback as its preferred DNS server" `
                    -Evidence (@($loopbackFirst.Summary) -join ' | ') `
                    -RootCause 'The loopback address is first in the DNS client list. The long-standing convention puts a partner DC (or this DC''s own static IP) first and leaves 127.0.0.1 last, reasoning that at boot the DNS service has not necessarily finished loading its AD-integrated zones, so an early self-query can fail where a partner would have answered. Guidance on this has shifted over the years and the practical effect on current Windows is small - treat it as a convention worth following rather than a defect.' `
                    -Impact 'Lookups in the first moments after a reboot may fail and retry, which tends to surface as registration warnings that clear on their own.' `
                    -Remediation 'Put a partner DC (or this DC''s own static IP) first and move 127.0.0.1 to the end of the list. Reasonable to waive if the current order is deliberate.'
            }

            $selfEntries = @($allEntries | Where-Object { $_.Class -in @('Self','Loopback') })
            $onlySelf    = ($selfEntries.Count -eq $allEntries.Count)

            # The DNS island: registers into its own copy of the zone and never learns the others
            if ($onlySelf -and $hasPeers) {
                $issues++
                $findings += New-ADTFinding -Severity Medium -Area DomainController -Target $dc.Name `
                    -Title "$($dc.Name) DNS client points only at itself" -Evidence $evidence `
                    -RootCause "No partner DC is listed anywhere in this DC's DNS client configuration, so it cannot bootstrap name resolution if its own DNS service is down, and it registers into a zone copy it may never reconcile with the others." `
                    -Impact 'During DNS service restarts or local DNS faults, this DC loses AD name resolution entirely, with no fallback.' `
                    -Remediation 'Add another healthy DC as an alternate DNS server.'
            }
            # Opposite check of DNS island. If the DC lists other DCs but not itself, an outage of the partner can take this DC down as well
            elseif ($selfEntries.Count -eq 0 -and $dcReport.HasDnsRole) {
                $issues++
                $findings += New-ADTFinding -Severity Low -Area DomainController -Target $dc.Name `
                    -Title "$($dc.Name) runs DNS but never points at itself" -Evidence $evidence `
                    -RootCause 'This DC hosts the DNS service, yet neither its own address nor loopback appears anywhere in its DNS client list, so every lookup it makes leaves the box.' `
                    -Impact 'If the DNS servers it points at become unreachable, this DC cannot resolve AD names even though a working DNS service is running locally.' `
                    -Remediation 'Add this DC''s own static IP (or 127.0.0.1) to its DNS client list as an alternate, behind a partner DC.'
            }
            # A single entry has nothing to fall back to. This is fine, but probably not intentional
            elseif ($hasPeers) {
                $singles = @($views | Where-Object { $_.Entries.Count -eq 1 })
                if ($singles.Count -gt 0) {
                    $issues++
                    $findings += New-ADTFinding -Severity Low -Area DomainController -Target $dc.Name `
                        -Title "$($dc.Name) has no alternate DNS server on $($singles.Count) interface(s)" `
                        -Evidence (@($singles.Summary) -join ' | ') `
                        -RootCause 'Only one DNS server is configured on this interface, so there is nothing to fall back to when it stops answering. Not a misconfiguration in itself - a working single entry resolves normally - but it leaves no margin.' `
                        -Impact 'A single DNS outage takes AD name resolution on this DC down with it until that server returns.' `
                        -Remediation 'Add a second domain controller as the alternate DNS server.'
                }
            }

            if ($issues -eq 0) {
                $findings += New-ADTFinding -Severity OK -Area DomainController -Target $dc.Name `
                    -Title "$($dc.Name) DNS client settings look healthy" -Evidence $evidence
            }
        }
        return $findings
    }
}
