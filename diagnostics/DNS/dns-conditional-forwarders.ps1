#Requires -Version 5.1
<#
    Diagnostic: DNS Conditional Forwarders

    Conditional forwarders send one namespace to a specific set of DNS servers:
      * A forwarded zone whose target servers do not answer at all (the zone is dead)
      * A target that answers but is not serving the zone (forwarding to the wrong server)
      * A conditional forwarder with no target servers configured
      * An AD-integrated conditional forwarder that has not reached every DC
#>
@{
    Kind              = 'Diagnostic'
    Id                = 'dns-conditional-forwarders'
    Name              = 'DNS Conditional Forwarders'
    Area              = 'DNS'
    Synopsis          = 'Have each DC look up every conditionally forwarded zone through its target servers'
    Writes            = $false
    IncludeInFullTest = $true
    Tags              = @('dns','forwarders','connectivity')

    Run = {
        param($Context)

        if (-not $Context.DomainControllers) {
            return (New-ADTFinding -Severity Info -Area DNS -Target 'Domain' -Title 'No DCs discovered to check')
        }

        # Runs ON each DC: reads the LOCAL conditional forwarders, then queries each target for the zone it is supposed to be serving
        $probeOnDC = {
            $report = [pscustomobject]@{ Zones = @(); Error = $null }
            try {
                if (-not (Get-Module -Name DnsServer)) { Import-Module DnsServer -ErrorAction Stop }
                $forwarderZones = @(Get-DnsServerZone -ErrorAction Stop | Where-Object { $_.ZoneType -eq 'Forwarder' })
                $zoneReports = @()
                foreach ($zone in $forwarderZones) {
                    $targetIps   = @($zone.MasterServers | ForEach-Object { $_.IPAddressToString } | Where-Object { $_ })
                    $probeResults = @()
                    foreach ($targetIp in $targetIps) {
                        $timer = [System.Diagnostics.Stopwatch]::StartNew()
                        try {
                            # SOA for the zone itself: proves the target actually serves this zone
                            $answers = @(Resolve-DnsName -Name $zone.ZoneName -Type SOA -Server $targetIp -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
                            $timer.Stop()
                            $soa = @($answers | Where-Object { $_.Type -eq 'SOA' })
                            if ($soa.Count -gt 0) {
                                $probeResults += [pscustomobject]@{ IP = $targetIp; Result = 'Resolved'; ElapsedMs = $timer.ElapsedMilliseconds; Detail = 'returned SOA' }
                            } else {
                                $probeResults += [pscustomobject]@{ IP = $targetIp; Result = 'NoZoneData'; ElapsedMs = $timer.ElapsedMilliseconds; Detail = 'answered but returned no SOA for this zone' }
                            }
                        } catch {
                            $timer.Stop()
                            $probeResults += [pscustomobject]@{ IP = $targetIp; Result = 'Failed'; ElapsedMs = $timer.ElapsedMilliseconds; Detail = $_.Exception.Message }
                        }
                    }
                    $zoneReports += [pscustomobject]@{
                        ZoneName     = [string]$zone.ZoneName
                        Targets      = $targetIps
                        Results      = $probeResults
                        DsIntegrated = [bool]$zone.IsDsIntegrated
                    }
                }
                $report.Zones = $zoneReports
            } catch {
                $report.Error = $_.Exception.Message
            }
            $report
        }

        $remoteRows = Invoke-ADTRemote -ComputerName @($Context.DomainControllers | ForEach-Object { $_.HostName }) -ScriptBlock $probeOnDC

        $rowByHost = @{}
        foreach ($remoteRow in $remoteRows) { $rowByHost[[string]$remoteRow.ComputerName] = $remoteRow }

        $findings   = @()
        $checkedDCs = @()          # DCs whose conditional forwarders we actually read
        $zoneByName = @{}          # zone name -> list of per-DC reports, for the cross-DC view

        foreach ($dc in $Context.DomainControllers) {
            $row = $rowByHost[$dc.HostName]

            # An unreachable DC is unchecked, not healthy
            if (-not $row -or -not $row.Success) {
                $findings += New-ADTFinding -Severity Low -Area DNS -Target $dc.Name `
                    -Title "Conditional forwarders on $($dc.Name) could not be checked" `
                    -Evidence $(if ($row) { [string]$row.Error } else { 'No result row was produced for this DC.' }) `
                    -RootCause 'The check runs on the DC over PowerShell remoting, and this DC could not be reached, so its conditional forwarders were not tested at all.' `
                    -Impact 'Dead conditional forwarders on this DC are invisible to this check - treat it as unverified, not healthy.' `
                    -Remediation 'Enable PowerShell remoting to this DC (or run the toolkit from it), then re-run.'
                continue
            }

            $dcReport = $row.Result
            if ($dcReport.Error) {
                $kb = Get-ADTKnowledge -Message ([string]$dcReport.Error)
                $findings += New-ADTFinding -Severity Low -Area DNS -Target $dc.Name `
                    -Title "Could not read conditional forwarders on $($dc.Name)" -Evidence ([string]$dcReport.Error) `
                    -RootCause "Reading the zone list on the DC failed: $($kb.RootCause)" -Remediation $kb.Fix
                continue
            }

            $checkedDCs += $dc.Name
            foreach ($zoneReport in @($dcReport.Zones)) {
                $name = [string]$zoneReport.ZoneName
                if (-not $zoneByName.ContainsKey($name)) { $zoneByName[$name] = @() }
                $zoneByName[$name] += [pscustomobject]@{ DC = $dc.Name; Report = $zoneReport }
            }
        }

        if ($checkedDCs.Count -eq 0) { return $findings }
        if ($zoneByName.Count -eq 0) {
            return @($findings + (New-ADTFinding -Severity Info -Area DNS -Target 'Domain' `
                -Title "No conditional forwarders are configured on $($checkedDCs.Count) checked DC(s)" `
                -Evidence (@($checkedDCs) -join ', ')))
        }

        # A DC that is dead for EVERY zone it forwards is one broken DC
        $heldZonesByDC = @{}   # DC -> zones it forwards (that have targets configured)
        $deadZonesByDC = @{}   # DC -> those zones where every target failed
        foreach ($name in $zoneByName.Keys) {
            foreach ($entry in @($zoneByName[$name])) {
                $targets = @($entry.Report.Targets)
                if ($targets.Count -eq 0) { continue }   # no-target zones are their own finding
                if (-not $heldZonesByDC.ContainsKey($entry.DC)) { $heldZonesByDC[$entry.DC] = @() }
                $heldZonesByDC[$entry.DC] += $name
                if (@($entry.Report.Results | Where-Object { $_.Result -ne 'Resolved' }).Count -eq $targets.Count) {
                    if (-not $deadZonesByDC.ContainsKey($entry.DC)) { $deadZonesByDC[$entry.DC] = @() }
                    $deadZonesByDC[$entry.DC] += $name
                }
            }
        }
        # Needs at least two zones to be a pattern
        $collapsedDCs = @($heldZonesByDC.Keys | Where-Object {
            $heldZonesByDC[$_].Count -ge 2 -and
            $deadZonesByDC.ContainsKey($_) -and
            $deadZonesByDC[$_].Count -eq $heldZonesByDC[$_].Count
        })

        foreach ($deadDC in ($collapsedDCs | Sort-Object)) {
            $deadZones  = @($deadZonesByDC[$deadDC] | Sort-Object)
            $everywhere = ($collapsedDCs.Count -eq $checkedDCs.Count)
            $findings += New-ADTFinding -Severity $(if ($everywhere) { 'High' } else { 'Medium' }) -Area DNS -Target $deadDC `
                -Title "$deadDC cannot resolve any of its $($deadZones.Count) conditionally forwarded zones" `
                -Evidence ($deadZones -join ', ') `
                -RootCause "Every conditional forwarder on $deadDC failed for its own zone. When one DC fails for all of them, the cause is that DC's path to the target servers rather than the zones themselves." `
                -Impact $(if ($everywhere) {
                    'No DC can resolve any conditionally forwarded namespace - forwarding is broken domain-wide.'
                } else {
                    "Clients using $deadDC cannot resolve any of these namespaces; the other DCs resolve them normally."
                }) `
                -Remediation "Check network reachability from $deadDC to the forwarder target servers - firewall, routing, or site egress - before changing any zone configuration."
        }

        # One finding per zone, aggregated across DCs
        foreach ($zoneName in ($zoneByName.Keys | Sort-Object)) {
            $perDC = @($zoneByName[$zoneName])

            $noTargets = @($perDC | Where-Object { @($_.Report.Targets).Count -eq 0 })
            if ($noTargets.Count -gt 0) {
                $findings += New-ADTFinding -Severity Medium -Area DNS -Target $zoneName `
                    -Title "Conditional forwarder '$zoneName' has no target servers on $($noTargets.Count) DC(s)" `
                    -Evidence ('No targets on: ' + (@($noTargets.DC) -join ', ')) `
                    -RootCause 'The forwarder zone exists but lists no servers to forward to, so queries for this namespace can never be answered through it.' `
                    -Impact "Names under '$zoneName' do not resolve on those DCs." `
                    -Remediation 'Set the target DNS servers on the conditional forwarder, or delete the zone if it is obsolete.'
            }

            # Reachability differs per DC
            $brokenPerDC = @()
            foreach ($entry in ($perDC | Where-Object { @($_.Report.Targets).Count -gt 0 -and $_.DC -notin $collapsedDCs })) {
                $failed = @($entry.Report.Results | Where-Object { $_.Result -ne 'Resolved' })
                if ($failed.Count -gt 0) {
                    $brokenPerDC += [pscustomobject]@{
                        DC      = $entry.DC
                        Failed  = $failed
                        Total   = @($entry.Report.Targets).Count
                        Summary = ($entry.DC + ': ' + (@($entry.Report.Results | ForEach-Object {
                            "$($_.IP)=$($_.Result) ($($_.ElapsedMs) ms)$(if ($_.Result -ne 'Resolved' -and $_.Detail) { " - $($_.Detail)" })"
                        }) -join ', '))
                    }
                }
            }

            $nameDCs = { param($dcNames)
                if (@($dcNames).Count -le 3) { @($dcNames) -join ', ' } else { "$(@($dcNames).Count) of $($perDC.Count) DC(s)" }
            }

            # Severity follows breadth first, then depth
            $deadOnDC     = @($brokenPerDC | Where-Object { $_.Failed.Count -eq $_.Total })
            $degradedOnDC = @($brokenPerDC | Where-Object { $_.Failed.Count -lt $_.Total })

            if ($deadOnDC.Count -gt 0) {
                $everywhere = ($deadOnDC.Count -eq @($perDC | Where-Object { $_.DC -notin $collapsedDCs }).Count)
                $findings += New-ADTFinding -Severity $(if ($everywhere) { 'High' } else { 'Medium' }) -Area DNS -Target $zoneName `
                    -Title "Conditional forwarder '$zoneName' does not resolve at all from $(& $nameDCs @($deadOnDC.DC))" `
                    -Evidence (@($deadOnDC.Summary) -join ' | ') `
                    -RootCause "Every server '$zoneName' forwards to either did not answer, or answered without serving the zone." `
                    -Impact $(if ($everywhere) {
                        "The '$zoneName' namespace does not resolve anywhere in the domain - the forwarded zone is dead."
                    } else {
                        "Clients using $(& $nameDCs @($deadOnDC.DC)) cannot resolve names under '$zoneName'; other DCs still can."
                    }) `
                    -Remediation 'Confirm the target servers are correct, reachable from the affected DCs, and authoritative for this zone - a target reachable from one site is often firewalled from another.'
            }

            if ($degradedOnDC.Count -gt 0) {
                $findings += New-ADTFinding -Severity Low -Area DNS -Target $zoneName `
                    -Title "Conditional forwarder '$zoneName' has unreachable target(s) from $(& $nameDCs @($degradedOnDC.DC))" `
                    -Evidence (@($degradedOnDC.Summary) -join ' | ') `
                    -RootCause "Some of the servers '$zoneName' forwards to did not answer, but at least one still serves the zone." `
                    -Impact "Names under '$zoneName' still resolve, but every query that hits a dead target costs a timeout first, and the redundancy is gone." `
                    -Remediation 'Remove or replace the unreachable target servers on this conditional forwarder.'
            }

            # An AD-integrated conditional forwarder should exist everywhere, a local one should not
            $missingOn = @($checkedDCs | Where-Object { $_ -notin @($perDC.DC) })
            if ($missingOn.Count -gt 0) {
                $dsIntegrated = @($perDC | Where-Object { $_.Report.DsIntegrated })
                if ($dsIntegrated.Count -gt 0) {
                    $findings += New-ADTFinding -Severity Medium -Area DNS -Target $zoneName `
                        -Title "AD-integrated conditional forwarder '$zoneName' is missing on $($missingOn.Count) DC(s)" `
                        -Evidence ('Present on: ' + (@($perDC.DC) -join ', ') + ' | Missing on: ' + (@($missingOn) -join ', ')) `
                        -RootCause 'The forwarder zone is AD-integrated, so it should replicate to every DC, but some do not have it - replication has not converged or the replication scope excludes them.' `
                        -Impact "Those DCs resolve '$zoneName' by normal recursion instead of forwarding, which may fail or reach the wrong servers." `
                        -Remediation @{ Text='Check the zone replication scope, then let AD replication converge or force it.'; ActionId='force-replication' }
                } else {
                    $findings += New-ADTFinding -Severity Low -Area DNS -Target $zoneName `
                        -Title "Conditional forwarder '$zoneName' is defined locally on only $($perDC.Count) of $($checkedDCs.Count) DC(s)" `
                        -Evidence ('Present on: ' + (@($perDC.DC) -join ', ') + ' | Not present on: ' + (@($missingOn) -join ', ')) `
                        -RootCause 'The forwarder zone is not AD-integrated, so it exists only on the servers where it was created. Its absence elsewhere is expected rather than a replication fault.' `
                        -Impact "DCs without it resolve '$zoneName' by normal recursion, so the namespace behaves differently depending on which DC a client asks." `
                        -Remediation 'Make the conditional forwarder AD-integrated so every DC uses it, or confirm the inconsistency is deliberate.'
                }
            }
        }

        if (-not ($findings | Where-Object { $_.Rank -ge 2 })) {
            $findings += New-ADTFinding -Severity OK -Area DNS -Target 'Domain' `
                -Title "All $($zoneByName.Count) conditional forwarder(s) resolvable from $($checkedDCs.Count) DC(s)" `
                -Evidence (($zoneByName.Keys | Sort-Object) -join ', ')
        }
        return $findings
    }
}
