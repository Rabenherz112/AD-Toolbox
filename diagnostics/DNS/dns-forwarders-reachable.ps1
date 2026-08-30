#Requires -Version 5.1
<#
    Diagnostic: DNS Forwarders Reachable

    Reads each DC's configured DNS forwarders and have that DC resolve a name through each
    one:
      * A forwarder the DC cannot resolve through (dead, refusing recursion, or upstream broken)
      * A forwarder that answers but returns no address for a known-good public name
      * A DC with no forwarders at all - it falls back to root hints, which may be intentional
#>
@{
    Kind              = 'Diagnostic'
    Id                = 'dns-forwarders-reachable'
    Name              = 'DNS Forwarders Reachable'
    Area              = 'DNS'
    Synopsis          = 'Have each DC resolve a public name through every forwarder it is configured to use'
    Writes            = $false
    IncludeInFullTest = $true
    Tags              = @('dns','forwarders','connectivity')

    Run = {
        param($Context)

        if (-not $Context.DomainControllers) {
            return (New-ADTFinding -Severity Info -Area DNS -Target 'Domain' -Title 'No DCs discovered to check')
        }

        # A stable public name with A records, change it if policy forbids resolving this from a DC
        $probeName = 'microsoft.com'

        # Runs ON each DC: reads the LOCAL forwarder list, then resolves through each forwarder
        $probeOnDC = {
            param($probeName)
            $report = [pscustomobject]@{ Forwarders = @(); Results = @(); Error = $null }
            try {
                if (-not (Get-Module -Name DnsServer)) { Import-Module DnsServer -ErrorAction Stop }
                $forwarderConfig   = Get-DnsServerForwarder -ErrorAction Stop
                $report.Forwarders = @($forwarderConfig.IPAddress | ForEach-Object { $_.IPAddressToString } | Where-Object { $_ })
                $probeResults      = @()
                foreach ($forwarderIp in $report.Forwarders) {
                    $timer = [System.Diagnostics.Stopwatch]::StartNew()
                    try {
                        # -NoHostsFile to avoid a local hosts entry masking a broken forwarder
                        $aRecords = @(Resolve-DnsName -Name $probeName -Type A -Server $forwarderIp -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'A' })
                        $timer.Stop()
                        if ($aRecords.Count -gt 0) {
                            $probeResults += [pscustomobject]@{ IP = $forwarderIp; Result = 'Resolved'; ElapsedMs = $timer.ElapsedMilliseconds; Detail = "$($aRecords.Count) A record(s)" }
                        } else {
                            $probeResults += [pscustomobject]@{ IP = $forwarderIp; Result = 'NoAnswer'; ElapsedMs = $timer.ElapsedMilliseconds; Detail = 'answered but returned no A record' }
                        }
                    } catch {
                        $timer.Stop()
                        $probeResults += [pscustomobject]@{ IP = $forwarderIp; Result = 'Failed'; ElapsedMs = $timer.ElapsedMilliseconds; Detail = $_.Exception.Message }
                    }
                }
                $report.Results = $probeResults
            } catch {
                $report.Error = $_.Exception.Message
            }
            $report
        }

        $remoteRows = Invoke-ADTRemote -ComputerName @($Context.DomainControllers | ForEach-Object { $_.HostName }) -ScriptBlock $probeOnDC -ArgumentList $probeName

        # Map rows back to the DC objects so findings can use the short name
        $rowByHost = @{}
        foreach ($remoteRow in $remoteRows) { $rowByHost[[string]$remoteRow.ComputerName] = $remoteRow }

        $findings = @()
        foreach ($dc in $Context.DomainControllers) {
            $row = $rowByHost[$dc.HostName]

            # An unreachable DC is unchecked, not healthy
            if (-not $row -or -not $row.Success) {
                $findings += New-ADTFinding -Severity Low -Area DNS -Target $dc.Name `
                    -Title "Forwarders on $($dc.Name) could not be checked" `
                    -Evidence $(if ($row) { [string]$row.Error } else { 'No result row was produced for this DC.' }) `
                    -RootCause 'The check runs on the DC over PowerShell remoting, and this DC could not be reached, so its forwarders were not tested at all.' `
                    -Impact 'Forwarder faults on this DC are invisible to this check - treat it as unverified, not healthy.' `
                    -Remediation 'Enable PowerShell remoting to this DC (or run the toolkit from it), then re-run.'
                continue
            }

            $dcReport = $row.Result
            if ($dcReport.Error) {
                $kb = Get-ADTKnowledge -Message ([string]$dcReport.Error)
                $findings += New-ADTFinding -Severity Low -Area DNS -Target $dc.Name `
                    -Title "Could not read DNS forwarders on $($dc.Name)" -Evidence ([string]$dcReport.Error) `
                    -RootCause "Reading the forwarder list on the DC failed: $($kb.RootCause)" -Remediation $kb.Fix
                continue
            }

            $forwarderIps = @($dcReport.Forwarders)
            if (-not $forwarderIps) {
                $findings += New-ADTFinding -Severity Info -Area DNS -Target $dc.Name `
                    -Title "$($dc.Name) has no DNS forwarders configured" `
                    -RootCause 'No forwarders are set, so this server resolves external names through root hints.' `
                    -Remediation 'This may be intentional. If external resolution is expected via forwarders, configure them.'
                continue
            }

            $probeResults = @($dcReport.Results)
            $notResolving = @($probeResults | Where-Object { $_.Result -ne 'Resolved' })
            $evidence     = (@($probeResults | ForEach-Object {
                "$($_.IP)=$($_.Result) ($($_.ElapsedMs) ms)$(if ($_.Result -ne 'Resolved' -and $_.Detail) { " - $($_.Detail)" })"
            }) -join ', ')

            if ($notResolving.Count -eq 0) {
                $findings += New-ADTFinding -Severity OK -Area DNS -Target $dc.Name `
                    -Title "$($dc.Name): all $($forwarderIps.Count) forwarder(s) resolving" -Evidence $evidence
                continue
            }

            # Losing one of several forwarders only degrades resolution; losing them all breaks it
            $noneResolving = ($notResolving.Count -eq $forwarderIps.Count)
            $findings += New-ADTFinding -Severity $(if ($noneResolving) { 'High' } else { 'Medium' }) -Area DNS -Target $dc.Name `
                -Title "$($dc.Name): $($notResolving.Count) of $($forwarderIps.Count) DNS forwarder(s) not resolving" `
                -Evidence $evidence `
                -RootCause "$($dc.Name) could not resolve '$probeName' through $(@($notResolving.IP) -join ', ')." `
                -Impact $(if ($noneResolving) {
                    'Every forwarder on this DC is unusable, so external name resolution from it fails or times out.'
                } else {
                    'Resolution still works through the surviving forwarder(s), but each query to a dead one costs a timeout first.'
                }) `
                -Remediation 'Verify the forwarder addresses are correct, reachable from THIS DC, and willing to recurse for it. Then remove or replace the dead ones.'
        }
        return $findings
    }
}
