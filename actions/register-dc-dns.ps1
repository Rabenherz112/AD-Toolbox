#Requires -Version 5.1
<#
    Action: Re-register DC DNS Records

    Makes a DC republish the records it owns:
      * its host A/AAAA records          (Register-DnsClient, i.e. ipconfig /registerdns)
      * its locator SRV and _msdcs records (nltest /dsregdns)

    IMPORTANT: This is idempotent and additive i.e it re-registers what the DC believes it should own and removes
    nothing, so it cannot clean up records for a DC that no longer exists (those are deleted by hand or by scavenging).

    Linked from dns-dc-srv-record
#>
@{
    Kind              = 'Action'
    Id                = 'register-dc-dns'
    Name              = 'Re-register DC DNS Records'
    Area              = 'DNS'
    Synopsis          = 'Re-register a DCs host and locator records (Register-DnsClient + nltest /dsregdns)'
    RiskLevel         = 'LowImpact'
    RequiresElevation = $true
    Tags              = @('dns','locator','remediation')

    Run = {
        param($Context, $Target)

        # An explicit target wins; otherwise every DC currently in scope (which -Server has already narrowed, if it was passed)
        $targets = if ($Target) { @($Target | Where-Object { $_ }) }
                   else { @($Context.DomainControllers | ForEach-Object { $_.HostName }) }

        if (-not $targets -or $targets.Count -eq 0) {
            return (New-ADTFinding -Severity Error -Area DNS -Target 'Domain' -Title 'No DC available to target' `
                    -RootCause 'No DC was discovered and none was supplied via -Server or a target prompt.')
        }

        if ($Context.WhatIf) {
            return (New-ADTFinding -Severity Info -Area DNS -Target ([string]$targets[0]) `
                    -Title "WhatIf: would re-register DNS records on $($targets.Count) DC(s)" `
                    -Evidence ($targets -join ', ') `
                    -RootCause 'No change made (WhatIf)')
        }

        # Runs ON the DC: host records first, then the locator/_msdcs set (Register-DnsClient + nltest /dsregdns)
        $registerOnDC = {
            $result = [pscustomobject]@{ Steps = @(); Failed = $false; Error = $null }
            try {
                if (Get-Command Register-DnsClient -ErrorAction SilentlyContinue) {
                    try {
                        Register-DnsClient -ErrorAction Stop
                        $result.Steps += 'Register-DnsClient: host records re-registered'
                    } catch {
                        $result.Steps += "Register-DnsClient: FAILED - $($_.Exception.Message)"
                        $result.Failed = $true
                    }
                } else {
                    $null = & ipconfig /registerdns 2>&1
                    $result.Steps += "ipconfig /registerdns: exit $LASTEXITCODE"
                    if ($LASTEXITCODE -ne 0) { $result.Failed = $true }
                }

                $out  = & nltest /dsregdns 2>&1
                $code = $LASTEXITCODE
                $text = (@(($out | Out-String) -split "`r?`n" | Where-Object { $_.Trim() }) -join '; ')
                $result.Steps += "nltest /dsregdns: exit $code - $text"
                if ($code -ne 0) {
                    $result.Failed = $true
                    $result.Error  = "nltest /dsregdns returned $code"
                }
            } catch {
                $result.Failed = $true
                $result.Error  = $_.Exception.Message
            }
            $result
        }

        $remoteRows = Invoke-ADTRemote -ComputerName $targets -ScriptBlock $registerOnDC
        $rowByHost  = @{}
        foreach ($remoteRow in $remoteRows) { $rowByHost[[string]$remoteRow.ComputerName] = $remoteRow }

        $findings = @()
        foreach ($t in $targets) {
            $row = $rowByHost[[string]$t]

            if ($row -and $row.Success) {
                $res      = $row.Result
                $evidence = (@($res.Steps) -join ' | ')
                if ($res.Failed) {
                    $kb = Get-ADTKnowledge -Message ([string]$(if ($res.Error) { $res.Error } else { $evidence }))
                    $findings += New-ADTFinding -Severity High -Area DNS -Target $t `
                        -Title "Re-registering DNS records on $t reported errors" -Evidence $evidence `
                        -RootCause $kb.RootCause -Impact $kb.Impact -Remediation $kb.Fix
                } else {
                    $findings += New-ADTFinding -Severity OK -Area DNS -Target $t `
                        -Title "DNS records re-registered on $t" -Evidence $evidence `
                        -RootCause 'The DC re-published its host records and its locator/_msdcs records.' `
                        -Impact 'Registration can take a few minutes to replicate; re-run dns-dc-srv-record to confirm.'
                }
                continue
            }

            # Remoting failed. nltest can still reach the DC's Netlogon service directly, which covers the locator records, but not the host A record, so say so
            $remoteError = if ($row) { [string]$row.Error } else { 'No result row was produced for this DC.' }
            if (-not (Get-Command nltest -ErrorAction SilentlyContinue)) {
                $findings += New-ADTFinding -Severity High -Area DNS -Target $t `
                    -Title "Could not re-register DNS records on $t" -Evidence $remoteError `
                    -RootCause 'PowerShell remoting to this DC failed and nltest is not available on this host, so neither route to the DC was usable.' `
                    -Impact 'This DC still has not re-registered its records.' `
                    -Remediation "Run 'ipconfig /registerdns' and 'nltest /dsregdns' on $t directly, or install RSAT here and re-run."
                continue
            }

            $out  = & nltest /dsregdns /server:$t 2>&1
            $code = $LASTEXITCODE
            $text = (@(($out | Out-String) -split "`r?`n" | Where-Object { $_.Trim() }) -join '; ')
            if ($code -eq 0) {
                $findings += New-ADTFinding -Severity Low -Area DNS -Target $t `
                    -Title "Locator records re-registered on $t, host record was not" `
                    -Evidence "remoting: $remoteError | nltest /dsregdns /server:$t -> exit 0 - $text" `
                    -RootCause 'PowerShell remoting to this DC failed, so only the remote-capable step ran. nltest re-registered the locator and _msdcs records; the host A record is registered by the DC itself and has to be triggered on the box.' `
                    -Impact 'If the missing record was the DC A record rather than an SRV record, it is still missing.' `
                    -Remediation "Run 'ipconfig /registerdns' on $t, or enable PowerShell remoting to it and re-run this action."
            } else {
                $kb = Get-ADTKnowledge -Message $text
                $findings += New-ADTFinding -Severity High -Area DNS -Target $t `
                    -Title "Could not re-register DNS records on $t" `
                    -Evidence "remoting: $remoteError | nltest /dsregdns /server:$t -> exit $code - $text" `
                    -RootCause $kb.RootCause -Impact $kb.Impact -Remediation $kb.Fix
            }
        }
        return $findings
    }
}
