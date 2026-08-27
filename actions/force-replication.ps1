#Requires -Version 5.1
<#
    Action: Force Replication (syncall)

    Pushes/pulls all naming contexts on a DC (default: the PDC emulator) using
    repadmin /syncall /AdeP. Low impact - it only triggers normal replication sooner
    Linked from dns-zone-sync
#>
@{
    Kind              = 'Action'
    Id                = 'force-replication'
    Name              = 'Force Replication (syncall /AdeP)'
    Area              = 'Replication'
    Synopsis          = 'repadmin /syncall /AdeP on a DC to converge all partitions now'
    RiskLevel         = 'LowImpact'
    RequiresElevation = $true
    Requires          = @('repadmin')
    Tags              = @('replication','remediation')

    Run = {
        param($Context, $Target)

        $dc = if ($Target) { $Target }
            elseif ($Context.Fsmo.PDCEmulator) { $Context.Fsmo.PDCEmulator }
            else { ($Context.DomainControllers | Select-Object -First 1).HostName }

        if (-not $dc) {
            return (New-ADTFinding -Severity Error -Area Replication -Target 'Domain' -Title 'No DC available to target' -RootCause 'No DC was discovered and none was supplied via -Server')
        }

        if ($Context.WhatIf) {
            return (New-ADTFinding -Severity Info -Area Replication -Target $dc `
                    -Title "WhatIf: would run 'repadmin /syncall $dc /AdeP'" `
                    -RootCause 'No change made (WhatIf)')
        }

        $out = repadmin /syncall $dc /AdeP 2>&1
        $text = ($out | Out-String)
        $bad  = ($text -match 'error|failed|fehler|0x[0-9a-fA-F]')

        if ($bad) {
            $kb = Get-ADTKnowledge -Message $text
            return (New-ADTFinding -Severity High -Area Replication -Target $dc `
                    -Title "Forced replication on $dc reported errors" `
                    -Evidence $text -RootCause $kb.RootCause -Impact $kb.Impact -Remediation $kb.Fix)
        }
        return (New-ADTFinding -Severity OK -Area Replication -Target $dc `
                -Title "Forced replication on $dc completed" `
                -Evidence $text -RootCause 'repadmin /syncall completed without reporting errors')
    }
}
