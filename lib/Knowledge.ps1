#Requires -Version 5.1
<#
    Knowledge.ps1 - The interpretation knowledge base (the core value-add)

    Maps Win32 / AD / DNS / Kerberos error codes and known failure signatures to a
    plain-English RootCause, a concrete Fix, the impact, a recommended remediation Action id,
    and a reference URL. Diagnostics call Get-ADTKnowledge instead of dumping raw error text,
    so every finding is actionable and the linked Action is correct per error code (e.g.
    8457 -> remove lingering objects, 8614 -> NO auto-action, it would be destructive)

    Two lookup modes:
      -Code <n>      explicit numeric code (from repadmin etc.): matched exactly (should be the preferred method to use this module)
      -Message <txt> free tool text (nltest/netdom/LDAP/service errors): matched by signature first, then by any DISTINCTIVE (>=3-digit) code embedded in the text.
                     Small ambiguous codes (5, 58) are intentionally NOT matched from free text, so a phrase like "Kerberos 5-minute" is never mis-tagged as "Access denied"

    To extend: add an entry to $script:ADTKnowledgeBase (keyed by the numeric code as a string)
    or a regex to $script:ADTSignatures. 'Action' must be an existing action id (or $null for
    "manual only"); this is enforced by the engine tests
#>

$script:ADTKnowledgeBase = @{

    '1256' = @{
        Title     = 'The remote system is not available (RPC server too busy / offline)'
        RootCause = 'The partner DC was unreachable for RPC at the time of the attempt (offline, busy, or blocked).'
        Impact    = 'Inbound replication from that partner is delayed; data diverges until it recovers.'
        Fix       = 'Confirm the partner DC is online and reachable; if it is decommissioned, clean up its metadata. Then re-trigger replication.'
        Action    = $null
        Url       = 'https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-1256'
    }
    '1355' = @{
        Title     = 'The specified domain either does not exist or could not be contacted'
        RootCause = 'The domain could not be located - DNS resolution, network connectivity, or the DC being down.'
        Impact    = 'Domain-dependent operations (joins, lookups, replication setup) fail.'
        Fix       = 'Check DNS (the client must use AD DNS), connectivity to a DC, and SRV records.'
        Action    = $null
        Url       = 'https://learn.microsoft.com/troubleshoot/windows-server/active-directory/'
    }
    '8240' = @{
        Title     = 'There is no such object on the server'
        RootCause = 'The directory object referenced by the operation does not exist on the target DC (may be a not-yet-replicated or already-deleted object).'
        Impact    = 'The operation referencing that object fails.'
        Fix       = 'Confirm the object exists and has replicated to the target; check replication latency for the partition.'
        Action    = $null
        Url       = 'https://learn.microsoft.com/troubleshoot/windows-server/active-directory/'
    }
    '8451' = @{
        Title     = 'The replication operation encountered a database error'
        RootCause = 'The NTDS database (ntds.dit) returned an error during replication - possible corruption or disk problem.'
        Impact    = 'Replication stalls; the DC may need database repair or rebuild.'
        Fix       = 'Check disk health and free space; review Directory Service events; consider an offline integrity check (ntdsutil), and in severe cases demote/repromote.'
        Action    = $null
        Url       = 'https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-8451'
    }
    '8453' = @{
        Title     = 'Replication access was denied'
        RootCause = 'The destination DC was denied access to read changes - missing replication permissions, a broken secure channel, or removed "Replicating Directory Changes" rights.'
        Impact    = 'The partition does not replicate inbound; data diverges.'
        Fix       = 'Verify the DC computer account, secure channel (nltest /sc_query), and that default replication permissions on the partition head are intact.'
        Action    = 'repair-secure-channel'
        Url       = 'https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-8453-replication-access-was-denied'
    }
    '8456' = @{
        Title     = 'The source server is currently rejecting replication requests'
        RootCause = 'Replication has been administratively or automatically disabled on the source DC (e.g. DISABLE_OUTBOUND_REPL, or it is in a recovery/quarantine state).'
        Impact    = 'No changes flow from this source until replication is re-enabled.'
        Fix       = 'Check repadmin /options for DISABLE_OUTBOUND_REPL and the DC health; re-enable replication only after confirming the DC is healthy (NOT for an 8614-quarantined DC).'
        Action    = $null
        Url       = 'https://learn.microsoft.com/troubleshoot/windows-server/active-directory/'
    }
    '8457' = @{
        Title     = 'The destination server is currently rejecting replication requests'
        RootCause = 'Inbound replication has been disabled on the destination DC (DISABLE_INBOUND_REPL) or it is recovering.'
        Impact    = 'The destination DC does not receive changes until re-enabled.'
        Fix       = 'Check repadmin /options for DISABLE_INBOUND_REPL; re-enable once the DC is confirmed healthy.'
        Action    = $null
        Url       = 'https://learn.microsoft.com/troubleshoot/windows-server/active-directory/'
    }
    '8614' = @{
        Title     = 'The directory service cannot replicate because the time since the last replication exceeds the tombstone lifetime'
        RootCause = 'This DC has not replicated within the tombstone lifetime, so it is no longer allowed to replicate (to avoid resurrecting deleted objects).'
        Impact    = 'The DC is replication-quarantined; it must be remediated or demoted/repromoted.'
        Fix       = 'Do NOT force-enable replication blindly - that can resurrect deleted objects. Investigate lingering objects, then demote/repromote the DC or perform a careful recovery.'
        Action    = $null
        Url       = 'https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-8614'
    }
}

# Signature-based interpretation for tool output that does not carry a clean numeric code
# Order matters: more specific patterns first
$script:ADTSignatures = @(
    @{ Pattern = 'no such object'; Code = '8240' }
)

function Get-ADTKnowledge {
    <#
        .SYNOPSIS
        Interpret an error code or a raw message/signature into RootCause + Fix + recommended Action

        .EXAMPLE
        $kb = Get-ADTKnowledge -Code 1722
        $kb = Get-ADTKnowledge -Message $repadminLine
    #>
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName='Code', Position=0)]
        $Code,

        [Parameter(ParameterSetName='Message', Position=0)]
        [string]$Message
    )

    $key = $null
    if ($PSCmdlet.ParameterSetName -eq 'Code' -and $null -ne $Code) {
        # Explicit code: match exactly (any code, including the small/ambiguous ones)
        $m = [regex]::Match([string]$Code, '-?\d+')
        if ($m.Success) { $key = $m.Value }
    }
    elseif ($Message) {
        # Free text: signatures first (most reliable), then a DISTINCTIVE (>=3-digit) embedded code. Small ambiguous codes (5/58) are never matched from free text
        foreach ($sig in $script:ADTSignatures) {
            if ($Message -match $sig.Pattern) { $key = $sig.Code; break }
        }
        if (-not $key) {
            foreach ($mm in [regex]::Matches($Message, '-?\d{3,10}')) {
                if ($script:ADTKnowledgeBase.ContainsKey($mm.Value)) { $key = $mm.Value; break }
            }
        }
    }

    if ($key -and $script:ADTKnowledgeBase.ContainsKey($key)) {
        $e = $script:ADTKnowledgeBase[$key]
        return [pscustomobject]@{
            Code      = $key
            Title     = $e.Title
            RootCause = $e.RootCause
            Impact    = $e.Impact
            Fix       = $e.Fix
            Action    = $e.Action
            Url       = $e.Url
            Known     = $true
        }
    }

    # Unknown - return a generic, still-structured result so callers never special-case
    $shown = if ($Message) { $Message } elseif ($null -ne $Code) { "code $Code" } else { 'unknown error' }
    [pscustomobject]@{
        Code      = $key
        Title     = "Uninterpreted error ($shown)"
        RootCause = "No knowledge-base entry for this error yet. Raw detail: $shown"
        Impact    = 'Unknown - review the evidence and the Directory Service event log.'
        Fix       = 'Investigate manually; consider adding this code to lib/Knowledge.ps1 once root cause is understood.'
        Action    = $null
        Url       = 'https://learn.microsoft.com/troubleshoot/windows-server/active-directory/'
        Known     = $false
    }
}
