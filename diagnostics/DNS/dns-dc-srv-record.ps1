#Requires -Version 5.1
<#
    Diagnostic: DC Locator / SRV Record Integrity

    Resolves the DNS records AD depends on to function pinpoints the missing/stale record AND which DC owns it:
      * the domain _ldap/_kerberos SRV records
      * every DC's A record
      * each DC's GUID._msdcs CNAME
#>
@{
    Kind              = 'Diagnostic'
    Id                = 'dns-dc-srv-record'
    Name              = 'DC Locator / SRV Record Integrity'
    Area              = 'DNS'
    Synopsis          = 'Resolve the SRV/A/_msdcs records DCs rely on; flag missing/stale ones'
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
            try { return @(Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop) }
            catch { return $null }
        }

        # 1) Domain-wide locator SRV records
        $srvChecks = @(
            @{ Name = "_ldap._tcp.dc._msdcs.$domain";     Label = 'LDAP DC locator';     Severity = 'Critical' },
            @{ Name = "_kerberos._tcp.dc._msdcs.$domain"; Label = 'Kerberos KDC locator'; Severity = 'High' },
            @{ Name = "_gc._tcp.$forest";                 Label = 'Global Catalog locator'; Severity = 'High' }
        )
        foreach ($srvCheck in $srvChecks) {
            $srvRecords = & $resolveDns $srvCheck.Name 'SRV'
            if (-not $srvRecords) {
                $findings += New-ADTFinding -Severity $srvCheck.Severity -Area DNS -Target 'Domain' `
                    -Title "$($srvCheck.Label) SRV record missing: $($srvCheck.Name)" `
                    -RootCause "The SRV record $($srvCheck.Name) did not resolve from this host's DNS." `
                    -Impact 'Clients/DCs cannot locate the service; logons, replication topology, or GC lookups fail.' `
                    -Remediation @{ Text='Ensure DCs register their SRV records (restart Netlogon) and that this host queries an AD DNS server.'; ActionId='register-dns' }
            } else {
                $findings += New-ADTFinding -Severity OK -Area DNS -Target 'Domain' -Title "$($srvCheck.Label) SRV present ($(@($srvRecords).Count) record(s))"
            }
        }

        # 2) Per-DC A records (and _msdcs CNAME when AD module available for objectGUID)
        $dcGuidByHost = @{}
        if ($Context.HasADModule) {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                foreach ($dc in (Get-ADDomainController -Filter * -ErrorAction Stop)) {
                    $dcGuidByHost[$dc.HostName] = $dc.ObjectGUID
                }
            } catch { }
        }

        foreach ($dc in $Context.DomainControllers) {
            $aRecords = & $resolveDns $dc.HostName 'A'
            if (-not $aRecords) {
                $findings += New-ADTFinding -Severity High -Area DNS -Target $dc.Name `
                    -Title "DC A record does not resolve: $($dc.HostName)" `
                    -RootCause "Host record for $($dc.HostName) did not resolve." `
                    -Impact 'This DC cannot be located by name; replication/auth to it will fail.' `
                    -Remediation @{ Text='Re-register the DC host record (ipconfig /registerdns) and check the forward zone.'; ActionId='register-dns' }
            }

            if ($dcGuidByHost.ContainsKey($dc.HostName) -and $dcGuidByHost[$dc.HostName]) {
                $msdcsCname = "$($dcGuidByHost[$dc.HostName].Guid)._msdcs.$forest"
                $cnameRecords = & $resolveDns $msdcsCname 'CNAME'
                if (-not $cnameRecords) {
                    $findings += New-ADTFinding -Severity High -Area DNS -Target $dc.Name `
                        -Title "Missing _msdcs CNAME for $($dc.Name)" -Evidence $msdcsCname `
                        -RootCause "The DSA GUID alias $msdcsCname did not resolve - other DCs cannot find this DC as a replication source." `
                        -Impact 'Replication FROM this DC fails with error 8524 (DNS lookup failure).' `
                        -Remediation @{ Text="On $($dc.HostName) restart Netlogon to re-register _msdcs records; verify _msdcs.$forest delegation/zone."; ActionId='register-dns' }
                }
            }
        }
        return $findings
    }
}
