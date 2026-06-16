#Requires -Version 5.1
<#
    Action (LowImpact): Example Action

    This is a example action that does nothing.
#>
@{
    Kind              = 'Action'
    Id                = 'example'
    Name              = 'Example Action'
    Area              = 'Example'
    Synopsis          = 'This is a example action that does nothing.'
    RiskLevel         = 'LowImpact'
    RequiresElevation = $true
    Requires          = @('example')
    Tags              = @('example','remediation')

    Run = {
        param($Context, $Target)
        Write-ADTLog -Level Info -Message "Example Action running"
        return (New-ADTFinding -Severity Info -Area Example -Target "Example" -Title "The example action did nothing on $($Target).")
        
    }
}
