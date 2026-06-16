#Requires -Version 5.1
<#
    Diagnostic: Example Diagnostic

    This is a example diagnostic that does nothing. It is only here to demonstrate the structure of a diagnostic.
#>
@{
    Kind              = 'Diagnostic'
    Id                = 'example-diag'
    Name              = 'Example Diagnostic'
    Area              = 'Example'
    Synopsis          = 'This is a example diagnostic that does nothing. It is only here to demonstrate the structure of a diagnostic.'
    Writes            = $false
    IncludeInFullTest = $true
    Tags              = @('example','core')

    Run = {
        param($Context)
        Write-ADTLog -Level Info -Message "Example Diagnostic running"
        New-ADTFinding -Severity Info -Area Example -Target "Example" -Title "The example diagnostic found a problem."
        return $findings
    }
}
