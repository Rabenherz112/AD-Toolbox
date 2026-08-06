#Requires -Version 5.1
<#
    Confirm.ps1 - Risk-tier confirmation gates for Actions (and risky Utilities)

    | RiskLevel  | Interactive               | CLI (non-interactive)            |
    | ReadOnly   | none                      | none                              |
    | LowImpact  | Y/N                       | -Confirm:$false or -Force         |
    | Disruptive | Y/N (+ target shown)      | -Force                            |
    | HighRisk   | type the action Id        | -Force AND -IUnderstand           |

    -WhatIf always "passes" (the Run block must honor $Context.WhatIf and not change anything)
#>

function Confirm-ADTAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Module,
        [string]$Target = 'the domain',
        [switch]$Interactive,
        [switch]$Force,
        [switch]$IUnderstand,
        [switch]$ConfirmDisabled,   # equivalent to -Confirm:$false on the CLI
        [switch]$WhatIf
    )

    $risk = $Module.RiskLevel
    if ($WhatIf)            { return $true }
    if ($risk -eq 'ReadOnly') { return $true }

    $label = "$($Module.Name) [$risk] on '$Target'"

    if ($Interactive) {
        switch ($risk) {
            'LowImpact'  { return (Read-ADTYesNo "Run $label?") }
            'Disruptive' {
                Write-Host "  WARNING: this is a DISRUPTIVE change against '$Target'." -ForegroundColor Yellow
                return (Read-ADTYesNo "Proceed with $label?")
            }
            'HighRisk'   {
                Write-Host ""
                Write-Host "  *** HIGH-RISK ACTION ***" -ForegroundColor Red
                Write-Host "  $label" -ForegroundColor Red
                Write-Host "  This can be destructive or hard to reverse. To proceed, type the action id exactly." -ForegroundColor Red
                $typed = Read-Host "  Type '$($Module.Id)' to confirm (anything else cancels)"
                if ($typed -ne $Module.Id) { Write-ADTLog -Level Warn -Message "High-risk action '$($Module.Id)' cancelled."; return $false }
                return $true
            }
        }
    }
    else {
        # Non-interactive: require the appropriate switches
        switch ($risk) {
            'LowImpact'  {
                if ($Force -or $ConfirmDisabled) { return $true }
                Write-ADTLog -Level Warn -Message "Refusing LowImpact action '$($Module.Id)' non-interactively without -Force/-Confirm:`$false."
                return $false
            }
            'Disruptive' {
                if ($Force) { return $true }
                Write-ADTLog -Level Warn -Message "Refusing Disruptive action '$($Module.Id)' without -Force."
                return $false
            }
            'HighRisk'   {
                if ($Force -and $IUnderstand) { return $true }
                Write-ADTLog -Level Warn -Message "Refusing HighRisk action '$($Module.Id)' without -Force AND -IUnderstand."
                return $false
            }
        }
    }
    return $false
}

function Read-ADTYesNo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [switch]$DefaultYes
    )

    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    $ans = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($ans)) { return [bool]$DefaultYes }
    return ($ans -match '^(y|yes)$')
}
