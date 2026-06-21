#Requires -Version 5.1
<#
    Discovery.ps1 - Find and validate plugins

    Every plugin is one .ps1 whose LAST expression is a metadata hashtable. We load it with
    & $file, validate the schema per Kind, derive Area from the folder, and skip (never crash
    on) malformed plugins. Files whose name starts with '_' are ignored (helpers/templates)
#>

$script:ADTValidKinds      = @('Diagnostic','Action')
$script:ADTValidRiskLevels = @('ReadOnly','LowImpact','Disruptive','HighRisk')

function Get-ADTModuleRegistry {
    [CmdletBinding()]
    param(
        [string]$Root = (Join-Path $PSScriptRoot '..'),
        [string[]]$Folders = @('diagnostics','actions')
    )

    $registry = @()
    $seenIds   = @{}

    foreach ($folder in $Folders) {
        $path = Join-Path $Root $folder
        if (-not (Test-Path $path)) { continue }

        $files = Get-ChildItem -Path $path -Recurse -Filter '*.ps1' -File | Where-Object { $_.Name -notlike '_*' }

        foreach ($file in $files) {
            $entry = $null
            try {
                $meta = & $file.FullName
                $entry = ConvertTo-ADTRegistryEntry -Meta $meta -File $file -RootFolder $folder
            }
            catch {
                Write-ADTLog -Level Warn -Message "Skipping plugin '$($file.Name)': $($_.Exception.Message)"
                continue
            }
            if (-not $entry) { continue }

            if ($seenIds.ContainsKey($entry.Id)) {
                Write-ADTLog -Level Warn -Message "Duplicate plugin Id '$($entry.Id)' in '$($file.Name)' (already from '$($seenIds[$entry.Id])'); skipping."
                continue
            }
            $seenIds[$entry.Id] = $file.Name
            $registry += $entry
        }
    }

    return $registry
}

function ConvertTo-ADTRegistryEntry {
    param(
        $Meta,
        $File,
        [string]$RootFolder
    )

    if ($Meta -is [object[]]) { $Meta = $Meta | Select-Object -Last 1 }
    if (-not ($Meta -is [hashtable] -or $Meta -is [System.Collections.IDictionary])) {
        throw "Plugin did not return a metadata hashtable as its last expression."
    }
    foreach ($req in 'Kind','Id','Name','Run') {
        if (-not $Meta.Contains($req) -or $null -eq $Meta[$req]) { throw "Missing required key '$req'." }
    }
    if ($Meta['Kind'] -notin $script:ADTValidKinds) {
        throw "Invalid Kind '$($Meta['Kind'])' (expected $($script:ADTValidKinds -join '/'))."
    }
    if (-not ($Meta['Run'] -is [scriptblock])) { throw "'Run' must be a scriptblock." }

    # Area defaults to the immediate sub-folder under the root (diagnostics/<Area>/...)
    Write-ADTLog -Level Debug -Message "Processing plugin '$($File.Name)' with metadata keys: $($Meta.Keys -join ', ')"
    $area = $Meta['Area']
    if (-not $area) { $area = Split-Path $File.DirectoryName -Leaf }

    $risk = $Meta['RiskLevel']
    if (-not $risk) { $risk = if ($Meta['Kind'] -eq 'Action') { 'Disruptive' } else { 'ReadOnly' } }
    if ($risk -notin $script:ADTValidRiskLevels) { throw "Invalid RiskLevel '$risk'." }

    [pscustomobject]@{
        PSTypeName        = 'ADT.Module'
        Kind              = $Meta['Kind']
        Id                = $Meta['Id']
        Name              = $Meta['Name']
        Area              = $area
        Synopsis          = $Meta['Synopsis']
        RiskLevel         = $risk
        Writes            = [bool]$Meta['Writes']
        IncludeInFullTest = $(if ($Meta.Contains('IncludeInFullTest')) { [bool]$Meta['IncludeInFullTest'] } else { $Meta['Kind'] -eq 'Diagnostic' })
        Requires          = @($Meta['Requires'])
        RequiresElevation = [bool]$Meta['RequiresElevation']
        Tags              = @($Meta['Tags'])
        Run               = $Meta['Run']
        SourcePath        = $File.FullName
        SourceFolder      = $RootFolder
    }
}
