<#
    .SYNOPSIS
    Installs script or module dependencies based on '#requires -Module' statements or module manifests.
    .EXAMPLE
    Install-Dependency.ps1 -Path .\Script.ps1
    Installs script dependencies defined by '#requires -Module' statements. Module is installed for current user only.
    .EXAMPLE
    Install-Dependency.ps1 -Path .\Module.psd1
    Installs module dependencies defined by module manifest (manifest is specified directly). Module is installed for current user only.
    .EXAMPLE
    Install-Dependency.ps1 -Path .\Module
    Installs module dependencies defined by module manifest (manifest is located by parent's name). Module is installed for current user only.
    .EXAMPLE
    Install-Dependency.ps1 -Path .\ScriptModule.psm1, .\Script.ps1, .\Module -Scope AllUsers
    Installs dependencies of all given items. Modules are installed globally for all users.
    .EXAMPLE
    Install-Dependency.ps1 -Path .\ScriptModule.psm1 -Scope CurrentUser -Repository PSGallery, UntrustedRepository
    Installs script module dependencies. Dependencies could be installed from given repositories even if repositories are not trusted. Module is installed for current user only.
    .EXAMPLE
    Install-Dependency.ps1 -Path .\Script.psm1 -LimitMajorVersion
    Installs script dependencies. If no maximum allowed version is specified, the script automatically adds maximum version constraint to prevent installing modules with breaking changes.
#>
[CmdletBinding()]
param(
    # Paths to items whose dependencies should be installed
    [Parameter(Mandatory = $true)]
    [string[]] $Path,

    # Installation scope of installed modules (allowed values are 'CurrentUser' and 'AllUsers')
    [ValidateSet("AllUsers", "CurrentUser")]
    [ValidateScript( {
            $CurrentUser = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent())
            if ($PSItem -eq "AllUsers" -and -not $CurrentUser.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
                throw "Modules can be installed globally only if the script is executed as administrator."
            }
            return $true
        }
    )]
    [string] $Scope = "CurrentUser",

    # Repositories from which modules could be installed (defaults to all trusted repositories)
    [string[]] $Repository = (Get-PSRepository | ? -Property "InstallationPolicy" -EQ -Value "Trusted" | select -ExpandProperty "Name"),

    # Limit major version in order to avoid breaking changes in installed modules
    [switch] $LimitMajorVersion
)

$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
Set-StrictMode -Version 2

$script:InstalledModules = Get-Module -ListAvailable
$script:RequiresModuleStatementRegex = [regex]::new("^\s*#requires\s+-modules?\s+(.*)$", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

function Test-Line {
    <#
        .SYNOPSIS
        Tests whether given line represents '#requires -Module' statement.
    #>
    param(
        # Line to test
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $Line
    )

    return $script:RequiresModuleStatementRegex.IsMatch($Line)
}

function ConvertTo-ModuleDefinition {
    <#
        .SYNOPSIS
        Converts hashtable with module reference (as used in '#requires -Module' statement or in module manifest)
        to a hashtable with module definition which can be used as parameter for Install-Module cmdlet.
    #>
    param(
        # Module reference to convert
        [Parameter(Mandatory = $true)]
        [hashtable] $ModuleReference
    )

    $ModuleDefinition = @{
        Name = $ModuleReference.ModuleName
    }

    if ($ModuleReference.ContainsKey("ModuleVersion")) {
        $ModuleDefinition.Add("MinimumVersion", $ModuleReference.ModuleVersion -as [version])
    }
    if ($ModuleReference.ContainsKey("MaximumVersion")) {
        $ModuleDefinition.Add("MaximumVersion", $ModuleReference.MaximumVersion -as [version])
    }
    elseif ($script:LimitMajorVersion -and $ModuleDefinition.ContainsKey("MinimumVersion")) {
        $MajorVersion = $ModuleDefinition.MinimumVersion.Major
        $MaxInt = [int]::MaxValue
        $HighestAllowedVersion = [version]::new($MajorVersion, $MaxInt, $MaxInt, $MaxInt)
        $ModuleDefinition.Add("MaximumVersion", $HighestAllowedVersion)
    }
    if ($ModuleReference.ContainsKey("RequiredVersion")) {
        $ModuleDefinition.Add("RequiredVersion", $ModuleReference.RequiredVersion -as [version])
    }

    return $ModuleDefinition
}

function Get-ModuleDefinition {
    <#
        .SYNOPSIS
        Extracts module definition from '#requires -Module' statement.
        The definition can be used as parameter for Install-Module cmdlet.
    #>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("PSAvoidUsingInvokeExpression", "",
        Justification = "Although potential security problem, we need to parse hashtable literal to get the module reference.")]
    param(
        # Line to extract module definition from
        [Parameter(Mandatory = $true)]
        [string] $Line
    )

    $StatementValue = $script:RequiresModuleStatementRegex.Match($Line).Groups[1].Value
    $StatementValue = $StatementValue.Split(",")

    $ModuleDefinitions = $StatementValue | % {
        $SerializedReference = $PSItem.Trim().Trim("'").Trim("""")

        if (-not $SerializedReference.StartsWith("@{")) {
            # Module is referenced only by its name. Provide complete reference structure.
            $SerializedReference = "@{ ModuleName = '$SerializedReference' }"
        }

        $DeserializedReference = Invoke-Expression -Command $SerializedReference
        return ConvertTo-ModuleDefinition -ModuleReference $DeserializedReference
    }

    return $ModuleDefinitions
}

function Test-ModuleCompliance {
    <#
        .SYNOPSIS
        Tests whether the given module complies name and version requirements.
    #>
    param(
        # Module to test
        [Parameter(Mandatory = $true)]
        [PSModuleInfo] $Module,

        # Requirements to test the module against
        [Parameter(Mandatory = $true)]
        [hashtable] $Requirement
    )

    if ($Module.Name -ne $Requirement.Name) {
        return $false
    }

    $ModuleVersion = $Module.Version
    if ($Requirement.ContainsKey("RequiredVersion") -and $ModuleVersion -ne $Requirement.RequiredVersion) {
        return $false
    }
    if ($Requirement.ContainsKey("MaximumVersion") -and $ModuleVersion -gt $Requirement.MaximumVersion) {
        return $false
    }
    if ($Requirement.ContainsKey("MinimumVersion") -and $ModuleVersion -lt $Requirement.MinimumVersion) {
        return $false
    }

    return $true
}

function Format-VersionConstraint {
    <#
        .SYNOPSIS
        Returns version constraint defined in module definition in printable format.
    #>
    param(
        # Module definition to format
        [Parameter(Mandatory = $true)]
        [hashtable] $ModuleDefinition
    )

    if ($ModuleDefinition.ContainsKey("RequiredVersion")) {
        return "[$($ModuleDefinition.RequiredVersion)]"
    }
    elseif ($ModuleDefinition.ContainsKey("MinimumVersion") -and -not $ModuleDefinition.ContainsKey("MaximumVersion")) {
        return "[$($ModuleDefinition.MinimumVersion), )"
    }
    elseif ($ModuleDefinition.ContainsKey("MinimumVersion") -and $ModuleDefinition.ContainsKey("MaximumVersion")) {
        return "[$($ModuleDefinition.MinimumVersion), $($ModuleDefinition.MaximumVersion)]"        
    }
    elseif (-not $ModuleDefinition.ContainsKey("MinimumVersion") -and $ModuleDefinition.ContainsKey("MaximumVersion")) {
        return "(, $($ModuleDefinition.MaximumVersion)]"
    }

    return "[0.0.0, )"
}

function Install-Dependency {
    <#
        .SYNOPSIS
        Installs module dependency defined by given module definition.
    #>
    param(
        # Module to install
        [Parameter(Mandatory = $true)]
        [hashtable] $ModuleDefinition
    )

    $ModuleName = $ModuleDefinition.Name
    $VersionConstraint = Format-VersionConstraint -ModuleDefinition $ModuleDefinition
    $SatisfyingModules = @($script:InstalledModules | ? { Test-ModuleCompliance -Module $PSItem -Requirement $ModuleDefinition })
    if ($SatisfyingModules.Length -gt 0) {
        $SkipMessage = "Module '$ModuleName' is already installed and its version constraints '$VersionConstraint' are satisfied by following modules:"
        Write-Information -MessageData $SkipMessage
        $SatisfyingModules | % { Write-Information -MessageData "$($PSItem.Name), $($PSItem.Version)" }
        continue
    }

    Write-Information "Installing module '$ModuleName, $VersionConstraint'."
    Install-Module @ModuleDefinition -Scope $script:Scope -Repository $script:Repository -Force

    # Since previously installed module could installed other dependencies that might be required later,
    # refresh the list of already installed modules.
    $script:InstalledModules = Get-Module -ListAvailable
}

function Install-ScriptFileDependency {
    <#
        .SYNOPSIS
        Installs script file module dependencies defined by '#requires -Module' statements.
    #>
    param(
        # Path to script
        [Parameter(Mandatory = $true)]
        [ValidateScript( { if (Test-Path -Path $PSItem -PathType Leaf) { return $true } else { throw "File '$PSItem' cannot be found. Specify valid path." } })]
        [string] $FilePath
    )

    $Lines = Get-Content -Path $FilePath

    $RequiredModules = $Lines | % {
        if (Test-Line -Line $PSItem) {
            return Get-ModuleDefinition -Line $PSItem
        }
    }

    foreach ($ModuleDefinition in $RequiredModules) {
        Install-Dependency -ModuleDefinition $ModuleDefinition
    }
}

function Install-ManifestFileDependency {
    <#
        .SYNOPSIS
        Installs module dependencies defined by module manifest.
    #>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("PSAvoidUsingInvokeExpression", "",
        Justification = "Although potential security problem, we need to parse module manifest.")]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript( { if (Test-Path -Path $PSItem -PathType Leaf) { return $true } else { throw "File '$PSItem' cannot be found. Specify valid path." } })]
        [string] $FilePath
    )

    [hashtable] $Manifest = Invoke-Expression -Command (Get-Content -Path $FilePath -Raw)

    if ($Manifest.ContainsKey("RequiredModules")) {
        $RequiredModules = $Manifest.RequiredModules
        foreach ($Module in $RequiredModules) {
            # Module is referenced only by its name. Provide complete reference structure.
            if ($Module -is [string]) {
                $Module = @{ ModuleName = $Module }
            }

            $ModuleDefinition = ConvertTo-ModuleDefinition -ModuleReference $Module
            Install-Dependency -ModuleDefinition $ModuleDefinition
        }
    }

    # Install also dependencies of all nested modules.
    if ($Manifest.ContainsKey("NestedModules")) {
        $NestedModules = $Manifest.NestedModules
        $BasePath = Split-Path -Path $FilePath -Parent
        foreach ($NestedModule in $NestedModules) {
            $NestedModulePath = Join-Path -Path $BasePath -ChildPath $NestedModule
            if (Test-Path -Path $NestedModulePath -PathType Container) {
                $ManifestName = "$(Split-Path -Path $NestedModulePath -Leaf).psd1"
                $NestedModuleManifestPath = Join-Path -Path $NestedModulePath -ChildPath $ManifestName
                if (Test-Path -Path $NestedModuleManifestPath -PathType Leaf) {
                    Install-ManifestFileDependency -FilePath $NestedModuleManifestPath
                }
            }
        }
    }
}

function Select-DependencyInstaller {
    <#
        .SYNOPSIS
        Selects proper dependency installer based on the type of given item.
    #>
    param(
        # Path to item whose dependencies should be installed
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    if (Test-Path -Path $Path -PathType Leaf) {
        $Extension = [System.IO.Path]::GetExtension($Path)
        switch -Regex ($Extension) {
            "\.psm?1" {
                Install-ScriptFileDependency -FilePath $Path
            }
            "\.psd1" {
                Install-ManifestFileDependency -FilePath $Path
            }
            default {
                Write-Warning -Message "Could not proceed with the file '$Path' due to the unknown extension '$Extension'."
            }
        }
    }
    elseif (Test-Path -Path $Path -PathType Container) {
        $ModuleManifestName = "$(Split-Path -Path $Path -Leaf).psd1"
        $ModuleManifestPath = Join-Path -Path $Path -ChildPath $ModuleManifestName
        if (Test-Path -Path $ModuleManifestPath -PathType Leaf) {
            Select-DependencyInstaller -Path $ModuleManifestPath
        }
        else {
            Write-Warning -Message "Could not locate module manifest '$ModuleManifestName' in the directory '$Path'."
        }
    }
    else {
        Write-Warning -Message "No item available on path '$Path'."
    }
}

foreach ($CurrentPath in $Path) {
    Select-DependencyInstaller -Path $CurrentPath -ErrorAction Continue
}