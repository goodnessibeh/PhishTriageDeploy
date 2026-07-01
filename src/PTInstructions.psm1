#Requires -Version 7.0
<#
    PTInstructions.psm1
    Manages the phishing-triage skills / runbook document (local files only):
      - Get-PTDefaultSkillsPath : path to the shipped default skills markdown
      - ConvertTo-PTLocalPath   : translate a Windows path (C:\...) to a WSL path when needed
      - Get-PTSkillsContent     : read skills markdown from a local path
      - Resolve-PTSkillsDocument: merge default + user file per mode (Default/Append/Replace)
      - Save-PTSkillsDocument   : write the resolved doc to a local path (honours -WhatIf)
      - Get-PTDesktopPath       : the operator's Desktop directory for the runbook copy

    The resolved document is a managed runbook the operator applies manually in the portal
    (the first-party agent has no instructions/knowledge API - it is tuned only by portal
    feedback). It is saved locally to the Desktop; there is no cloud copy.
#>

function Get-PTDefaultSkillsPath {
    <# Returns the absolute path to the shipped default skills (runbook) markdown. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Join-Path (Split-Path $PSScriptRoot -Parent) 'skills/default-phishing-triage-skills.md')
}

function Get-PTDefaultPromptbookPath {
    <# Returns the absolute path to the shipped default promptbook spec markdown. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Join-Path (Split-Path $PSScriptRoot -Parent) 'skills/default-phishing-triage-promptbook.md')
}

function ConvertTo-PTLocalPath {
    <#
        Normalises a caller-supplied path. A Windows drive path (e.g. C:\SOC\file.md) is
        translated to its WSL mount (/mnt/c/SOC/file.md) when running on Linux; on Windows it
        is returned unchanged. Non-drive paths are returned as-is.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)

    if ($Path -match '^([A-Za-z]):[\\/](.*)$' -and $IsLinux) {
        $drive = $Matches[1].ToLower()
        $rest = $Matches[2] -replace '\\', '/'
        return "/mnt/$drive/$rest"
    }
    return $Path
}

function Get-PTSkillsContent {
    <# Reads skills markdown from a local path (Windows or WSL form). Throws if unreadable. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)

    $resolved = ConvertTo-PTLocalPath -Path $Path
    if (-not (Test-Path -LiteralPath $resolved)) {
        throw "Skills file not found: '$Path' (resolved to '$resolved')."
    }
    return (Get-Content -LiteralPath $resolved -Raw)
}

function Resolve-PTSkillsDocument {
    <#
        Produces the effective skills document from the shipped default and an optional
        user-supplied document, according to -Mode:
          Default : the shipped default only (user content ignored)
          Append  : the default followed by the user content under an 'Organization Overrides'
                    header
          Replace : the user content only
        Returns a [pscustomobject] with Mode, Content and Source fields.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateSet('Default', 'Append', 'Replace')][string]$Mode,
        [string]$UserContent,
        [string]$DefaultPath
    )

    if ([string]::IsNullOrWhiteSpace($DefaultPath)) { $DefaultPath = Get-PTDefaultSkillsPath }
    $default = ''
    if (Test-Path -LiteralPath $DefaultPath) { $default = Get-Content -LiteralPath $DefaultPath -Raw }

    if ($Mode -in @('Append', 'Replace') -and [string]::IsNullOrWhiteSpace($UserContent)) {
        throw "SkillsMode '$Mode' requires a user skills file, but none was provided."
    }

    $content = switch ($Mode) {
        'Replace' { $UserContent }
        'Append'  {
            $sep = "`n`n---`n`n## Organization overrides (appended)`n`n"
            "$default$sep$UserContent"
        }
        default   { $default }
    }

    return [pscustomobject]@{
        Mode    = $Mode
        Source  = if ($Mode -eq 'Default') { 'default' } else { 'default+user' }
        Content = $content
    }
}

function Save-PTSkillsDocument {
    <# Writes the resolved skills content to a local path. Honours -WhatIf. #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$Path
    )
    $resolved = ConvertTo-PTLocalPath -Path $Path
    if ($PSCmdlet.ShouldProcess($resolved, 'Write resolved skills document')) {
        $dir = Split-Path -Parent $resolved
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Set-Content -LiteralPath $resolved -Value $Content -Encoding utf8
        Write-PTStatus -Level OK -Message "Runbook written to '$resolved'."
    }
    else {
        Write-PTStatus -Level DRYRUN -Message "Would write runbook to '$resolved'."
    }
    return $resolved
}

function Get-PTDesktopPath {
    <#
        Returns the operator's Desktop directory for the runbook copy. Uses the OS Desktop
        path (handles OneDrive-redirected desktops on Windows) and falls back to ~/Desktop when
        the OS does not report one (Linux/WSL/macOS).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $desktop = [Environment]::GetFolderPath('Desktop')
    if ([string]::IsNullOrWhiteSpace($desktop)) { $desktop = Join-Path $HOME 'Desktop' }
    return $desktop
}

Export-ModuleMember -Function Get-PTDefaultSkillsPath, Get-PTDefaultPromptbookPath,
    ConvertTo-PTLocalPath, Get-PTSkillsContent, Resolve-PTSkillsDocument, Save-PTSkillsDocument,
    Get-PTDesktopPath
