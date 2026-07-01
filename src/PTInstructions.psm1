#Requires -Version 7.0
<#
    PTInstructions.psm1
    Manages the phishing-triage skills/instructions document:
      - Get-PTDefaultSkillsPath : path to the shipped default skills markdown
      - ConvertTo-PTLocalPath   : translate a Windows path (C:\...) to a WSL path when needed
      - Get-PTSkillsContent     : read skills markdown from a local path or SharePoint (Graph)
      - Resolve-PTSkills        : merge default + user file per mode (Default/Append/Replace)
      - Save-PTSkills           : write the resolved doc to a local path (honours -WhatIf)
      - Publish-PTSkills        : publish the resolved doc to a SharePoint library (honours -WhatIf)

    Honesty note: the first-party Phishing Triage Agent has NO file/SharePoint ingestion and no
    instructions API - it is tuned only by portal-typed feedback. This document is therefore a
    managed runbook / source-of-truth surfaced in the wizard handoff, and is manifest-ready for a
    custom Security Copilot agent if one is ever built.
#>

function Get-PTDefaultSkillsPath {
    <# Returns the absolute path to the shipped default skills markdown. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Join-Path (Split-Path $PSScriptRoot -Parent) 'skills/default-phishing-triage-skills.md')
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

function Get-PTSharePointFileContent {
    <#
        Reads a text file from SharePoint by its sharing/web URL using the Graph /shares endpoint
        (encodes the URL to an unpadded base64 share token). Requires a Graph connection with
        Sites.Read(Write).All. Returns the file text.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$ShareUrl)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($ShareUrl)
    $b64 = [System.Convert]::ToBase64String($bytes).TrimEnd('=').Replace('/', '_').Replace('+', '-')
    $token = "u!$b64"
    $item = Invoke-PTGraphRequest -Method GET -Uri "/v1.0/shares/$token/driveItem"
    $content = Invoke-PTGraphRequest -Method GET -Uri "/v1.0/shares/$token/driveItem/content"
    if ($content -is [byte[]]) { return [System.Text.Encoding]::UTF8.GetString($content) }
    if ($null -ne $item) { return [string]$content }
    return [string]$content
}

function Get-PTSkillsContent {
    <#
        Reads skills markdown from either a local path (-Path, Windows or WSL form) or a
        SharePoint URL (-SharePointUrl). Returns the file text, or throws if unreadable.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Local')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Local')][string]$Path,
        [Parameter(Mandatory, ParameterSetName = 'SharePoint')][string]$SharePointUrl
    )

    if ($PSCmdlet.ParameterSetName -eq 'SharePoint') {
        return Get-PTSharePointFileContent -ShareUrl $SharePointUrl
    }
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
        Write-PTStatus -Level OK -Message "Skills document written to '$resolved'."
    }
    else {
        Write-PTStatus -Level DRYRUN -Message "Would write skills document to '$resolved'."
    }
    return $resolved
}

function Publish-PTSkillsDocument {
    <#
        Publishes the resolved skills content to a SharePoint drive path via Graph
        (PUT .../drive/root:/{ItemPath}:/content). Requires the drive ID and the target item
        path (e.g. 'AgentDocs/phishing-triage-skills.md'). Honours -WhatIf.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$DriveId,
        [Parameter(Mandatory)][string]$ItemPath
    )
    $safePath = $ItemPath.TrimStart('/')
    $uri = "/v1.0/drives/$DriveId/root:/${safePath}:/content"
    if ($PSCmdlet.ShouldProcess("$DriveId :/$ItemPath", 'Publish skills document to SharePoint')) {
        $item = Invoke-PTGraphRequest -Method PUT -Uri $uri -Body $Content
        Write-PTStatus -Level OK -Message "Skills document published to SharePoint '$ItemPath'."
        return [pscustomobject]@{ Published = $true; WebUrl = (Get-PTProperty $item 'webUrl') }
    }
    Write-PTStatus -Level DRYRUN -Message "Would publish skills document to SharePoint '$ItemPath'."
    return [pscustomobject]@{ Published = $false; WebUrl = $null }
}

Export-ModuleMember -Function Get-PTDefaultSkillsPath, ConvertTo-PTLocalPath, Get-PTSkillsContent,
    Resolve-PTSkillsDocument, Save-PTSkillsDocument, Publish-PTSkillsDocument
