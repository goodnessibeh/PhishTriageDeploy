#Requires -Version 7.0
<#
    PTIdentity.psm1
    Identity resolution for the Phishing Triage Agent deployment tool. Implements the
    "detect & branch" identity path from the design (sections 3 and 7): create a
    dedicated Entra account, select an existing agent identity, or skip to the portal
    wizard. All Graph traffic goes through PTCommon (Invoke-PTGraphRequest); this module
    never re-implements the connect/retry/logging idioms.

      - ConvertTo-PTUpnLocalPart : sanitize a display name into a UPN local part
      - New-PTAgentUser          : idempotent POST /users for a dedicated agent account
      - Get-PTUserByIdOrUpn      : single-object lookup by objectId or UPN (reliable path)
      - Get-PTAgentIdentity      : best-effort paged enumeration of Entra Agent IDs (beta)
      - Select-PTAgentIdentity   : interactive picker (search/page/select/paste), skippable
      - Resolve-PTIdentity       : the branch brain (Create / SelectExisting / Skip / Prompt)

    PTCommon.psm1 is loaded at runtime by the orchestrator; its functions
    (Invoke-PTGraphRequest, Write-PTStatus, Get-PTProperty) are called here directly.
#>

function Test-PTInteractive {
    <# Private: true when a real interactive host is present, so prompting is safe. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return [Environment]::UserInteractive
}

function Get-PTRandomPassword {
    <#
        Private: builds a strong plaintext password (>= 20 chars, mixed classes) from two
        GUIDs plus a symbol set. Kept as plaintext deliberately: the Graph passwordProfile
        requires a plain string, and ConvertTo-SecureString with plaintext trips the
        analyzer. The value lives only in-memory for the single POST /users call.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([int]$MinLength = 24)

    $hex = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
    $symbols = '!@#$%^&*-_=+?'
    $s1 = $symbols[(Get-Random -Maximum $symbols.Length)]
    $s2 = $symbols[(Get-Random -Maximum $symbols.Length)]
    $core = $hex.Substring(0, [Math]::Max(20, $MinLength))
    # 'Pt' guarantees an upper + a lower; core adds hex letters/digits; symbols + '9' round it out.
    return ('Pt' + $s1 + $core.ToUpper().Substring(0, 2) + $core + $s2 + '9')
}

function ConvertTo-PTUpnLocalPart {
    <#
        Sanitizes a display name into a UPN local part: lowercase, every run of non
        [a-z0-9] characters collapses to a single '-', and leading/trailing '-' are
        trimmed. Example: 'Phishing Triage Agent' -> 'phishing-triage-agent'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$DisplayName)

    $lower = $DisplayName.ToLowerInvariant()
    $collapsed = [regex]::Replace($lower, '[^a-z0-9]+', '-')
    return $collapsed.Trim('-')
}

function New-PTAgentUser {
    <#
        Creates a dedicated Entra user for the agent (the only path where the 5 URBAC
        permissions can be pre-assigned). Idempotent: if the UPN already exists the
        function reports SKIP and returns Created=$false with the existing Id. Honors
        -WhatIf: the POST is gated behind ShouldProcess. Returns a result object
        @{ Created; Id; UserPrincipalName; DisplayName }.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Password',
        Justification = 'Graph passwordProfile requires a plaintext string; SecureString/ConvertTo-SecureString is disallowed by design. Value is in-memory only for one POST.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '',
        Justification = 'UserPrincipalName is a UPN, not a credential username; there is no combined credential to pass. Password is optional and generated when absent.')]
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [string]$Password
    )

    $existing = $null
    try { $existing = Invoke-PTGraphRequest -Method GET -Uri "/v1.0/users/$UserPrincipalName" }
    catch { $existing = $null }

    if ($existing) {
        $eid = Get-PTProperty $existing 'id'
        Write-PTStatus -Level SKIP -Message "User '$UserPrincipalName' already exists (id $eid)."
        return [pscustomobject]@{
            Created           = $false
            Id                = $eid
            UserPrincipalName = $UserPrincipalName
            DisplayName       = $DisplayName
        }
    }

    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, "Create Entra user '$DisplayName'")) {
        Write-PTStatus -Level DRYRUN -Message "Would create user '$UserPrincipalName' ('$DisplayName')."
        return [pscustomobject]@{
            Created           = $false
            Id                = $null
            UserPrincipalName = $UserPrincipalName
            DisplayName       = $DisplayName
        }
    }

    if ([string]::IsNullOrWhiteSpace($Password)) { $Password = Get-PTRandomPassword }
    $nickname = ($UserPrincipalName -split '@', 2)[0]
    $body = @{
        accountEnabled    = $true
        displayName       = $DisplayName
        mailNickname      = $nickname
        userPrincipalName = $UserPrincipalName
        passwordProfile   = @{
            password                      = $Password
            forceChangePasswordNextSignIn = $false
        }
    }
    $new = Invoke-PTGraphRequest -Method POST -Uri '/v1.0/users' -Body $body
    $nid = Get-PTProperty $new 'id'
    Write-PTStatus -Level OK -Message "Created user '$UserPrincipalName' (id $nid)."
    return [pscustomobject]@{
        Created           = $true
        Id                = $nid
        UserPrincipalName = $UserPrincipalName
        DisplayName       = $DisplayName
    }
}

function Get-PTUserByIdOrUpn {
    <#
        Single-object lookup by objectId or UPN. This is the RELIABLE identity path: it
        underpins the paste-an-id fallback for agent-identity selection. Returns the raw
        user object, or $null when it is not found / not readable.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Mandatory)][string]$IdOrUpn)

    try { return Invoke-PTGraphRequest -Method GET -Uri "/v1.0/users/$IdOrUpn" }
    catch { return $null }
}

function Get-PTAgentIdentity {
    <#
        Best-effort enumeration of EXISTING Entra Agent IDs. Honest caveat: the exact
        collection/shape for listing Agent IDs is a newer/beta Graph surface and remains
        an OPEN ITEM in the design (section 11). The -Uri default is a documented best
        guess; the whole read is wrapped so an unsupported surface degrades gracefully.
        Follows '@odata.nextLink' to gather every page. RELIABLE FALLBACK: if this cannot
        list, callers should paste an objectId/UPN and validate via Get-PTUserByIdOrUpn.
        Returns @{ Readable; Identities = @(objects with Id, DisplayName, UserPrincipalName) }.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$Uri = '/beta/directoryObjects/microsoft.graph.user?$select=id,displayName,userPrincipalName'
    )

    $items = @()
    $next = $Uri
    try {
        while ($next) {
            $resp = Invoke-PTGraphRequest -Method GET -Uri $next
            foreach ($o in @($resp.value)) {
                $items += [pscustomobject]@{
                    Id                = (Get-PTProperty $o 'id')
                    DisplayName       = (Get-PTProperty $o 'displayName')
                    UserPrincipalName = (Get-PTProperty $o 'userPrincipalName')
                }
            }
            $next = Get-PTProperty $resp '@odata.nextLink'
        }
        return [pscustomobject]@{ Readable = $true; Identities = @($items) }
    }
    catch {
        Write-PTStatus -Level WARN -Message "Could not enumerate agent identities: $($_.Exception.Message)"
        return [pscustomobject]@{ Readable = $false; Identities = @() }
    }
}

function Select-PTAgentIdentity {
    <#
        Interactive picker over Get-PTAgentIdentity results: search filter, paging (20 per
        page), select by number, or paste an objectId/UPN (validated via
        Get-PTUserByIdOrUpn). Non-interactive short-circuit: when -IdOrUpn is supplied the
        function validates it without any prompt (so unit tests need no TTY). Returns the
        chosen identity @{ Id; DisplayName; UserPrincipalName } or $null.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$IdOrUpn,
        [string]$Uri
    )

    if (-not [string]::IsNullOrWhiteSpace($IdOrUpn)) {
        $u = Get-PTUserByIdOrUpn -IdOrUpn $IdOrUpn
        if ($u) {
            return [pscustomobject]@{
                Id                = (Get-PTProperty $u 'id')
                DisplayName       = (Get-PTProperty $u 'displayName')
                UserPrincipalName = (Get-PTProperty $u 'userPrincipalName')
            }
        }
        Write-PTStatus -Level FAIL -Message "No identity found for '$IdOrUpn'."
        return $null
    }

    $listParams = @{}
    if ($Uri) { $listParams['Uri'] = $Uri }
    $all = @((Get-PTAgentIdentity @listParams).Identities)

    $filter = ''
    $page = 0
    $pageSize = 20
    while ($true) {
        $view = if ($filter) {
            @($all | Where-Object {
                    ($_.DisplayName -like "*$filter*") -or ($_.UserPrincipalName -like "*$filter*")
                })
        }
        else { $all }

        $pages = [Math]::Max(1, [Math]::Ceiling($view.Count / $pageSize))
        if ($page -ge $pages) { $page = $pages - 1 }
        if ($page -lt 0) { $page = 0 }
        $start = $page * $pageSize
        $slice = @($view | Select-Object -Skip $start -First $pageSize)

        Write-PTStatus -Level INFO -Message ("Identities page {0}/{1} (filter '{2}', {3} match)" -f ($page + 1), $pages, $filter, $view.Count)
        for ($i = 0; $i -lt $slice.Count; $i++) {
            Write-PTStatus -Level INFO -Message ('  [{0}] {1}  {2}' -f ($start + $i + 1), $slice[$i].DisplayName, $slice[$i].Id)
        }

        $ans = Read-Host '[#]=select  [N]ext  [P]rev  [F]ilter  paste an ID  [Q]uit'
        switch -Regex ($ans) {
            '^[Qq]$' { return $null }
            '^[Nn]$' { $page++ }
            '^[Pp]$' { $page-- }
            '^[Ff]$' { $filter = (Read-Host 'Filter text').Trim(); $page = 0 }
            '^\d+$' {
                $idx = [int]$ans - 1
                if ($idx -ge 0 -and $idx -lt $view.Count) {
                    $sel = $view[$idx]
                    return [pscustomobject]@{
                        Id                = $sel.Id
                        DisplayName       = $sel.DisplayName
                        UserPrincipalName = $sel.UserPrincipalName
                    }
                }
                Write-PTStatus -Level WARN -Message 'Selection number is out of range.'
            }
            default {
                if (-not [string]::IsNullOrWhiteSpace($ans)) {
                    $u = Get-PTUserByIdOrUpn -IdOrUpn $ans.Trim()
                    if ($u) {
                        return [pscustomobject]@{
                            Id                = (Get-PTProperty $u 'id')
                            DisplayName       = (Get-PTProperty $u 'displayName')
                            UserPrincipalName = (Get-PTProperty $u 'userPrincipalName')
                        }
                    }
                    Write-PTStatus -Level WARN -Message "No identity found for '$ans'."
                }
            }
        }
    }
}

function Resolve-PTIdentity {
    <#
        The branch brain for identity resolution. Modes: Create, SelectExisting, Skip, or
        Prompt (default). When Mode is Prompt AND the host is interactive, the 3-choice
        menu is shown; otherwise the explicit Mode is honored for unattended runs (a
        Prompt with no TTY falls back to Skip, the safe readiness-only path). Honors
        -WhatIf via ShouldProcess and delegates the actual write to New-PTAgentUser.
        Returns @{ Path; Identity; Action } where
          Path   = 'ExistingUser' | 'SelectedAgentId' | 'NewAgentId-Portal'
          Action = 'created' | 'existing' | 'selected' | 'skipped'.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('Create', 'SelectExisting', 'Skip', 'Prompt')][string]$Mode = 'Prompt',
        [string]$DisplayName,
        [string]$UserPrincipalName,
        [string]$IdOrUpn
    )

    $interactive = Test-PTInteractive

    if ($Mode -eq 'Prompt') {
        if ($interactive) {
            Write-PTStatus -Level INFO -Message 'Identity for the Phishing Triage Agent:'
            Write-PTStatus -Level INFO -Message '  [1] Create a new dedicated identity + assign the 5 permissions (recommended)'
            Write-PTStatus -Level INFO -Message '  [2] Select an existing agent identity + assign the 5 permissions'
            Write-PTStatus -Level INFO -Message '  [3] Skip (new Entra Agent ID via the portal wizard - readiness only)'
            $choice = Read-Host 'Choose 1, 2, or 3'
            $Mode = switch ($choice) {
                '1' { 'Create' }
                '2' { 'SelectExisting' }
                '3' { 'Skip' }
                default { 'Skip' }
            }
        }
        else {
            $Mode = 'Skip'
        }
    }

    switch ($Mode) {
        'Create' {
            if ([string]::IsNullOrWhiteSpace($DisplayName) -and $interactive) {
                $DisplayName = Read-Host 'Display name for the new identity'
            }
            if ([string]::IsNullOrWhiteSpace($DisplayName)) {
                Write-PTStatus -Level FAIL -Message 'A display name is required to create an identity.'
                return [pscustomobject]@{ Path = 'NewAgentId-Portal'; Identity = $null; Action = 'skipped' }
            }
            if ([string]::IsNullOrWhiteSpace($UserPrincipalName) -and $interactive) {
                $UserPrincipalName = Read-Host 'Sign-in name (UPN) for the new identity'
            }
            if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
                Write-PTStatus -Level FAIL -Message 'A UserPrincipalName is required to create an identity.'
                return [pscustomobject]@{ Path = 'NewAgentId-Portal'; Identity = $null; Action = 'skipped' }
            }

            if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, "Resolve and create agent identity '$DisplayName'")) {
                Write-PTStatus -Level DRYRUN -Message "Would create and resolve identity '$UserPrincipalName'."
                return [pscustomobject]@{ Path = 'ExistingUser'; Identity = $null; Action = 'skipped' }
            }

            $created = New-PTAgentUser -DisplayName $DisplayName -UserPrincipalName $UserPrincipalName
            $idObj = $null
            if ($created.Id) {
                $idObj = [pscustomobject]@{
                    Id                = $created.Id
                    DisplayName       = $created.DisplayName
                    UserPrincipalName = $created.UserPrincipalName
                }
            }
            $action = if ($created.Created) { 'created' } elseif ($created.Id) { 'existing' } else { 'skipped' }
            return [pscustomobject]@{ Path = 'ExistingUser'; Identity = $idObj; Action = $action }
        }
        'SelectExisting' {
            $sel = Select-PTAgentIdentity -IdOrUpn $IdOrUpn
            if ($sel) {
                return [pscustomobject]@{ Path = 'SelectedAgentId'; Identity = $sel; Action = 'selected' }
            }
            return [pscustomobject]@{ Path = 'SelectedAgentId'; Identity = $null; Action = 'skipped' }
        }
        default {
            # 'Skip': no writes; the portal wizard will mint a new Entra Agent ID.
            Write-PTStatus -Level INFO -Message 'Skipping identity creation; portal wizard will create a new Entra Agent ID.'
            return [pscustomobject]@{ Path = 'NewAgentId-Portal'; Identity = $null; Action = 'skipped' }
        }
    }
}

Export-ModuleMember -Function ConvertTo-PTUpnLocalPart, New-PTAgentUser, Get-PTUserByIdOrUpn,
    Get-PTAgentIdentity, Select-PTAgentIdentity, Resolve-PTIdentity
