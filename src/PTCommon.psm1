#Requires -Version 7.0
<#
    PTCommon.psm1
    Shared building blocks for the Phishing Triage Agent deployment tool:
      - Get-PTConfig            : load config/tenants.json (UPN-based)
      - Get-PTDomainFromUpn     : derive tenant domain from an admin UPN
      - Get-PTProperty          : safe property access for JSON-deserialised objects
      - Write-PTStatus          : consistent [OK]/[SKIP]/[DRYRUN]/[FAIL]/[INFO] host output
      - Connect-PTGraph         : interactive Connect-MgGraph (delegated OAuth, no stored secrets)
      - Get-PTVerifiedDomain    : verified domains of the connected tenant
      - Assert-PTTenant         : hard wrong-tenant guard, called before any write
      - Test-PTAdminRole        : confirm the signed-in admin holds Security Administrator
      - Invoke-PTGraphRequest   : Graph call wrapper with 429/503 retry honouring Retry-After
#>

# Default delegated scopes. Security Administrator (checked separately) backs the Defender
# RBAC and agent-governance actions; these scopes cover the automatable Graph surface.
$Script:PTDefaultScopes = @(
    'Organization.Read.All',            # subscribedSkus + organization/verifiedDomains
    'User.ReadWrite.All',               # create the dedicated agent account
    'RoleManagement.ReadWrite.Directory' # read directory-role membership + role work
)

# Entra role template ID for Security Administrator (well-known, tenant-independent).
$Script:PTSecurityAdminRoleTemplateId = '194ae4cb-b126-40b2-bd5b-6091b380977d'

function Get-PTDefaultScope {
    <# Returns the default delegated Graph scopes requested at sign-in. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return [string[]]$Script:PTDefaultScopes
}

function Get-PTProperty {
    <#
        Safe property read: returns $Default when the property/key is absent or the object is
        null (no StrictMode surprises). Handles both PSObject-style objects and dictionaries -
        Invoke-MgGraphRequest returns hashtables, whose keys are not exposed as PSObject
        properties, so dictionary keys are read directly.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        $Object,
        [Parameter(Mandatory)][string] $Name,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $Default
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $Default
}

function Get-PTConfig {
    <#
        Loads config/tenants.json listing the tenant admin UPNs. Default location is
        config/tenants.json in the repo root. Returns the parsed object, or $null when no
        file exists. Only the admin UPN is required per tenant (the domain is derived from it).
        Shape:
            { "Tenants": [ { "UserPrincipalName": "admin@contoso.onmicrosoft.com", ... } ] }
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param([string]$ConfigPath)

    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        $ConfigPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'config/tenants.json'
    }
    if (-not (Test-Path -LiteralPath $ConfigPath)) { return $null }
    try { return (Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json) }
    catch { throw "Failed to read tenant config '$ConfigPath': $($_.Exception.Message)" }
}

function Get-PTDomainFromUpn {
    <#
        Derives a tenant domain from an admin UPN: the part after '@'. A UPN can only sign in
        if that domain is verified in the tenant, so the derived domain is a valid value for
        the wrong-tenant guard. Returns $null for an empty/invalid UPN.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$UserPrincipalName)
    if ([string]::IsNullOrWhiteSpace($UserPrincipalName) -or $UserPrincipalName -notmatch '@') { return $null }
    return ($UserPrincipalName -split '@', 2)[1].Trim()
}

function Write-PTStatus {
    <#
        Consistent coloured status line. Levels: OK, SKIP, DRYRUN, FAIL, INFO, WARN.
        (PSAvoidUsingWriteHost is excluded in the analyzer settings - this is interactive tooling.)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('OK', 'SKIP', 'DRYRUN', 'FAIL', 'INFO', 'WARN')][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )
    $colour = switch ($Level) {
        'OK'     { 'Green' }
        'SKIP'   { 'Yellow' }
        'DRYRUN' { 'Yellow' }
        'FAIL'   { 'Red' }
        'WARN'   { 'Magenta' }
        default  { 'Cyan' }
    }
    Write-Host ('  [{0,-6}] {1}' -f $Level, $Message) -ForegroundColor $colour
}

function Initialize-PTGraphModule {
    <#
        Ensures Microsoft.Graph.Authentication is installed and imported. Bootstraps TLS 1.2, the
        NuGet package provider and a trusted PSGallery when needed (common on a fresh box), and
        throws a clear, actionable error if it still cannot install/load the module.
    #>
    [CmdletBinding()]
    param()

    if (Get-Module Microsoft.Graph.Authentication) { return }
    if (Get-Module Microsoft.Graph.Authentication -ListAvailable) {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        return
    }

    Write-PTStatus -Level INFO -Message 'Microsoft.Graph.Authentication not found - installing for the current user...'
    try {
        # Older hosts default to TLS 1.0/1.1, which the PowerShell Gallery rejects.
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion '2.8.5.201' -Scope CurrentUser -Force | Out-Null
        }
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
    }
    catch {
        throw ("Could not install Microsoft.Graph.Authentication automatically ($($_.Exception.Message)). " +
            "Install it manually in PowerShell 7 and re-run:  " +
            "Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force")
    }

    try { Import-Module Microsoft.Graph.Authentication -ErrorAction Stop }
    catch {
        throw ("Microsoft.Graph.Authentication installed but could not be loaded ($($_.Exception.Message)). " +
            "Open a fresh PowerShell 7 session and re-run.")
    }
}

function Connect-PTGraph {
    <#
        Connects to Microsoft Graph with interactive delegated OAuth (browser sign-in):
        no secrets stored, tokens held in memory only.
        Installs the Microsoft.Graph.Authentication module on first use. Pass -TenantDomain to
        bind the sign-in to a specific tenant; -Scopes to override the default scope set.
    #>
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [string]$TenantDomain,
        [string[]]$Scopes = $Script:PTDefaultScopes,
        [switch]$ForceReconnect
    )

    Initialize-PTGraphModule

    # Reuse an open session only when it already serves the target tenant. A session for a
    # different tenant (or -ForceReconnect) is dropped so a fresh interactive sign-in is
    # triggered - rather than silently reusing a wrong-tenant token and failing the guard.
    $existing = Get-MgContext -ErrorAction SilentlyContinue
    $existingDomain = if ($existing -and $existing.Account) { ($existing.Account -split '@', 2)[-1] } else { $null }
    $servesTarget = (-not $TenantDomain) -or ($existingDomain -and $existingDomain -ieq $TenantDomain)

    if ($existing -and ($ForceReconnect -or -not $servesTarget)) {
        if ($TenantDomain -and -not $servesTarget) {
            Write-PTStatus -Level INFO -Message "Open session is a different tenant ($existingDomain); reconnecting to '$TenantDomain'."
        }
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        $existing = $null
    }

    if (-not $existing) {
        if ($UserPrincipalName) {
            Write-PTStatus -Level INFO -Message "Sign in as '$UserPrincipalName' (or another admin of the '$TenantDomain' tenant)."
        }
        $connectParams = @{ Scopes = $Scopes; NoWelcome = $true }
        if ($TenantDomain) { $connectParams['TenantId'] = $TenantDomain }
        Connect-MgGraph @connectParams -ErrorAction Stop
    }

    if ($TenantDomain) {
        Assert-PTTenant -Domain $TenantDomain
        Write-PTStatus -Level OK -Message "Connected to tenant serving '$TenantDomain'."
    }
    return Get-MgContext
}

function Get-PTVerifiedDomain {
    <# Returns the verified domain names of the currently connected tenant, or $null. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    try {
        $org = Invoke-PTGraphRequest -Method GET -Uri '/v1.0/organization?$select=verifiedDomains'
        $domains = [string[]]@($org.value.verifiedDomains.name)
        if ($domains.Count) { return $domains }
    }
    catch { return $null }
    return $null
}

function Assert-PTTenant {
    <#
        Hard guard: throws unless the connected tenant serves $Domain. Call this before any
        write so a misdirected session (still signed into another tenant) can never be written
        to. A no-op when $Domain is empty.
    #>
    [CmdletBinding()]
    param([string]$Domain)

    if ([string]::IsNullOrWhiteSpace($Domain)) { return }
    $domains = Get-PTVerifiedDomain
    if (-not $domains) {
        throw "Not connected to Graph, or could not read verified domains; cannot verify tenant '$Domain'."
    }
    if ($domains -notcontains $Domain) {
        throw ("Connected tenant does NOT serve '$Domain' (verified domains: $($domains -join ', ')). " +
               "Refusing to write. Sign in with an admin of the '$Domain' tenant.")
    }
}

function Test-PTAdminRole {
    <#
        Returns $true when the signed-in admin holds the Entra Security Administrator role
        (required for Defender RBAC and agent governance). Best-effort: on a read failure it
        returns $false so callers fail closed rather than proceeding blindly.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    try {
        $uri = "/v1.0/me/memberOf/microsoft.graph.directoryRole?`$select=roleTemplateId,displayName"
        $roles = Invoke-PTGraphRequest -Method GET -Uri $uri
        foreach ($r in @($roles.value)) {
            if ($r.roleTemplateId -eq $Script:PTSecurityAdminRoleTemplateId) { return $true }
        }
        return $false
    }
    catch { return $false }
}

function Invoke-PTGraphRequest {
    <#
        Wrapper over Invoke-MgGraphRequest that retries transient failures (HTTP 429/503) with
        backoff honouring the Retry-After header, and surfaces the Graph error body cleanly on
        permanent failures. Returns the parsed response object.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        $Body,
        [int]$MaxRetries = 4
    )

    for ($attempt = 0; ; $attempt++) {
        try {
            $params = @{ Method = $Method; Uri = $Uri; ErrorAction = 'Stop' }
            if ($null -ne $Body) {
                $params['Body'] = ($Body | ConvertTo-Json -Depth 20)
                $params['ContentType'] = 'application/json'
            }
            return Invoke-MgGraphRequest @params
        }
        catch {
            $status = $null
            $resp = $_.Exception.Response
            if ($resp -and $resp.StatusCode) { $status = [int]$resp.StatusCode }

            $transient = $status -in @(429, 503, 504)
            if (-not $transient -or $attempt -ge $MaxRetries) {
                throw "Graph $Method $Uri failed$(if ($status) { " (HTTP $status)" }): $($_.Exception.Message)"
            }

            $delay = [Math]::Min([Math]::Pow(2, $attempt), 30)
            if ($resp -and $resp.Headers -and $resp.Headers.RetryAfter -and $resp.Headers.RetryAfter.Delta) {
                $delay = $resp.Headers.RetryAfter.Delta.TotalSeconds
            }
            Write-PTStatus -Level WARN -Message "Graph $Method returned $status; retrying in $delay s (attempt $($attempt + 1)/$MaxRetries)."
            Start-Sleep -Seconds $delay
        }
    }
}

function Test-PTInteractive {
    <# True when the session can prompt the operator (interactive host, stdin not redirected). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    try { return ([Environment]::UserInteractive -and -not [System.Console]::IsInputRedirected) }
    catch { return $false }
}

function Read-PTChoice {
    <#
        Prompts for one of a fixed set of options. Accepts the option NUMBER (1-based), the
        option NAME (case-insensitive), or empty input (returns $Default). Options are shown
        numbered so the operator can just type a digit.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string[]]$Option,
        [Parameter(Mandatory)][string]$Default
    )
    $numbered = @()
    for ($i = 0; $i -lt $Option.Count; $i++) { $numbered += "[$($i + 1)] $($Option[$i])" }
    $defaultIndex = [Array]::IndexOf($Option, $Default) + 1
    $label = "$Prompt $($numbered -join '  ') (default: $defaultIndex=$Default)"

    while ($true) {
        $answer = (Read-Host $label).Trim()
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
        $num = 0
        if ([int]::TryParse($answer, [ref]$num) -and $num -ge 1 -and $num -le $Option.Count) {
            return $Option[$num - 1]
        }
        $named = $Option | Where-Object { $_ -ieq $answer } | Select-Object -First 1
        if ($named) { return $named }
        Write-PTStatus -Level WARN -Message "Enter a number 1-$($Option.Count), or one of: $($Option -join ', ')."
    }
}

function Read-PTInteractiveConfig {
    <#
        Interactively builds a tenants.json-shaped config object, prompting for every field a
        tenant entry supports (UPN, identity path, agent account UPN, display name, skills mode,
        skills file). Loops so several tenants can be entered in one run.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $tenants = @()
    do {
        $upn = Read-Host 'Admin UPN (required, e.g. admin@contoso.onmicrosoft.com)'
        while ([string]::IsNullOrWhiteSpace($upn) -or $upn -notmatch '@') {
            $upn = Read-Host 'Enter a valid admin UPN (name@domain)'
        }
        $identityPath = Read-PTChoice -Prompt 'Identity path' -Option @('Auto', 'ExistingUser', 'NewAgentId') -Default 'Auto'
        $agentUpn = Read-Host 'Agent account UPN (optional - blank to skip)'
        $displayName = Read-Host 'Identity display name (optional - blank to skip)'
        $skillsMode = Read-PTChoice -Prompt 'Skills mode' -Option @('Default', 'Append', 'Replace') -Default 'Default'
        $skillsFile = ''
        if ($skillsMode -in @('Append', 'Replace')) { $skillsFile = Read-Host 'Skills file path (Windows or WSL)' }

        $entry = [ordered]@{ UserPrincipalName = $upn.Trim() }
        if ($identityPath -ne 'Auto') { $entry['IdentityPath'] = $identityPath }
        if (-not [string]::IsNullOrWhiteSpace($agentUpn)) { $entry['AgentAccountUpn'] = $agentUpn.Trim() }
        if (-not [string]::IsNullOrWhiteSpace($displayName)) { $entry['DisplayName'] = $displayName.Trim() }
        $entry['SkillsMode'] = $skillsMode
        if (-not [string]::IsNullOrWhiteSpace($skillsFile)) { $entry['SkillsFile'] = $skillsFile.Trim() }

        $tenants += [pscustomobject]$entry
        $more = Read-Host 'Add another tenant? (y/N)'
    } while ($more -match '^(y|yes)$')

    return [pscustomobject]@{ Tenants = $tenants }
}

function Save-PTConfig {
    <# Writes a config object to tenants.json (default config/tenants.json). Returns the path. #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $Config,
        [string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Join-Path (Split-Path $PSScriptRoot -Parent) 'config/tenants.json'
    }
    $Config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding utf8
    Write-PTStatus -Level OK -Message "Saved tenant config to '$Path'."
    return $Path
}

Export-ModuleMember -Function Get-PTDefaultScope, Get-PTProperty, Get-PTConfig, Get-PTDomainFromUpn,
    Write-PTStatus, Connect-PTGraph, Get-PTVerifiedDomain, Assert-PTTenant, Test-PTAdminRole,
    Invoke-PTGraphRequest, Test-PTInteractive, Read-PTInteractiveConfig, Save-PTConfig
