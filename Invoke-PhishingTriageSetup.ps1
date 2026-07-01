#Requires -Version 7.0
<#
.SYNOPSIS
    Stages a tenant for the Microsoft Defender for Office 365 Phishing Triage Agent:
    verifies licenses, creates/selects the agent identity, assigns the five Defender URBAC
    permissions, reports manual prerequisites, and prints the portal wizard handoff.

.DESCRIPTION
    Multi-tenant, idempotent reconciler. Mirrors the MDOMigrate idioms: UPN-based
    config/tenants.json, interactive delegated OAuth (Connect-MgGraph), wrong-tenant guard,
    and DRY-RUN by default (writes only under -Live). The Phishing Triage Agent itself is
    created in the Defender portal wizard (no API exists); this tool automates everything
    up to that final manual step.

.PARAMETER ConfigPath
    Path to tenants.json. Defaults to config/tenants.json next to this script.

.PARAMETER Tenant
    Optional UPN (or domain) filter: process only the matching tenant from the config.

.PARAMETER Live
    Perform writes. Without it the run is a dry-run (WhatIf) and mutates nothing.

.PARAMETER Force
    Do not prompt for confirmation (e.g. auto-continue past an unreadable SCU check).

.PARAMETER IdentityMode
    Create | SelectExisting | Skip | Prompt (default Prompt).

.PARAMETER SkillsMode
    Default | Append | Replace (default Default) for the skills/instructions document.

.PARAMETER SkillsFile
    Path (Windows or WSL) to a user skills markdown, for Append/Replace.

.EXAMPLE
    ./Invoke-PhishingTriageSetup.ps1                 # dry-run sweep of all configured tenants

.EXAMPLE
    ./Invoke-PhishingTriageSetup.ps1 -Live -Tenant admin@contoso.onmicrosoft.com
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath,
    [string]$Tenant,
    [switch]$Live,
    [switch]$Force,
    [ValidateSet('Create', 'SelectExisting', 'Skip', 'Prompt')][string]$IdentityMode = 'Prompt',
    [ValidateSet('Default', 'Append', 'Replace')][string]$SkillsMode = 'Default',
    [string]$SkillsFile
)

# --- exit-code map (see PTReport/Get-PTExitCodeName) ---
$Script:PTExit = @{
    Success        = 0
    WrongTenant    = 10
    NoAdminRole    = 11
    MdoP2Absent    = 20
    ScuAbsent      = 21
    ScuUnconfirmed = 22
    WriteFailure   = 30
}

# Dry-run by default: turning on WhatIf makes every SupportsShouldProcess function skip writes.
if (-not $Live) { $WhatIfPreference = $true }

# --- load modules (PTCommon first; the rest resolve their PTCommon calls at runtime) ---
Import-Module (Join-Path $PSScriptRoot 'src/PTCommon.psm1') -Force -ErrorAction Stop
Get-ChildItem (Join-Path $PSScriptRoot 'src') -Filter 'PT*.psm1' |
    Where-Object { $_.Name -ne 'PTCommon.psm1' } |
    ForEach-Object { Import-Module $_.FullName -Force -ErrorAction Stop }

function Resolve-PTTenantSkill {
    <# Resolves the effective skills document for a tenant (default/append/replace). #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([string]$Mode, [string]$File)

    $userContent = $null
    if ($Mode -in @('Append', 'Replace')) {
        if ([string]::IsNullOrWhiteSpace($File)) { throw "SkillsMode '$Mode' needs -SkillsFile." }
        $userContent = Get-PTSkillsContent -Path $File
    }
    return Resolve-PTSkillsDocument -Mode $Mode -UserContent $userContent
}

function Invoke-PTTenantSetup {
    <# Runs the full gated pipeline for a single tenant. Returns a result [pscustomobject]. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $TenantEntry,
        [string]$IdentityMode = 'Prompt',
        [switch]$Force,
        [string]$SkillsMode = 'Default',
        [string]$SkillsFile
    )

    $upn = Get-PTProperty $TenantEntry 'UserPrincipalName'
    $domain = Get-PTDomainFromUpn $upn
    $result = [pscustomobject]@{
        Tenant           = $upn
        LicenseGate      = 'n/a'
        IdentityPath     = 'n/a'
        IdentityName     = 'n/a'
        PermissionStatus = 'n/a'
        ExitCode         = $Script:PTExit.Success
    }

    Write-PTStatus -Level INFO -Message "=== Tenant: $upn (domain: $domain) ==="

    # 0. Connect + wrong-tenant guard
    try { Connect-PTGraph -UserPrincipalName $upn -TenantDomain $domain | Out-Null }
    catch {
        Write-PTStatus -Level FAIL -Message "Connect/guard failed: $($_.Exception.Message)"
        $result.ExitCode = $Script:PTExit.WrongTenant
        return $result
    }

    # 1. Admin role
    if (-not (Test-PTAdminRole)) {
        Write-PTStatus -Level FAIL -Message 'Signed-in admin lacks Entra Security Administrator.'
        $result.ExitCode = $Script:PTExit.NoAdminRole
        return $result
    }

    # 2. License gate
    $gate = Get-PTLicenseGate
    $result.LicenseGate = $gate.Gate
    switch ($gate.Gate) {
        'FailMdo' {
            Write-PTStatus -Level FAIL -Message 'MDO Plan 2 absent - closing per license requirement.'
            $result.ExitCode = $Script:PTExit.MdoP2Absent; return $result
        }
        'FailScu' {
            Write-PTStatus -Level FAIL -Message 'Security Copilot SCU capacity absent - closing.'
            $result.ExitCode = $Script:PTExit.ScuAbsent; return $result
        }
        'ConfirmScu' {
            Write-PTStatus -Level WARN -Message 'SCU capacity could not be verified via API.'
            if (-not $Force) {
                $answer = Read-Host 'Continue anyway? Confirm SCU capacity exists (y/N)'
                if ($answer -notmatch '^(y|yes)$') {
                    Write-PTStatus -Level FAIL -Message 'SCU not confirmed - closing.'
                    $result.ExitCode = $Script:PTExit.ScuUnconfirmed; return $result
                }
            }
        }
    }

    # 3. Identity resolve (detect/create/select/skip)
    $idParams = @{ Mode = $IdentityMode }
    $dn = Get-PTProperty $TenantEntry 'DisplayName'
    $agentUpn = Get-PTProperty $TenantEntry 'AgentAccountUpn'
    if ($dn) { $idParams['DisplayName'] = $dn }
    if ($agentUpn) { $idParams['UserPrincipalName'] = $agentUpn }
    $configuredPath = Get-PTProperty $TenantEntry 'IdentityPath'
    if ($configuredPath -eq 'ExistingUser') { $idParams['Mode'] = 'Create' }
    elseif ($configuredPath -eq 'NewAgentId') { $idParams['Mode'] = 'Skip' }

    try { $identity = Resolve-PTIdentity @idParams }
    catch {
        Write-PTStatus -Level FAIL -Message "Identity resolution failed: $($_.Exception.Message)"
        $result.ExitCode = $Script:PTExit.WriteFailure; return $result
    }
    $result.IdentityPath = $identity.Path
    if ($identity.Identity) { $result.IdentityName = $identity.Identity.DisplayName }

    # 4. Permission gate (only when we have a concrete identity to bind)
    if ($identity.Identity -and $identity.Identity.Id) {
        try {
            $recon = Invoke-PTPermissionReconcile -PrincipalId $identity.Identity.Id
            $result.PermissionStatus = $recon.Status
        }
        catch {
            Write-PTStatus -Level FAIL -Message "Permission reconcile failed: $($_.Exception.Message)"
            $result.ExitCode = $Script:PTExit.WriteFailure; return $result
        }
    }
    else {
        $result.PermissionStatus = 'deferred-to-wizard'
        Write-PTStatus -Level SKIP -Message 'No pre-assignable identity (new Agent ID path) - permissions handled in the wizard.'
    }

    # 5. Skills document -> Desktop runbook copy the operator pastes into the portal.
    # A personal deliverable, not a tenant change, so it is produced in dry-run too.
    $skillsPath = $null
    try {
        $skill = Resolve-PTTenantSkill -Mode $SkillsMode -File $SkillsFile
        $fileName = 'phishing-triage-runbook-{0}.md' -f ($domain -replace '[^0-9A-Za-z]', '-')
        $skillsPath = Join-Path (Get-PTDesktopPath) $fileName
        Save-PTSkillsDocument -Content $skill.Content -Path $skillsPath -WhatIf:$false | Out-Null
    }
    catch { Write-PTStatus -Level WARN -Message "Skills document step skipped: $($_.Exception.Message)" }

    # 6. Prereq report -> readiness -> wizard handoff
    if ([string]::IsNullOrWhiteSpace($skillsPath)) { $skillsPath = '(runbook not written)' }
    $prereqs = @(Get-PTPrereqReport)
    $portalReady = @($prereqs | Where-Object { $_.State -ne 'On' }).Count -eq 0
    Write-PTWizardChecklist -Identity $identity.Identity -SkillsPath $skillsPath -PortalReady $portalReady

    return $result
}

# ---------------- main ----------------
$mode = if ($Live) { 'LIVE' } else { 'DRY-RUN (no writes; pass -Live to apply)' }
Write-PTStatus -Level INFO -Message "Phishing Triage Agent setup - mode: $mode"

$config = Get-PTConfig -ConfigPath $ConfigPath
$synthesized = $false
if (-not $config) {
    if ($Tenant) {
        # -Tenant supplied standalone: build a minimal config from it (other fields prompt at their steps).
        $config = [pscustomobject]@{ Tenants = @([pscustomobject]@{ UserPrincipalName = $Tenant }) }
        $synthesized = $true
    }
    elseif (Test-PTInteractive) {
        Write-PTStatus -Level WARN -Message 'No config/tenants.json found - starting interactive setup.'
        $config = Read-PTInteractiveConfig
        $save = Read-Host 'Save these details to config/tenants.json for next time? (y/N)'
        if ($save -match '^(y|yes)$') { Save-PTConfig -Config $config -Path $ConfigPath | Out-Null }
        $synthesized = $true
    }
    else {
        Write-PTStatus -Level FAIL -Message 'No config/tenants.json found (non-interactive). Copy tenants.example.json and edit it.'
        exit 1
    }
}

$tenants = @(Get-PTProperty $config 'Tenants')
if ($Tenant -and -not $synthesized) {
    $tenants = @($tenants | Where-Object { (Get-PTProperty $_ 'UserPrincipalName') -like "*$Tenant*" })
}
if (-not $tenants.Count) { Write-PTStatus -Level FAIL -Message 'No matching tenants in config.'; exit 1 }

$results = @()
foreach ($entry in $tenants) {
    try {
        $results += Invoke-PTTenantSetup -TenantEntry $entry -IdentityMode $IdentityMode `
            -Force:$Force -SkillsMode $SkillsMode -SkillsFile $SkillsFile
    }
    catch {
        Write-PTStatus -Level FAIL -Message "Unhandled error for tenant: $($_.Exception.Message)"
        $results += [pscustomobject]@{ Tenant = (Get-PTProperty $entry 'UserPrincipalName'); LicenseGate = 'error';
            IdentityPath = 'n/a'; IdentityName = 'n/a'; PermissionStatus = 'n/a'; ExitCode = $Script:PTExit.WriteFailure }
    }
}

Write-PTSummary -TenantResult $results
$worst = ($results.ExitCode | Measure-Object -Maximum).Maximum
exit [int]$worst
