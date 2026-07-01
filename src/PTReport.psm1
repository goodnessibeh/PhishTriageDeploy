#Requires -Version 7.0
<#
    PTReport.psm1
    Formats and prints the operator-facing output of the Phishing Triage Agent deployment
    tool. All console text lives here so the orchestrator can keep the report/exit-code logic
    separate from presentation:
      - Get-PTExitCodeName    : map a numeric exit code to a human label (pure, unit-testable)
      - Write-PTSummary       : per-tenant summary table for a multi-tenant / MSP sweep
      - Write-PTWizardChecklist : the numbered manual-handoff checklist (portal-only final step)

    Honesty note (design section 9): the first-party agent cannot be created programmatically -
    there is no instructions API. The checklist is a runbook the operator applies by hand in the
    security.microsoft.com wizard, gated by the Entra Security Administrator role.
#>

function Get-PTExitCodeName {
    <#
        Maps a tool exit code to a short human-readable label (design section 9). Pure helper
        with no side effects: safe to call from unit tests and from the summary formatter.
        Returns 'Unknown(<code>)' for any code the tool does not define.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][int]$Code)

    switch ($Code) {
        0  { return 'Success-ManualHandoff' }
        10 { return 'WrongTenant' }
        11 { return 'NoAdminRole' }
        20 { return 'MdoP2Absent' }
        21 { return 'ScuAbsent' }
        22 { return 'ScuUnconfirmed' }
        30 { return 'GraphWriteFailure' }
        default { return "Unknown($Code)" }
    }
}

function Write-PTSummary {
    <#
        Prints a per-tenant summary table for a multi-tenant / MSP sweep. Each element of
        -TenantResult is a [pscustomobject] describing one tenant's outcome, with fields such as
        Tenant, LicenseGate, IdentityPath, IdentityName, PermissionStatus and ExitCode. The
        numeric ExitCode is rendered alongside its human label from Get-PTExitCodeName. Missing
        fields are read safely via Get-PTProperty and shown as '-'. No return value.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$TenantResult)

    Write-Host ''
    Write-Host 'Per-tenant summary'
    Write-Host '=================='

    if (-not $TenantResult -or $TenantResult.Count -eq 0) {
        Write-PTStatus -Level INFO -Message 'No tenant results to report.'
        return
    }

    $rows = foreach ($result in $TenantResult) {
        $code = [int](Get-PTProperty $result 'ExitCode' 0)
        [pscustomobject]@{
            Tenant     = [string](Get-PTProperty $result 'Tenant' '-')
            License    = [string](Get-PTProperty $result 'LicenseGate' '-')
            IdPath     = [string](Get-PTProperty $result 'IdentityPath' '-')
            Identity   = [string](Get-PTProperty $result 'IdentityName' '-')
            Permission = [string](Get-PTProperty $result 'PermissionStatus' '-')
            Exit       = $code
            Outcome    = Get-PTExitCodeName -Code $code
        }
    }

    $rows | Format-Table -AutoSize -Property Tenant, License, IdPath, Identity, Permission, Exit, Outcome | Out-Host

    $failures = @($rows | Where-Object { $_.Exit -ne 0 })
    if ($failures.Count -eq 0) {
        Write-PTStatus -Level OK -Message "All $($rows.Count) tenant(s) reached the manual-handoff stage."
    }
    else {
        Write-PTStatus -Level WARN -Message "$($failures.Count) of $($rows.Count) tenant(s) hard-stopped before handoff."
    }
}

function Write-PTWizardChecklist {
    <#
        Prints the numbered manual-handoff checklist the operator follows to finish setup in the
        portal (design sections 1 and 9). -Identity is the resolved agent identity object (or
        $null when none was created/selected and the operator must create an Entra Agent ID in
        the wizard); its DisplayName and Id are surfaced in step 2. -SkillsPath is where the
        resolved skills / runbook document was written. -PortalReady reflects whether upstream
        prereq detection judged the portal ready; when $false the operator is warned to clear the
        reported prereqs first. No return value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$Identity,
        [Parameter(Mandatory)][string]$SkillsPath,
        [Parameter(Mandatory)][bool]$PortalReady
    )

    Write-Host ''
    Write-Host 'Manual handoff - finish in the portal'
    Write-Host '====================================='

    if ($PortalReady) {
        Write-PTStatus -Level OK -Message 'Prereq detection found no blocking items. Proceed with the steps below.'
    }
    else {
        Write-PTStatus -Level WARN -Message 'Prereq detection flagged items above - clear them before finishing the wizard.'
    }

    Write-Host ''
    Write-Host '  1. Go to security.microsoft.com > Security Copilot > Agents and start'
    Write-Host '     "set up the Phishing Triage Agent".'

    Write-Host ''
    if ($null -ne $Identity) {
        $displayName = [string](Get-PTProperty $Identity 'DisplayName' '(unnamed)')
        $identityId = [string](Get-PTProperty $Identity 'Id' '(unknown id)')
        Write-Host '  2. Select the identity this tool staged:'
        Write-Host ("       DisplayName : {0}" -f $displayName)
        Write-Host ("       Id          : {0}" -f $identityId)
        Write-Host '     The 5 Defender URBAC permissions are already assigned to it.'
    }
    else {
        Write-Host '  2. No identity was staged (skip path). Create a new Entra Agent ID inside'
        Write-Host '     the wizard, then assign the 5 Defender URBAC permissions to it.'
    }

    Write-Host ''
    Write-Host '  3. Finishing the wizard REQUIRES the Entra Security Administrator role.'
    Write-Host '     If your account lacks it, hand off to an admin who holds it.'

    Write-Host ''
    Write-Host '  4. Apply the whitelists and seed the initial feedback from the skills document:'
    Write-Host ("       {0}" -f $SkillsPath)

    Write-Host ''
    Write-Host '  5. Reminder: the first-party agent has no instructions API. The skills document'
    Write-Host '     is a runbook you apply manually in the portal - there is nothing further to'
    Write-Host '     automate from this tool.'

    Write-Host ''
    if ($null -ne $Identity) {
        Write-PTStatus -Level INFO -Message 'All automatable work is done. The remaining steps are portal-only.'
    }
    else {
        Write-PTStatus -Level INFO -Message 'Readiness check complete. Identity and permissions are portal-only on the skip path.'
    }
}

Export-ModuleMember -Function Get-PTExitCodeName, Write-PTSummary, Write-PTWizardChecklist
