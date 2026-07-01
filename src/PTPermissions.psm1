#Requires -Version 7.0
<#
    PTPermissions.psm1
    Reconciles the five Microsoft Defender Unified RBAC (URBAC) permissions the Phishing
    Triage Agent identity needs. The permissions live in the "Security operations" group and
    are granted by a single custom role scoped to the Microsoft Defender for Office 365 (MDO)
    data source - NOT Graph app-roles and NOT Entra directory roles. Work is done through the
    Graph Defender RBAC BETA provider:
        /beta/roleManagement/defender/roleDefinitions
        /beta/roleManagement/defender/roleAssignments

    Public surface:
      - Get-PTPermissionSpec      : load config/permissions.json (the declarative source of truth)
      - Set-PTUrbacRole           : idempotent ensure of the custom role (create / patch drift / OK)
      - Set-PTRoleAssignment      : idempotent ensure of role -> principal binding
      - Get-PTPermissionDrift     : pure set diff of declared vs actual permissions (no network)
      - Invoke-PTPermissionReconcile : orchestrates role + assignment + read-back drift report

    Depends on PTCommon (loaded at runtime): Invoke-PTGraphRequest, Write-PTStatus, Get-PTProperty.

    OPEN ITEM (design section 11): the exact permission-identifier strings carried in a Defender
    roleDefinition payload are not yet confirmed against a live tenant. The mapping from the five
    human permission names to their API "allowedResourceActions" representation is therefore
    DERIVED here from permissions.json (see Resolve-PTPermissionAction) so it is easy to correct:
      - to hard-set a real identifier, add an "action" field to a permission entry in the config;
      - otherwise a plausible "<prefix>/<slug>/<level>" string is synthesised.
    The data-source scope string is likewise a plausible placeholder pending live confirmation.
#>

# Plausible URBAC action namespace - OPEN ITEM, confirm against a live tenant (design 11).
$Script:PTUrbacActionPrefix = 'microsoft.xdr.securityOperations'
# Plausible MDO data-source scope for the roleDefinition - OPEN ITEM, confirm against a tenant.
$Script:PTUrbacDataSourceScope = 'microsoft.defender/dataSources/mdo'

function Resolve-PTPermissionAction {
    <#
        Maps one declared permission (a { name; level; [action] } object) to its API action
        identifier. If the config entry carries an explicit "action" it wins (the correction
        hook); otherwise a plausible "<prefix>/<slug>/<level>" identifier is synthesised.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Permission)

    $explicit = Get-PTProperty $Permission 'action'
    if (-not [string]::IsNullOrWhiteSpace([string]$explicit)) { return [string]$explicit }

    $name  = [string](Get-PTProperty $Permission 'name' '')
    $level = [string](Get-PTProperty $Permission 'level' 'read')
    $slug  = ($name.ToLowerInvariant() -replace '[^a-z0-9]+', '.').Trim('.')
    return ('{0}/{1}/{2}' -f $Script:PTUrbacActionPrefix, $slug, $level.ToLowerInvariant())
}

function Get-PTSpecActionList {
    <# Flattens a spec object's Permissions into the list of declared action identifiers. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] $Spec)

    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($p in @(Get-PTProperty $Spec 'Permissions' @())) {
        $out.Add((Resolve-PTPermissionAction -Permission $p))
    }
    return [string[]]$out
}

function Get-PTRoleActionList {
    <# Extracts the actual action identifiers carried by a live Defender roleDefinition object. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] $Role)

    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($rp in @(Get-PTProperty $Role 'rolePermissions' @())) {
        foreach ($a in @(Get-PTProperty $rp 'allowedResourceActions' @())) {
            if (-not [string]::IsNullOrWhiteSpace([string]$a)) { $out.Add([string]$a) }
        }
    }
    return [string[]]$out
}

function Get-PTPermissionSpec {
    <#
        .SYNOPSIS
        Loads config/permissions.json - the declarative source of truth for the five URBAC
        permissions - and returns the parsed object (RoleName, DataSource, Permissions[...]).
        .PARAMETER ConfigPath
        Override path. Defaults to <repo-root>/config/permissions.json.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param([string]$ConfigPath)

    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        $ConfigPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'config/permissions.json'
    }
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Permission spec not found at '$ConfigPath'."
    }
    try { return (Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json) }
    catch { throw "Failed to read permission spec '$ConfigPath': $($_.Exception.Message)" }
}

function Get-PTPermissionDrift {
    <#
        .SYNOPSIS
        Pure, network-free set diff of declared vs actual permission identifiers. Comparison is
        case-insensitive. Returns InSync plus the Missing (declared, not present) and Extra
        (present, not declared) sets. Unit-testable in isolation.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Declared,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Actual
    )

    $cmp         = [System.StringComparer]::OrdinalIgnoreCase
    $declaredSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$Declared, $cmp)
    $actualSet   = [System.Collections.Generic.HashSet[string]]::new([string[]]$Actual, $cmp)

    $missing = @($declaredSet | Where-Object { -not $actualSet.Contains($_) })
    $extra   = @($actualSet   | Where-Object { -not $declaredSet.Contains($_) })

    return [pscustomobject]@{
        InSync  = (($missing.Count -eq 0) -and ($extra.Count -eq 0))
        Missing = [string[]]$missing
        Extra   = [string[]]$extra
    }
}

function Set-PTUrbacRole {
    <#
        .SYNOPSIS
        Idempotently ensures the custom Defender URBAC role that carries the five permissions.
        Reads the current roleDefinitions, then: creates the role if absent, PATCHes it if its
        permission set has drifted, or reports OK if it already matches. Honours -WhatIf.
        .PARAMETER Spec
        Parsed permission spec. Loaded from config/permissions.json when omitted.
        .OUTPUTS
        [pscustomobject] with RoleId, Created, DriftFixed.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param($Spec)

    if ($null -eq $Spec) { $Spec = Get-PTPermissionSpec }
    $roleName = [string](Get-PTProperty $Spec 'RoleName' '')
    $declared = Get-PTSpecActionList -Spec $Spec

    $existing = $null
    $resp = Invoke-PTGraphRequest -Method GET -Uri '/beta/roleManagement/defender/roleDefinitions'
    foreach ($r in @(Get-PTProperty $resp 'value' @())) {
        if ([string](Get-PTProperty $r 'displayName') -eq $roleName) { $existing = $r; break }
    }

    # Full desired-state body (used for both create and drift-fixing patch).
    $body = @{
        displayName     = $roleName
        description     = [string](Get-PTProperty $Spec 'RoleDescription' '')
        isEnabled       = $true
        rolePermissions = @(@{ allowedResourceActions = $declared })
        resourceScopes  = @($Script:PTUrbacDataSourceScope)
    }

    if ($null -eq $existing) {
        if ($PSCmdlet.ShouldProcess($roleName, 'Create Defender URBAC role')) {
            $created = Invoke-PTGraphRequest -Method POST `
                -Uri '/beta/roleManagement/defender/roleDefinitions' -Body $body
            $newId = [string](Get-PTProperty $created 'id')
            Write-PTStatus -Level OK -Message "Created URBAC role '$roleName' ($newId) with $($declared.Count) permissions."
            return [pscustomobject]@{ RoleId = $newId; Created = $true; DriftFixed = $false }
        }
        Write-PTStatus -Level DRYRUN -Message "Would create URBAC role '$roleName' with $($declared.Count) permissions."
        return [pscustomobject]@{ RoleId = $null; Created = $false; DriftFixed = $false }
    }

    $roleId = [string](Get-PTProperty $existing 'id')
    $actual = Get-PTRoleActionList -Role $existing
    $drift  = Get-PTPermissionDrift -Declared $declared -Actual $actual

    if ($drift.InSync) {
        Write-PTStatus -Level OK -Message "URBAC role '$roleName' already matches the declared permission set."
        return [pscustomobject]@{ RoleId = $roleId; Created = $false; DriftFixed = $false }
    }

    $target = "$roleName (missing: $($drift.Missing.Count), extra: $($drift.Extra.Count))"
    if ($PSCmdlet.ShouldProcess($target, 'Patch Defender URBAC role to fix permission drift')) {
        Invoke-PTGraphRequest -Method PATCH `
            -Uri "/beta/roleManagement/defender/roleDefinitions/$roleId" -Body $body | Out-Null
        Write-PTStatus -Level OK -Message "Fixed permission drift on '$roleName' ($target)."
        return [pscustomobject]@{ RoleId = $roleId; Created = $false; DriftFixed = $true }
    }
    Write-PTStatus -Level DRYRUN -Message "Would patch '$roleName' to fix drift ($target)."
    return [pscustomobject]@{ RoleId = $roleId; Created = $false; DriftFixed = $false }
}

function Set-PTRoleAssignment {
    <#
        .SYNOPSIS
        Idempotently ensures a Defender URBAC role assignment binding -RoleId to -PrincipalId.
        Reads current roleAssignments; if the binding exists it is reported OK, otherwise it is
        created. Honours -WhatIf.
        .OUTPUTS
        [pscustomobject] with AssignmentId, Created.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$RoleId,
        [Parameter(Mandatory)][string]$PrincipalId
    )

    $resp = Invoke-PTGraphRequest -Method GET -Uri '/beta/roleManagement/defender/roleAssignments'
    foreach ($a in @(Get-PTProperty $resp 'value' @())) {
        $rid = [string](Get-PTProperty $a 'roleDefinitionId')
        if ($rid -ne $RoleId) { continue }

        # Principals may be exposed as a collection (principalIds) or a scalar (principalId).
        $principals = @(Get-PTProperty $a 'principalIds' @())
        $single     = [string](Get-PTProperty $a 'principalId')
        if (-not [string]::IsNullOrWhiteSpace($single)) { $principals += $single }

        if ($principals -contains $PrincipalId) {
            $aid = [string](Get-PTProperty $a 'id')
            Write-PTStatus -Level OK -Message "Role assignment already binds role '$RoleId' to principal '$PrincipalId'."
            return [pscustomobject]@{ AssignmentId = $aid; Created = $false }
        }
    }

    $body = @{ roleDefinitionId = $RoleId; principalIds = @($PrincipalId) }
    if ($PSCmdlet.ShouldProcess($PrincipalId, "Assign Defender URBAC role '$RoleId'")) {
        $created = Invoke-PTGraphRequest -Method POST `
            -Uri '/beta/roleManagement/defender/roleAssignments' -Body $body
        $aid = [string](Get-PTProperty $created 'id')
        Write-PTStatus -Level OK -Message "Assigned role '$RoleId' to principal '$PrincipalId' ($aid)."
        return [pscustomobject]@{ AssignmentId = $aid; Created = $true }
    }
    Write-PTStatus -Level DRYRUN -Message "Would assign role '$RoleId' to principal '$PrincipalId'."
    return [pscustomobject]@{ AssignmentId = $null; Created = $false }
}

function Invoke-PTPermissionReconcile {
    <#
        .SYNOPSIS
        End-to-end idempotent reconcile of the URBAC permission model for a principal: ensure the
        custom role, ensure the role -> principal assignment, then read the role back and compute
        declared-vs-actual drift. Honours and passes -WhatIf through to the write steps.
        .PARAMETER PrincipalId
        Object id of the agent identity that must hold the role.
        .PARAMETER ConfigPath
        Override path to permissions.json.
        .OUTPUTS
        [pscustomobject] with Role, Assignment, Drift, Status
        (Status = created | already-present | drift-fixed | dryrun).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        [string]$ConfigPath
    )

    $spec = Get-PTPermissionSpec -ConfigPath $ConfigPath
    $role = Set-PTUrbacRole -Spec $spec

    if ([string]::IsNullOrWhiteSpace([string]$role.RoleId)) {
        # No role id yet (dry-run create): nothing to bind against.
        Write-PTStatus -Level DRYRUN -Message 'Role not yet created (dry-run); skipping role assignment.'
        $assignment = [pscustomobject]@{ AssignmentId = $null; Created = $false }
    }
    else {
        $assignment = Set-PTRoleAssignment -RoleId $role.RoleId -PrincipalId $PrincipalId
    }

    # Read back and diff declared vs actual for the drift report.
    $declared = Get-PTSpecActionList -Spec $spec
    $roleName = [string](Get-PTProperty $spec 'RoleName' '')
    $actual   = @()
    $resp = Invoke-PTGraphRequest -Method GET -Uri '/beta/roleManagement/defender/roleDefinitions'
    foreach ($r in @(Get-PTProperty $resp 'value' @())) {
        if ([string](Get-PTProperty $r 'displayName') -eq $roleName) {
            $actual = Get-PTRoleActionList -Role $r
            break
        }
    }
    $drift = Get-PTPermissionDrift -Declared $declared -Actual $actual

    $status =
        if ($WhatIfPreference)                            { 'dryrun' }
        elseif ($role.Created -or $assignment.Created)   { 'created' }
        elseif ($role.DriftFixed)                        { 'drift-fixed' }
        else                                             { 'already-present' }

    return [pscustomobject]@{
        Role       = $role
        Assignment = $assignment
        Drift      = $drift
        Status     = $status
    }
}

Export-ModuleMember -Function Get-PTPermissionSpec, Set-PTUrbacRole, Set-PTRoleAssignment,
    Get-PTPermissionDrift, Invoke-PTPermissionReconcile
