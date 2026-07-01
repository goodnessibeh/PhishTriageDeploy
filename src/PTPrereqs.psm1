#Requires -Version 7.0
<#
    PTPrereqs.psm1
    Report-only detection of the MANUAL prerequisites for the Microsoft Defender
    for Office 365 (MDO) Phishing Triage Agent. This module NEVER writes.

    Most of these settings are not reliably readable via the public Microsoft Graph
    surface - that is precisely the point of this tool. When a state cannot be read
    with confidence, the item is reported as 'VerifyInPortal' together with the exact
    portal path the operator should open. Reported items:
      - URBAC (Unified RBAC) workload activation for Defender for Office 365.
      - "Monitor reported messages in Outlook" user-reported setting.
      - Alert policy "Email reported by user as malware or phish" is ON.
      - The built-in "Auto-Resolve - Email reported by user as malware or phish"
        alert-tuning rule is OFF (and any custom rule resolving that alert).

    Public functions:
      - Get-PTPrereqItem   : construct a single prereq result object (no side effects)
      - Get-PTPrereqReport : best-effort detection, returns an array of prereq items

    Depends on PTCommon.psm1 (loaded at runtime): Invoke-PTGraphRequest, Write-PTStatus,
    Get-PTProperty. Those are called here, never re-implemented.
#>

function Get-PTPrereqItem {
    <#
        .SYNOPSIS
        Builds a single prerequisite result object.

        .DESCRIPTION
        Pure constructor with no side effects (named with the Get- verb so the
        analyzer does not demand SupportsShouldProcess). State is constrained to
        the four values the report uses. Detail carries the portal location or the
        evidence behind the verdict.

        .OUTPUTS
        pscustomobject with Name, State, Detail properties.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('On', 'Off', 'Unknown', 'VerifyInPortal')][string]$State,
        [Parameter(Mandatory)][string]$Detail
    )
    return [pscustomobject]@{
        Name   = $Name
        State  = $State
        Detail = $Detail
    }
}

function Write-PTPrereqLine {
    <#
        .SYNOPSIS
        Logs one prereq item through Write-PTStatus with a level matching its state.

        .DESCRIPTION
        On maps to OK; Off and VerifyInPortal map to WARN (operator action likely
        needed); Unknown maps to INFO. Internal helper, not exported.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Item)

    $level = switch ($Item.State) {
        'On'   { 'OK' }
        'Off'  { 'WARN' }
        'Unknown' { 'INFO' }
        default { 'WARN' }
    }
    Write-PTStatus -Level $level -Message ('{0}: {1} - {2}' -f $Item.Name, $Item.State, $Item.Detail)
}

function Get-PTUrbacWorkloadItem {
    <#
        .SYNOPSIS
        Reports URBAC (Unified RBAC) workload activation for Defender for Office 365.

        .DESCRIPTION
        Best-effort read of the Defender RBAC activation surface (beta). The workload
        activation state for individual data sources is not exposed as a stable,
        publicly documented Graph property, so a successful read is treated as a hint
        only and the operator is still pointed at the portal to confirm.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $portal = 'security.microsoft.com > System > Permissions > Roles (activate Microsoft Defender for Office 365 workload)'
    try {
        $resp = Invoke-PTGraphRequest -Method GET -Uri '/beta/roleManagement/defender/roleDefinitions?$top=1'
        $value = Get-PTProperty $resp 'value' $null
        if ($null -ne $value) {
            return Get-PTPrereqItem -Name 'URBAC workload activation (MDO)' -State 'VerifyInPortal' `
                -Detail ("Defender RBAC endpoint is reachable but per-workload activation is not a documented Graph state. Confirm at $portal")
        }
        return Get-PTPrereqItem -Name 'URBAC workload activation (MDO)' -State 'VerifyInPortal' `
            -Detail ("Defender RBAC state not exposed via Graph. Confirm at $portal")
    }
    catch {
        $hint = 'Confirm at ' + $portal
        if ($_.Exception.Message -match '403|Forbidden') {
            $hint = ('A 403 usually means the RoleManagement.ReadWrite.Defender scope was not consented, ' +
                'or Unified RBAC is not activated for this workload, or the account is not Security Administrator. ' +
                'Confirm/activate at ' + $portal)
        }
        return Get-PTPrereqItem -Name 'URBAC workload activation (MDO)' -State 'VerifyInPortal' `
            -Detail ("Could not read Defender RBAC via Graph ($($_.Exception.Message)). $hint")
    }
}

function Get-PTReportedMessageItem {
    <#
        .SYNOPSIS
        Reports the "Monitor reported messages in Outlook" user-reported setting.

        .DESCRIPTION
        The user-reported-message policy lives in Exchange Online / the Defender
        portal and is not surfaced through public Microsoft Graph. Reported as
        VerifyInPortal with the portal path; no Graph call is attempted because none
        reliably returns this value.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $portal = 'security.microsoft.com > Settings > Email & collaboration > User reported settings > Monitor reported messages in Outlook'
    return Get-PTPrereqItem -Name 'Monitor reported messages in Outlook' -State 'VerifyInPortal' `
        -Detail ("Not exposed via public Graph. Confirm 'Monitor reported messages in Outlook' is enabled at $portal")
}

function Get-PTAlertPolicyItem {
    <#
        .SYNOPSIS
        Reports whether the alert policy "Email reported by user as malware or phish"
        is ON.

        .DESCRIPTION
        Purview / Defender alert policies are not exposed through public Microsoft
        Graph (they live behind the Security & Compliance PowerShell surface). Marked
        VerifyInPortal with the portal path.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $portal = 'security.microsoft.com > Policies & rules > Alert policy > Email reported by user as malware or phish (Status = On)'
    return Get-PTPrereqItem -Name 'Alert policy "Email reported by user as malware or phish"' -State 'VerifyInPortal' `
        -Detail ("Alert policy state not exposed via public Graph. Confirm the policy Status is On at $portal")
}

function Get-PTAutoResolveRuleItem {
    <#
        .SYNOPSIS
        Reports whether the built-in "Auto-Resolve - Email reported by user as
        malware or phish" alert-tuning rule is OFF.

        .DESCRIPTION
        Alert-tuning rules (including any custom rule that auto-resolves this alert)
        are managed in the Defender portal and are not exposed via public Microsoft
        Graph. The desired state is OFF so the agent still receives the alerts; when
        unreadable this is reported as VerifyInPortal with the portal path.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $portal = 'security.microsoft.com > Settings > Microsoft Defender XDR > Alert tuning (built-in "Auto-Resolve - Email reported by user as malware or phish" must be Off; also check custom rules resolving this alert)'
    return Get-PTPrereqItem -Name 'Auto-resolve alert-tuning rule is off' -State 'VerifyInPortal' `
        -Detail ("Alert-tuning rules not exposed via public Graph. Confirm the auto-resolve rule (and any custom equivalent) is Off at $portal")
}

function Get-PTPrereqReport {
    <#
        .SYNOPSIS
        Best-effort detection of every manual Phishing Triage Agent prerequisite.

        .DESCRIPTION
        Runs the individual, report-only detectors, logs each result through
        Write-PTStatus (OK for On; WARN for Off or VerifyInPortal; INFO for Unknown),
        and returns the collected items. This function performs no writes. Any Graph
        calls made by the detectors are wrapped in try/catch and downgrade to
        VerifyInPortal on failure, so a read error never stops the report.

        .OUTPUTS
        pscustomobject[] - one prereq item per prerequisite.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    Write-PTStatus -Level INFO -Message 'Detecting manual prerequisites (report-only; nothing is changed)...'

    $items = @(
        Get-PTUrbacWorkloadItem
        Get-PTReportedMessageItem
        Get-PTAlertPolicyItem
        Get-PTAutoResolveRuleItem
    )

    foreach ($item in $items) {
        Write-PTPrereqLine -Item $item
    }

    return [pscustomobject[]]$items
}

Export-ModuleMember -Function Get-PTPrereqItem, Get-PTPrereqReport
