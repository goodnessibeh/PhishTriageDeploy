#Requires -Version 7.0
<#
    PTLicense.psm1
    License / subscription gate for the Phishing Triage Agent deployment tool:
      - Get-PTServicePlanId : the MDO Plan 2 (THREAT_INTELLIGENCE) service-plan GUID
      - Test-PTMdoPlan2     : HARD gate - MDO Plan 2 present via /subscribedSkus
      - Test-PTScuCapacity  : BEST-EFFORT Security Copilot SCU detection via Azure ARM
      - Get-PTLicenseGate   : orchestrates both checks into a single gate verdict

    PTCommon.psm1 is loaded by the orchestrator at runtime; this module calls
    Invoke-PTGraphRequest, Write-PTStatus and Get-PTProperty rather than re-implementing
    them. Read-only module: no state-changing verbs, no ShouldProcess needed.
#>

function Get-PTServicePlanId {
    <#
        Returns the well-known service-plan identifier for Microsoft Defender for Office 365
        Plan 2. The service plan named THREAT_INTELLIGENCE (GUID
        8e0c0a52-6a6c-4d40-8370-dd62790dcd70) is the plan whose presence in an enabled
        subscribed SKU proves MDO P2 entitlement, and is the plan the license gate looks for.

        Open item (design section 11): rather than trusting this hardcoded constant, resolve
        the GUID at runtime from Microsoft's published licensing service-plan reference CSV,
        so a rename or reissue on Microsoft's side cannot silently break the license gate.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return [pscustomobject]@{
        ServicePlanId   = '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'
        ServicePlanName = 'THREAT_INTELLIGENCE'
    }
}

function Test-PTMdoPlan2 {
    <#
        HARD license gate. Reads /v1.0/subscribedSkus and scans every SKU's service plans
        for the MDO Plan 2 service-plan id, treating a plan as active when its
        provisioningStatus or capabilityStatus indicates Enabled. The parent SKU must itself
        be enabled and carry available or consumed units (an empty or suspended SKU does not
        entitle anyone).

        Returns a pscustomobject:
            Present       [bool]           - MDO P2 usably present in this tenant
            SkuPartNumber [string or null] - the SKU that carries the plan (first match)
            Detail        [string]         - human-readable explanation of the verdict
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $target = (Get-PTServicePlanId).ServicePlanId

    try {
        $skus = Invoke-PTGraphRequest -Method GET -Uri '/v1.0/subscribedSkus'
    }
    catch {
        return [pscustomobject]@{
            Present       = $false
            SkuPartNumber = $null
            Detail        = "Could not read subscribedSkus: $($_.Exception.Message)"
        }
    }

    $skuList = @(Get-PTProperty $skus 'value')
    if ($skuList.Count -eq 0) {
        return [pscustomobject]@{
            Present       = $false
            SkuPartNumber = $null
            Detail        = 'subscribedSkus returned no subscriptions for this tenant.'
        }
    }

    foreach ($sku in $skuList) {
        $skuPart  = [string](Get-PTProperty $sku 'skuPartNumber' 'unknown-sku')
        $skuStat  = [string](Get-PTProperty $sku 'capabilityStatus' '')
        $prepaid  = Get-PTProperty $sku 'prepaidUnits'
        $enabled  = [int](Get-PTProperty $prepaid 'enabled' 0)
        $consumed = [int](Get-PTProperty $sku 'consumedUnits' 0)

        $skuUsable = ($skuStat -eq 'Enabled') -and (($enabled -gt 0) -or ($consumed -gt 0))
        if (-not $skuUsable) { continue }

        foreach ($plan in @(Get-PTProperty $sku 'servicePlans')) {
            if ([string](Get-PTProperty $plan 'servicePlanId') -ne $target) { continue }

            $prov = [string](Get-PTProperty $plan 'provisioningStatus' '')
            $cap  = [string](Get-PTProperty $plan 'capabilityStatus' '')
            $planActive = ($prov -eq 'Success') -or ($cap -eq 'Enabled')
            if (-not $planActive) { continue }

            return [pscustomobject]@{
                Present       = $true
                SkuPartNumber = $skuPart
                Detail        = ("MDO Plan 2 service plan THREAT_INTELLIGENCE is active on SKU " +
                                 "'$skuPart' (units enabled=$enabled, consumed=$consumed).")
            }
        }
    }

    return [pscustomobject]@{
        Present       = $false
        SkuPartNumber = $null
        Detail        = ("No enabled subscription carries the active MDO Plan 2 service plan " +
                         "($target). Checked $($skuList.Count) subscription(s).")
    }
}

function Test-PTScuCapacity {
    <#
        BEST-EFFORT Security Copilot Compute Unit (SCU) detection. There is NO reliable
        Microsoft Graph endpoint for SCUs: capacity is provisioned as an Azure Resource
        Manager (ARM) resource of type Microsoft.SecurityCopilot/capacities, which lives in
        an Azure subscription, not in the Graph/Entra surface this tool authenticates to.

        Supply an ARM bearer token (-AzureAccessToken, audience management.azure.com) and the
        owning -SubscriptionId to attempt a real ARM read. When both are supplied the function
        lists capacities and sets Present accordingly. When either is missing, or the ARM call
        fails, it returns Readable=$false and the caller must ask the operator to confirm.

        Returns a pscustomobject:
            Readable [bool]         - whether the ARM check actually ran and returned a verdict
            Present  [bool or null] - $true/$false when Readable; $null when not Readable
            Detail   [string]       - honest description of what was (or was not) checked
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$AzureAccessToken,
        [string]$SubscriptionId
    )

    if ([string]::IsNullOrWhiteSpace($AzureAccessToken)) {
        return [pscustomobject]@{
            Readable = $false
            Present  = $null
            Detail   = ('No Azure ARM access token supplied; SCU capacity cannot be read from ' +
                        'Graph and was not checked. Confirm Security Copilot SCU capacity manually.')
        }
    }
    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
        return [pscustomobject]@{
            Readable = $false
            Present  = $null
            Detail   = ('An ARM token was supplied but no -SubscriptionId; cannot target the ' +
                        'Microsoft.SecurityCopilot/capacities resource. Confirm SCU capacity manually.')
        }
    }

    $uri = ("https://management.azure.com/subscriptions/$SubscriptionId/providers/" +
            'Microsoft.SecurityCopilot/capacities?api-version=2023-12-01-preview')
    try {
        $headers = @{ Authorization = "Bearer $AzureAccessToken" }
        $resp = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -ErrorAction Stop
        $capacities = @(Get-PTProperty $resp 'value')
        $present = $capacities.Count -gt 0

        $detail = if ($present) {
            "ARM reports $($capacities.Count) Security Copilot capacity resource(s) in subscription $SubscriptionId."
        }
        else {
            "ARM reports no Security Copilot capacity resources in subscription $SubscriptionId."
        }

        return [pscustomobject]@{
            Readable = $true
            Present  = $present
            Detail   = $detail
        }
    }
    catch {
        return [pscustomobject]@{
            Readable = $false
            Present  = $null
            Detail   = ("ARM capacity read failed ($($_.Exception.Message)); SCU state is unknown. " +
                        'Confirm Security Copilot SCU capacity manually.')
        }
    }
}

function Get-PTLicenseGate {
    <#
        Orchestrates the license gate: the HARD MDO Plan 2 check (Test-PTMdoPlan2) plus the
        BEST-EFFORT SCU capacity check (Test-PTScuCapacity), logging each via Write-PTStatus.

        Pass -AzureAccessToken and -SubscriptionId through to enable the ARM SCU read; omit
        them to force the confirm branch.

        Returns a pscustomobject:
            MdoP2 [object] - the Test-PTMdoPlan2 result
            Scu   [object] - the Test-PTScuCapacity result
            Gate  [string] - one of:
                Pass       - MDO P2 present and SCU not proven absent
                FailMdo    - MDO P2 absent (hard stop)
                ConfirmScu - MDO P2 present but SCU capacity unreadable (operator must confirm)
                FailScu    - MDO P2 present but SCU capacity proven absent
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$AzureAccessToken,
        [string]$SubscriptionId
    )

    Write-PTStatus -Level INFO -Message 'License gate: checking MDO Plan 2 (hard gate)...'
    $mdo = Test-PTMdoPlan2
    if ($mdo.Present) {
        Write-PTStatus -Level OK -Message "MDO Plan 2 present: $($mdo.Detail)"
    }
    else {
        Write-PTStatus -Level FAIL -Message "MDO Plan 2 absent: $($mdo.Detail)"
    }

    Write-PTStatus -Level INFO -Message 'License gate: checking Security Copilot SCU capacity (best-effort)...'
    $scu = Test-PTScuCapacity -AzureAccessToken $AzureAccessToken -SubscriptionId $SubscriptionId
    if (-not $scu.Readable) {
        Write-PTStatus -Level WARN -Message "SCU capacity unreadable: $($scu.Detail)"
    }
    elseif ($scu.Present) {
        Write-PTStatus -Level OK -Message "SCU capacity present: $($scu.Detail)"
    }
    else {
        Write-PTStatus -Level FAIL -Message "SCU capacity absent: $($scu.Detail)"
    }

    $gate =
        if (-not $mdo.Present) { 'FailMdo' }
        elseif ($scu.Readable -and ($scu.Present -eq $false)) { 'FailScu' }
        elseif (-not $scu.Readable) { 'ConfirmScu' }
        else { 'Pass' }

    switch ($gate) {
        'Pass'       { Write-PTStatus -Level OK   -Message 'License gate: PASS.' }
        'FailMdo'    { Write-PTStatus -Level FAIL -Message 'License gate: FAIL (MDO Plan 2 required).' }
        'FailScu'    { Write-PTStatus -Level FAIL -Message 'License gate: FAIL (Security Copilot SCU capacity absent).' }
        'ConfirmScu' { Write-PTStatus -Level WARN -Message 'License gate: CONFIRM (SCU capacity unreadable; operator confirmation required).' }
    }

    return [pscustomobject]@{
        MdoP2 = $mdo
        Scu   = $scu
        Gate  = $gate
    }
}

Export-ModuleMember -Function Get-PTServicePlanId, Test-PTMdoPlan2, Test-PTScuCapacity, Get-PTLicenseGate
