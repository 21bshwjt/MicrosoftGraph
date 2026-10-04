# 04. M365 - Entra Conditional Access Policies Insights - Beta API
# Graph permission (Application): Policy.Read.All, RoleManagement.Read.Directory, User.Read.All, GroupMember.Read.All,
#                                 Application.Read.All, Agreement.Read.All (optional - Terms of Use names)

#region Authentication & Authorization
#. (Join-Path $PSScriptRoot "..\Connect-M365Tenant.ps1")
#endregion
. (Join-Path $PSScriptRoot "..\Icovar.ps1")
. (Join-Path $PSScriptRoot "..\ExcelPathConfig.ps1")

#region Generic Variables
if (-not $Token) { throw 'No access token found in $Token. Check Connect-M365Tenant.ps1.' }

$BaseApi = 'https://graph.microsoft.com'
$ApiVersion = 'beta'     # beta exposes the most CA properties (insider/agent risk, token protection, GSA)
$GraphUri = "$BaseApi/$ApiVersion"
$BatchSize = 20         # Microsoft Graph $batch hard limit
$MaxRetries = 5          # Retries for throttling (429) / transient (5xx) errors

$Headers = @{ 'Authorization' = "Bearer $Token" }
#endregion

#region Graph Helper Functions
function Invoke-Graph {
    # Graph call with retry on throttling (429) and transient server errors (5xx)
    param([Parameter(Mandatory)][string]$Uri, [string]$Method = 'GET', [object]$Body)

    $Attempt = 0
    while ($true) {
        try {
            $Splat = @{ Uri = $Uri; Headers = $Headers; Method = $Method; ErrorAction = 'Stop' }
            if ($null -ne $Body) {
                $Splat.Body = $Body | ConvertTo-Json -Depth 20 -Compress
                $Splat.ContentType = 'application/json'
            }
            return Invoke-RestMethod @Splat
        }
        catch {
            $Response = $_.Exception.Response
            $StatusCode = if ($Response) { [int]$Response.StatusCode } else { 0 }

            if ($StatusCode -eq 401) {
                throw 'Graph returned 401 Unauthorized - the access token is missing or expired. Re-run Connect-M365Tenant.'
            }
            if (($StatusCode -eq 429 -or $StatusCode -ge 500) -and $Attempt -lt $MaxRetries) {
                $Attempt++
                $Wait = [math]::Min(60, [math]::Pow(2, $Attempt) * 2)
                try { if ($Response.Headers.RetryAfter.Delta) { $Wait = [int]$Response.Headers.RetryAfter.Delta.TotalSeconds } } catch {}  # PS 7
                try { if ($Response.Headers['Retry-After']) { $Wait = [int]$Response.Headers['Retry-After'] } } catch {}                 # PS 5.1
                Write-Warning "Graph returned HTTP $StatusCode. Retry $Attempt/$MaxRetries in $Wait seconds..."
                Start-Sleep -Seconds $Wait
                continue
            }
            throw
        }
    }
}

function Get-GraphAllPages {
    # Follows @odata.nextLink until all pages are retrieved
    param([Parameter(Mandatory)][string]$Uri)
    $Next = $Uri
    while ($Next) {
        $R = Invoke-Graph -Uri $Next
        if ($null -ne $R.PSObject.Properties['value']) { $R.value } else { $R }
        $Next = $R.'@odata.nextLink'
    }
}
#endregion

#region Configuration
$GaRoleTemplateId = '62e90394-69f5-4237-9190-012177145e10'   # Global Administrator
$PhishResistantStrength = '00000000-0000-0000-0000-000000000004'   # Built-in "Phishing-resistant MFA" strength
$AzureManagementAppId = '797f4846-ba00-4fd7-ba43-dac1f8f63013'   # Windows Azure Service Management API

# First-party apps that often have no service principal in the tenant
$KnownApps = @{
    '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Windows Azure Service Management API'
    '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
    '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
    '00000003-0000-0ff1-ce00-000000000000' = 'Office 365 SharePoint Online'
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' = 'Azure Portal'
    '0000000a-0000-0000-c000-000000000000' = 'Microsoft Intune'
    'd4ebce55-015a-49b5-a083-c84d1797ae8c' = 'Microsoft Intune Enrollment'
}

$GrantNames = @{
    block                       = 'Block access'
    mfa                         = 'Require multifactor authentication'
    compliantDevice             = 'Require device to be marked as compliant'
    domainJoinedDevice          = 'Require Microsoft Entra hybrid joined device'
    approvedApplication         = 'Require approved client app'
    compliantApplication        = 'Require app protection policy'
    applicationProtectionPolicy = 'Require app protection policy'
    passwordChange              = 'Require password change'
    riskRemediation             = 'Require risk remediation'
}

$UserActionNames = @{
    'urn:user:registersecurityinfo' = 'Register security information'
    'urn:user:registerdevice'       = 'Register or join devices'
}

$SpecialMap = @{
    user     = @{ All = 'All users'; None = 'None'; GuestsOrExternalUsers = 'Guests or external users' }
    group    = @{ All = 'All groups' }
    role     = @{ All = 'All roles' }
    app      = @{ All = 'All cloud apps'; None = 'None'; Office365 = 'Office 365'; MicrosoftAdminPortals = 'Microsoft Admin Portals' }
    sp       = @{ All = 'All'; None = 'None'; ServicePrincipalsInMyTenant = 'All service principals in my tenant' }
    location = @{ All = 'Any location'; AllTrusted = 'All trusted locations' }
    context  = @{}
    tou      = @{}
}
#endregion

#region Helper Functions
function Test-Guid {
    param([string]$Value)
    $g = [guid]::Empty
    [guid]::TryParse($Value, [ref]$g)
}

# GET requests through /$batch (20 per call). Throttled/transient sub-requests are re-queued.
# Returns: request id -> batch response item ($null if the whole batch call failed)
function Invoke-GraphBatchGet {
    param([object[]]$Requests)

    $Results = @{}
    $Retries = @{}
    $ById = @{}
    $Queue = [System.Collections.Generic.Queue[object]]::new()
    foreach ($R in $Requests) { $ById[$R.id] = $R; $Queue.Enqueue($R) }

    while ($Queue.Count -gt 0) {
        $Chunk = [System.Collections.Generic.List[object]]::new()
        while ($Chunk.Count -lt $BatchSize -and $Queue.Count -gt 0) {
            $R = $Queue.Dequeue()
            $Chunk.Add(@{ id = $R.id; method = 'GET'; url = $R.url })
        }

        try {
            $Resp = Invoke-Graph -Uri "$GraphUri/`$batch" -Method POST -Body @{ requests = $Chunk.ToArray() }
        }
        catch {
            Write-Warning "  Batch failed: $($_.Exception.Message)"
            foreach ($C in $Chunk) { $Results[$C.id] = $null }
            continue
        }

        $Wait = 0
        foreach ($Item in $Resp.responses) {
            $Status = [int]$Item.status
            if (($Status -eq 429 -or $Status -ge 500) -and [int]$Retries[$Item.id] -lt $MaxRetries) {
                $Retries[$Item.id] = 1 + [int]$Retries[$Item.id]
                $Queue.Enqueue($ById[$Item.id])
                $Wait = [math]::Max($Wait, [math]::Max([int]$Item.headers.'Retry-After', 5))
            }
            else {
                $Results[$Item.id] = $Item
            }
        }
        if ($Wait) { Start-Sleep -Seconds $Wait }
    }
    $Results
}

# Name from a single-object batch response; 404 = object deleted but still referenced by a policy
function Get-BatchName {
    param($Resp, [string]$Id)
    if (-not $Resp) { return $Id }
    switch ([int]$Resp.status) {
        200 { if ($Resp.body.displayName) { $Resp.body.displayName } else { $Id } }
        404 { "$Id (deleted)" }
        default { $Id }
    }
}

# IDs -> readable names (special values, resolved names, else the raw ID)
function Resolve-Ids {
    param($Ids, [string]$Kind)
    $List = @($Ids | Where-Object { $_ })
    if ($List.Count -eq 0) { return 'None' }
    ($List | ForEach-Object {
        $Id = [string]$_
        if ($SpecialMap[$Kind].ContainsKey($Id)) { $SpecialMap[$Kind][$Id] }
        elseif ($NameMaps[$Kind].ContainsKey($Id)) { $NameMaps[$Kind][$Id] }
        elseif ($Kind -eq 'location') { "Unknown location ($Id)" }
        elseif ($Kind -eq 'context') { "Unknown context ($Id)" }
        else { $Id }
    }) -join ', '
}

function Join-OrNone {
    param($Values)
    $List = @($Values | Where-Object { $_ })
    if ($List.Count) { $List -join ', ' } else { 'None' }
}

function Format-Guests {
    param($Guests)
    if (-not $Guests) { return 'None' }
    $Types = ($Guests.guestOrExternalUserTypes -split ',' | Where-Object { $_ }) -join ', '
    $Tenants = $Guests.externalTenants
    $Scope = if (-not $Tenants) { 'N/A' }
    elseif ($Tenants.membershipKind -eq 'all') { 'all external tenants' }
    else { 'tenants: ' + (@($Tenants.members) -join ', ') }
    "$Types ($Scope)"
}

function Format-Date {
    param($Value)
    if ($Value) { ([datetime]$Value).ToString('yyyy-MM-dd') } else { 'N/A' }
}

# --- Baseline predicates (raw policy object) ---
function Test-MfaGrant { param($P) [bool](($P.grantControls.builtInControls -contains 'mfa') -or $P.grantControls.authenticationStrength) }
function Test-BlockGrant { param($P) [bool]($P.grantControls.builtInControls -contains 'block') }
function Test-AllUsers { param($P) [bool]($P.conditions.users.includeUsers -contains 'All') }
function Test-AllApps { param($P) [bool]($P.conditions.applications.includeApplications -contains 'All') }
function Test-HasRoles { param($P) [bool](@($P.conditions.users.includeRoles | Where-Object { $_ }).Count -gt 0) }
function Test-TargetsGA { param($P) [bool]((Test-AllUsers $P) -or ($P.conditions.users.includeRoles -contains $GaRoleTemplateId)) }
#endregion

#region Fetch Conditional Access data
$Policies = @(Get-GraphAllPages -Uri "$GraphUri/identity/conditionalAccess/policies")
Write-Host "  Conditional Access policies: $($Policies.Count)"

$NamedLocations = @(Get-GraphAllPages -Uri "$GraphUri/identity/conditionalAccess/namedLocations")
$AuthContexts = @(Get-GraphAllPages -Uri "$GraphUri/identity/conditionalAccess/authenticationContextClassReferences")
$AuthStrengths = @(Get-GraphAllPages -Uri "$GraphUri/policies/authenticationStrengthPolicies")
Write-Host "  Named locations: $($NamedLocations.Count) | Auth contexts: $($AuthContexts.Count) | Auth strengths: $($AuthStrengths.Count)"

# Role names - CA policies reference roles by templateId
$RoleNames = @{}
try {
    foreach ($Role in (Get-GraphAllPages -Uri "$BaseApi/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName,templateId")) {
        $RoleNames[$Role.id] = $Role.displayName
        if ($Role.templateId) { $RoleNames[$Role.templateId] = $Role.displayName }
    }
}
catch { Write-Warning "  Role definitions not available ($($_.Exception.Message)). Role IDs will be shown." }

# Terms of Use names (optional permission)
$TouNames = @{}
try {
    foreach ($Tou in (Get-GraphAllPages -Uri "$GraphUri/identityGovernance/termsOfUse/agreements?`$select=id,displayName")) { $TouNames[$Tou.id] = $Tou.displayName }
}
catch { Write-Warning "  Terms of Use not available (Agreement.Read.All missing?). Terms of Use IDs will be shown." }

# Soft-deleted policies (recoverable for 30 days) - optional
$DeletedPolicies = $null
try { $DeletedPolicies = @(Get-GraphAllPages -Uri "$GraphUri/identity/conditionalAccess/deletedItems/policies") }
catch { Write-Warning "  Deleted policies not available ($($_.Exception.Message))." }

$LocationNames = @{}; foreach ($L in $NamedLocations) { $LocationNames[$L.id] = $L.displayName }
$ContextNames = @{}; foreach ($C in $AuthContexts) { $ContextNames[$C.id] = $C.displayName }
$StrengthById = @{}; foreach ($S in $AuthStrengths) { $StrengthById[$S.id] = $S }
#endregion

#region Resolve users, groups, service principals and apps (unique IDs only, batched)
$UserIds = [System.Collections.Generic.HashSet[string]]::new()
$GroupIds = [System.Collections.Generic.HashSet[string]]::new()
$SpIds = [System.Collections.Generic.HashSet[string]]::new()
$AppIds = [System.Collections.Generic.HashSet[string]]::new()

foreach ($P in $Policies) {
    $U = $P.conditions.users
    foreach ($Id in @($U.includeUsers) + @($U.excludeUsers)) { if (Test-Guid $Id) { [void]$UserIds.Add($Id) } }
    foreach ($Id in @($U.includeGroups) + @($U.excludeGroups)) { if (Test-Guid $Id) { [void]$GroupIds.Add($Id) } }
    $CA = $P.conditions.clientApplications
    foreach ($Id in @($CA.includeServicePrincipals) + @($CA.excludeServicePrincipals)) { if (Test-Guid $Id) { [void]$SpIds.Add($Id) } }
    $A = $P.conditions.applications
    foreach ($Id in @($A.includeApplications) + @($A.excludeApplications)) { if ((Test-Guid $Id) -and -not $KnownApps.ContainsKey($Id)) { [void]$AppIds.Add($Id) } }
}

$Requests = [System.Collections.Generic.List[object]]::new()
foreach ($Id in $UserIds) { $Requests.Add(@{ id = "u_$Id"; url = "/users/$($Id)?`$select=displayName" }) }
foreach ($Id in $GroupIds) { $Requests.Add(@{ id = "g_$Id"; url = "/groups/$($Id)?`$select=displayName" }) }
foreach ($Id in $SpIds) { $Requests.Add(@{ id = "s_$Id"; url = "/servicePrincipals/$($Id)?`$select=displayName" }) }
# Apps are referenced by appId: look up their service principals, 15 appIds per request ($filter 'in' limit)
$AppList = @($AppIds)
$AppChunks = @{}
for ($i = 0; $i -lt $AppList.Count; $i += 15) {
    $Chunk = $AppList[$i..([math]::Min($i + 14, $AppList.Count - 1))]
    $Filter = [uri]::EscapeDataString("appId in ('" + ($Chunk -join "','") + "')")
    $AppChunks["a_$i"] = $Chunk
    $Requests.Add(@{ id = "a_$i"; url = "/servicePrincipals?`$filter=$Filter&`$select=appId,displayName" })
}

Write-Host "  Resolving names: $($UserIds.Count) users, $($GroupIds.Count) groups, $($SpIds.Count) service principals, $($AppIds.Count) apps"
$Batch = if ($Requests.Count) { Invoke-GraphBatchGet -Requests $Requests.ToArray() } else { @{} }

$UserNames = @{}; foreach ($Id in $UserIds) { $UserNames[$Id] = Get-BatchName $Batch["u_$Id"] $Id }
$GroupNames = @{}; foreach ($Id in $GroupIds) { $GroupNames[$Id] = Get-BatchName $Batch["g_$Id"] $Id }
$SpNames = @{}; foreach ($Id in $SpIds) { $SpNames[$Id] = Get-BatchName $Batch["s_$Id"] $Id }
$AppNames = @{} + $KnownApps
foreach ($Key in $AppChunks.Keys) {
    $Resp = $Batch[$Key]
    if ($Resp -and [int]$Resp.status -eq 200) { foreach ($Sp in $Resp.body.value) { $AppNames[$Sp.appId] = $Sp.displayName } }
}

$NameMaps = @{ user = $UserNames; group = $GroupNames; role = $RoleNames; app = $AppNames; sp = $SpNames; location = $LocationNames; context = $ContextNames; tou = $TouNames }
#endregion

#region Build policy rows (one column per setting)
$LocationUsage = @{}; $StrengthUsage = @{}; $ContextUsage = @{}
function Add-Usage {
    param([hashtable]$Map, $Ids, [string]$PolicyName)
    foreach ($Id in @($Ids | Where-Object { $_ })) {
        if (-not $Map.ContainsKey($Id)) { $Map[$Id] = [System.Collections.Generic.List[string]]::new() }
        if (-not $Map[$Id].Contains($PolicyName)) { $Map[$Id].Add($PolicyName) }
    }
}

$PolicyRows = foreach ($P in ($Policies | Sort-Object displayName)) {
    $C = $P.conditions
    $U = $C.users
    $A = $C.applications
    $G = $P.grantControls
    $S = $P.sessionControls

    Add-Usage $LocationUsage (@($C.locations.includeLocations) + @($C.locations.excludeLocations)) $P.displayName
    Add-Usage $ContextUsage $A.includeAuthenticationContextClassReferences $P.displayName
    if ($G.authenticationStrength.id) { Add-Usage $StrengthUsage $G.authenticationStrength.id $P.displayName }

    # Grant controls
    $Controls = @($G.builtInControls | Where-Object { $_ } | ForEach-Object { if ($GrantNames.ContainsKey($_)) { $GrantNames[$_] } else { $_ } })
    $Strength = $G.authenticationStrength
    $StrengthName = if ($Strength) { if ($Strength.displayName) { $Strength.displayName } elseif ($StrengthById[$Strength.id]) { $StrengthById[$Strength.id].displayName } else { $Strength.id } } else { 'None' }
    $StrengthCombos = if ($Strength) {
        $Combos = if ($Strength.allowedCombinations) { $Strength.allowedCombinations } else { $StrengthById[$Strength.id].allowedCombinations }
        Join-OrNone $Combos
    }
    else { 'None' }

    # Session controls
    $Sif = $S.signInFrequency
    $SignInFrequency = if ($Sif.isEnabled) {
        $Every = if ($Sif.frequencyInterval -eq 'everyTime') { 'Every time' } else { "$($Sif.value) $($Sif.type)" }
        $AuthType = switch ($Sif.authenticationType) { 'secondaryAuthentication' { 'secondary auth only' } 'primaryAndSecondaryAuthentication' { 'primary + secondary auth' } default { $Sif.authenticationType } }
        if ($AuthType) { "$Every ($AuthType)" } else { $Every }
    }
    else { 'Not configured' }

    # Display values
    $IncUsers = Resolve-Ids $U.includeUsers 'user'; $ExcUsers = Resolve-Ids $U.excludeUsers 'user'
    $IncGroups = Resolve-Ids $U.includeGroups 'group'; $ExcGroups = Resolve-Ids $U.excludeGroups 'group'
    $IncRoles = Resolve-Ids $U.includeRoles 'role'; $ExcRoles = Resolve-Ids $U.excludeRoles 'role'
    $IncApps = Resolve-Ids $A.includeApplications 'app'; $ExcApps = Resolve-Ids $A.excludeApplications 'app'
    $IncSps = Resolve-Ids $C.clientApplications.includeServicePrincipals 'sp'
    $ExcSps = Resolve-Ids $C.clientApplications.excludeServicePrincipals 'sp'
    $IncLocs = Resolve-Ids $C.locations.includeLocations 'location'
    $ExcLocs = Resolve-Ids $C.locations.excludeLocations 'location'
    $Contexts = Resolve-Ids $A.includeAuthenticationContextClassReferences 'context'
    $Tou = Resolve-Ids $G.termsOfUse 'tou'

    $DeviceFilter = if ($C.devices.deviceFilter) { "$($C.devices.deviceFilter.mode): $($C.devices.deviceFilter.rule)" } else { 'None' }
    if ($C.devices.includeDevices -or $C.devices.excludeDevices) {
        $DeviceFilter += " | Legacy include: $(Join-OrNone $C.devices.includeDevices); exclude: $(Join-OrNone $C.devices.excludeDevices)"
    }

    # Findings (informational)
    $Findings = [System.Collections.Generic.List[string]]::new()
    switch ($P.state) {
        'disabled' { $Findings.Add('Policy disabled') }
        'enabledForReportingButNotEnforced' { $Findings.Add('Report-only (not enforced)') }
    }
    $ExclusionCount = @(@($U.excludeUsers) + @($U.excludeGroups) + @($U.excludeRoles) | Where-Object { $_ -and $_ -ne 'None' }).Count
    $HasGuestExclusion = [bool]$U.excludeGuestsOrExternalUsers
    if ($ExclusionCount) { $Findings.Add("Exclusions: $ExclusionCount (review break-glass / exceptions)") }
    if ("$IncUsers $ExcUsers $IncGroups $ExcGroups $IncSps $ExcSps" -match '\(deleted\)') { $Findings.Add('References deleted object(s)') }
    if ($P.state -eq 'enabled' -and (Test-AllUsers $P) -and -not $ExclusionCount -and -not $HasGuestExclusion) {
        $Findings.Add('All users with no exclusions (lockout risk - exclude emergency access accounts)')
    }
    if ((Test-BlockGrant $P) -and -not $ExclusionCount -and -not $HasGuestExclusion) { $Findings.Add('Block policy with no exclusions') }
    if ($G.operator -eq 'OR' -and ($Controls.Count + [int][bool]$Strength) -gt 1) { $Findings.Add('Grant uses OR - any one control satisfies the policy') }
    if ($Contexts -match 'Unknown context') { $Findings.Add('References unknown authentication context') }
    if ("$IncLocs $ExcLocs" -match 'Unknown location') { $Findings.Add('References unknown / system location') }

    [PSCustomObject][ordered]@{
        PolicyName                 = $P.displayName
        State                      = $P.state
        Findings                   = if ($Findings.Count) { $Findings -join '; ' } else { 'None' }
        IncludeUsers               = $IncUsers
        ExcludeUsers               = $ExcUsers
        IncludeGroups              = $IncGroups
        ExcludeGroups              = $ExcGroups
        IncludeRoles               = $IncRoles
        ExcludeRoles               = $ExcRoles
        IncludeGuests              = Format-Guests $U.includeGuestsOrExternalUsers
        ExcludeGuests              = Format-Guests $U.excludeGuestsOrExternalUsers
        IncludeApps                = $IncApps
        ExcludeApps                = $ExcApps
        UserActions                = Join-OrNone ($A.includeUserActions | Where-Object { $_ } | ForEach-Object { if ($UserActionNames.ContainsKey($_)) { $UserActionNames[$_] } else { $_ } })
        AuthContexts               = $Contexts
        AppFilter                  = if ($A.applicationFilter) { "$($A.applicationFilter.mode): $($A.applicationFilter.rule)" } else { 'None' }
        IncludeWorkloadIdentities  = $IncSps
        ExcludeWorkloadIdentities  = $ExcSps
        WorkloadIdentityFilter     = if ($C.clientApplications.servicePrincipalFilter) { "$($C.clientApplications.servicePrincipalFilter.mode): $($C.clientApplications.servicePrincipalFilter.rule)" } else { 'None' }
        IncludePlatforms           = Join-OrNone $C.platforms.includePlatforms
        ExcludePlatforms           = Join-OrNone $C.platforms.excludePlatforms
        IncludeLocations           = $IncLocs
        ExcludeLocations           = $ExcLocs
        ClientAppTypes             = Join-OrNone $C.clientAppTypes
        DeviceFilter               = $DeviceFilter
        UserRisk                   = Join-OrNone $C.userRiskLevels
        SignInRisk                 = Join-OrNone $C.signInRiskLevels
        InsiderRisk                = Join-OrNone $C.insiderRiskLevels
        ServicePrincipalRisk       = Join-OrNone $C.servicePrincipalRiskLevels
        AgentIdRisk                = Join-OrNone $C.agentIdRiskLevels
        AuthFlows                  = if ($C.authenticationFlows.transferMethods) { $C.authenticationFlows.transferMethods } else { 'None' }
        GrantOperator              = if ($G.operator) { $G.operator } else { 'None' }
        GrantControls              = if ($Controls.Count) { $Controls -join '; ' } else { 'None' }
        AuthStrength               = $StrengthName
        AuthStrengthMethods        = $StrengthCombos
        TermsOfUse                 = $Tou
        CustomAuthFactors          = Join-OrNone $G.customAuthenticationFactors
        SignInFrequency            = $SignInFrequency
        PersistentBrowser          = if ($S.persistentBrowser.isEnabled) { $S.persistentBrowser.mode } else { 'Not configured' }
        CloudAppSecurity           = if ($S.cloudAppSecurity.isEnabled) { $S.cloudAppSecurity.cloudAppSecurityType } else { 'Not configured' }
        AppEnforcedRestrictions    = if ($S.applicationEnforcedRestrictions.isEnabled) { 'Enabled' } else { 'Not configured' }
        ContinuousAccessEvaluation = if ($S.continuousAccessEvaluation.mode) { $S.continuousAccessEvaluation.mode } else { 'Default' }
        ResilienceDefaults         = if ($S.disableResilienceDefaults -eq $true) { 'Disabled' } else { 'Default (enabled)' }
        TokenProtection            = if ($S.secureSignInSession.isEnabled) { 'Enabled' } else { 'Not configured' }
        GSAFilteringProfile        = if ($S.globalSecureAccessFilteringProfile.profileId) { $S.globalSecureAccessFilteringProfile.profileId } else { 'Not configured' }
        TemplateId                 = if ($P.templateId) { $P.templateId } else { 'None' }
        Created                    = Format-Date $P.createdDateTime
        Modified                   = Format-Date $P.modifiedDateTime
        PolicyId                   = $P.id
    }
}
$PolicyRows = @($PolicyRows)
if ($PolicyRows.Count -eq 0) {
    $PolicyRows = @([PSCustomObject]@{ PolicyName = 'No Conditional Access policies found'; State = 'N/A'; Findings = 'No Conditional Access policies are configured' })
}
#endregion

#region Baseline checks (Microsoft / CIS recommendations)
$BaselineChecks = @(
    @{ Check = 'Require MFA for administrators'; Note = 'Targets Global Administrator (or all users), all cloud apps, MFA / auth strength'
        Test = { param($P) (Test-TargetsGA $P) -and (Test-AllApps $P) -and (Test-MfaGrant $P) }
    }
    @{ Check = 'Phishing-resistant MFA for administrators'; Note = 'Targets Global Administrator (or all users), all cloud apps, "Phishing-resistant MFA" strength'
        Test = { param($P) (Test-TargetsGA $P) -and (Test-AllApps $P) -and ($P.grantControls.authenticationStrength.id -eq $PhishResistantStrength) }
    }
    @{ Check = 'Require MFA for all users'; Note = 'All users, all cloud apps, MFA / auth strength'
        Test = { param($P) (Test-AllUsers $P) -and (Test-AllApps $P) -and (Test-MfaGrant $P) }
    }
    @{ Check = 'Require MFA for guests'; Note = 'All users or guests/external users, all cloud apps, MFA / auth strength'
        Test = { param($P) ((Test-AllUsers $P) -or ($P.conditions.users.includeUsers -contains 'GuestsOrExternalUsers') -or $P.conditions.users.includeGuestsOrExternalUsers) -and (Test-AllApps $P) -and (Test-MfaGrant $P) }
    }
    @{ Check = 'Require MFA for Azure management'; Note = 'All cloud apps or Windows Azure Service Management API, MFA / auth strength'
        Test = { param($P) ((Test-AllApps $P) -or ($P.conditions.applications.includeApplications -contains $AzureManagementAppId)) -and ((Test-AllUsers $P) -or (Test-HasRoles $P)) -and (Test-MfaGrant $P) }
    }
    @{ Check = 'Require MFA for Microsoft Admin Portals'; Note = 'All cloud apps or Microsoft Admin Portals, MFA / auth strength'
        Test = { param($P) ((Test-AllApps $P) -or ($P.conditions.applications.includeApplications -contains 'MicrosoftAdminPortals')) -and ((Test-AllUsers $P) -or (Test-HasRoles $P)) -and (Test-MfaGrant $P) }
    }
    @{ Check = 'Block legacy authentication'; Note = 'All users, client apps "Exchange ActiveSync" / "Other clients", Block'
        Test = { param($P) (Test-AllUsers $P) -and (($P.conditions.clientAppTypes -contains 'exchangeActiveSync') -or ($P.conditions.clientAppTypes -contains 'other')) -and (Test-BlockGrant $P) }
    }
    @{ Check = 'Sign-in risk policy'; Note = 'Sign-in risk condition with MFA or Block (requires Entra ID P2)'
        Test = { param($P) (@($P.conditions.signInRiskLevels | Where-Object { $_ }).Count -gt 0) -and ((Test-MfaGrant $P) -or (Test-BlockGrant $P)) }
    }
    @{ Check = 'User risk policy'; Note = 'User risk condition with password change / risk remediation / Block (requires Entra ID P2)'
        Test = { param($P) (@($P.conditions.userRiskLevels | Where-Object { $_ }).Count -gt 0) -and (($P.grantControls.builtInControls -contains 'passwordChange') -or ($P.grantControls.builtInControls -contains 'riskRemediation') -or (Test-BlockGrant $P)) }
    }
    @{ Check = 'Block device code flow'; Note = 'Authentication flows "Device code flow", Block'
        Test = { param($P) ("$($P.conditions.authenticationFlows.transferMethods)" -match 'deviceCodeFlow') -and (Test-BlockGrant $P) }
    }
    @{ Check = 'Protect security info registration'; Note = 'User action "Register security information" with a grant or location condition'
        Test = { param($P) ($P.conditions.applications.includeUserActions -contains 'urn:user:registersecurityinfo') }
    }
    @{ Check = 'Require MFA to register or join devices'; Note = 'User action "Register or join devices", MFA / auth strength'
        Test = { param($P) ($P.conditions.applications.includeUserActions -contains 'urn:user:registerdevice') -and (Test-MfaGrant $P) }
    }
    @{ Check = 'Sign-in frequency for administrators'; Note = 'Targets directory roles, sign-in frequency session control'
        Test = { param($P) (Test-HasRoles $P) -and $P.sessionControls.signInFrequency.isEnabled }
    }
    @{ Check = 'No persistent browser for administrators'; Note = 'Targets directory roles, persistent browser = never'
        Test = { param($P) (Test-HasRoles $P) -and $P.sessionControls.persistentBrowser.isEnabled -and ($P.sessionControls.persistentBrowser.mode -eq 'never') }
    }
)

$BaselineRows = foreach ($B in $BaselineChecks) {
    $Matched = @($Policies | Where-Object { & $B.Test $_ })
    $Enforced = @($Matched | Where-Object { $_.state -eq 'enabled' })
    $ReportOnly = @($Matched | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' })
    [PSCustomObject][ordered]@{
        Check                = $B.Check
        Status               = if ($Enforced.Count) { 'COMPLIANT' } elseif ($ReportOnly.Count) { 'REPORT-ONLY' } else { 'NOT-COMPLIANT' }
        EnforcedBy           = Join-OrNone $Enforced.displayName
        ReportOnlyCandidates = Join-OrNone $ReportOnly.displayName
        Requirement          = $B.Note
    }
}
$BaselineRows = @($BaselineRows)
Write-Host "  Baseline: $(@($BaselineRows | Where-Object Status -eq 'COMPLIANT').Count) of $($BaselineRows.Count) checks compliant"
#endregion

#region Supporting objects
$NamedLocationRows = @($NamedLocations | Sort-Object displayName | ForEach-Object {
        $Type = switch -Wildcard ($_.'@odata.type') { '*ipNamedLocation' { 'IP ranges' } '*countryNamedLocation' { 'Countries' } default { ($_.'@odata.type' -replace '#microsoft.graph.', '') } }
        [PSCustomObject][ordered]@{
            Name                    = $_.displayName
            Type                    = $Type
            Trusted                 = if ($null -ne $_.isTrusted) { $_.isTrusted } else { 'N/A' }
            IpRanges                = Join-OrNone ($_.ipRanges | ForEach-Object { $_.cidrAddress })
            Countries               = Join-OrNone $_.countriesAndRegions
            IncludeUnknownCountries = if ($null -ne $_.includeUnknownCountriesAndRegions) { $_.includeUnknownCountriesAndRegions } else { 'N/A' }
            LookupMethod            = if ($_.countryLookupMethod) { $_.countryLookupMethod } else { 'N/A' }
            UsedByPolicies          = if ($LocationUsage[$_.id]) { $LocationUsage[$_.id] -join ', ' } else { 'Not used' }
            Created                 = Format-Date $_.createdDateTime
            Modified                = Format-Date $_.modifiedDateTime
            Id                      = $_.id
        }
    })

$AuthStrengthRows = @($AuthStrengths | Sort-Object policyType, displayName | ForEach-Object {
        [PSCustomObject][ordered]@{
            Name                  = $_.displayName
            Type                  = $_.policyType
            RequirementsSatisfied = $_.requirementsSatisfied
            AllowedCombinations   = Join-OrNone $_.allowedCombinations
            UsedByPolicies        = if ($StrengthUsage[$_.id]) { $StrengthUsage[$_.id] -join ', ' } else { 'Not used' }
            Description           = $_.description
            Id                    = $_.id
        }
    })

$AuthContextRows = @($AuthContexts | Sort-Object id | ForEach-Object {
        [PSCustomObject][ordered]@{
            Id             = $_.id
            Name           = $_.displayName
            Description    = $_.description
            IsAvailable    = $_.isAvailable
            UsedByPolicies = if ($ContextUsage[$_.id]) { $ContextUsage[$_.id] -join ', ' } else { 'Not used' }
        }
    })

$DeletedRows = if ($null -ne $DeletedPolicies) {
    @($DeletedPolicies | ForEach-Object {
            [PSCustomObject][ordered]@{
                PolicyName = $_.displayName
                State      = $_.state
                Deleted    = Format-Date $_.deletedDateTime
                Modified   = Format-Date $_.modifiedDateTime
                PolicyId   = $_.id
            }
        })
}
else { @() }
#endregion

#region HTML Output
$Ps1FileName = $($MyInvocation.MyCommand.Name)
$DirName = ($Ps1FileName -split "_")[0]
$HtmFileName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)

# Ensure the output directory exists
$OutputDir = Join-Path $PSScriptRoot "..\Output\$DirName"
if (!(Test-Path $OutputDir)) {
    [void](New-Item -ItemType Directory -Path $OutputDir -Force)
}

$FirstLine = Get-Content $MyInvocation.MyCommand.Path -TotalCount 1
$Title = $FirstLine -replace '^#\s*\d+\.\s*', ''
$date = (Get-Date).ToString('MM-dd-yyyy')
$headertxt = "<H2><Center>$Title | $date </Center></H2>"

New-HTML -FavIcon $icon -TitleText $Title {
    New-HTMLTab -Name 'Policies' {
        New-HTMLContent -HeaderText "<center>$headertxt</center>" {
            New-HTMLTable -Title 'Conditional Access Policies' -DataTable $PolicyRows -HideFooter -PagingOptions @(100, 200, 300) {
                TableConditionalFormatting -Name 'PolicyName' -ComparisonType string -Operator ne -Value "bshwjt" -Color Black -BackgroundColor YellowGreen
                TableConditionalFormatting -Name 'State' -ComparisonType string -Operator eq -Value "enabled" -Color White -BackgroundColor Green
                TableConditionalFormatting -Name 'State' -ComparisonType string -Operator eq -Value "enabledForReportingButNotEnforced" -Color Blue -BackgroundColor Orange
                TableConditionalFormatting -Name 'State' -ComparisonType string -Operator eq -Value "disabled" -Color White -BackgroundColor Gray
                TableConditionalFormatting -Name 'Findings' -ComparisonType string -Operator contains -Value "lockout risk" -Color White -BackgroundColor Red
                TableConditionalFormatting -Name 'GrantControls' -ComparisonType string -Operator contains -Value "Block access" -Color White -BackgroundColor Red
            }
        }
    }
    New-HTMLTab -Name 'Baseline' {
        New-HTMLContent -HeaderText "<center>$headertxt</center>" {
            New-HTMLTable -Title 'Conditional Access Baseline' -DataTable $BaselineRows -HideFooter {
                TableConditionalFormatting -Name 'Status' -ComparisonType string -Operator eq -Value "COMPLIANT" -Color NavyBlue -BackgroundColor GreenYellow
                TableConditionalFormatting -Name 'Status' -ComparisonType string -Operator eq -Value "REPORT-ONLY" -Color Black -BackgroundColor Orange
                TableConditionalFormatting -Name 'Status' -ComparisonType string -Operator eq -Value "NOT-COMPLIANT" -Color White -BackgroundColor Red
            }
        }
    }
    if ($NamedLocationRows.Count) {
        New-HTMLTab -Name 'Named Locations' {
            New-HTMLContent -HeaderText "<center>$headertxt</center>" {
                New-HTMLTable -Title 'Named Locations' -DataTable $NamedLocationRows -HideFooter {
                    TableConditionalFormatting -Name 'UsedByPolicies' -ComparisonType string -Operator eq -Value "Not used" -Color Black -BackgroundColor Orange
                }
            }
        }
    }
    if ($AuthStrengthRows.Count) {
        New-HTMLTab -Name 'Auth Strengths' {
            New-HTMLContent -HeaderText "<center>$headertxt</center>" {
                New-HTMLTable -Title 'Authentication Strengths' -DataTable $AuthStrengthRows -HideFooter {
                    TableConditionalFormatting -Name 'UsedByPolicies' -ComparisonType string -Operator eq -Value "Not used" -Color Black -BackgroundColor Orange
                }
            }
        }
    }
    if ($AuthContextRows.Count) {
        New-HTMLTab -Name 'Auth Contexts' {
            New-HTMLContent -HeaderText "<center>$headertxt</center>" {
                New-HTMLTable -Title 'Authentication Contexts' -DataTable $AuthContextRows -HideFooter {
                    TableConditionalFormatting -Name 'UsedByPolicies' -ComparisonType string -Operator eq -Value "Not used" -Color Black -BackgroundColor Orange
                }
            }
        }
    }
    if ($DeletedRows.Count) {
        New-HTMLTab -Name 'Deleted Policies' {
            New-HTMLContent -HeaderText "<center>$headertxt</center>" {
                New-HTMLTable -Title 'Deleted Policies (last 30 days)' -DataTable $DeletedRows -HideFooter
            }
        }
    }
} -FilePath (Join-Path $OutputDir "$HtmFileName.htm")
#endregion

#region Excel Output
$SheetName = if ($HtmFileName.Length -gt 31) { $HtmFileName.Substring(0, 31) } else { $HtmFileName }   # Excel sheet name limit

$ConditionalText = @(
    New-ConditionalText -Text 'enabled'                           -ConditionalType Equal        -ConditionalTextColor Black -BackgroundColor GreenYellow
    New-ConditionalText -Text 'enabledForReportingButNotEnforced' -ConditionalType Equal        -ConditionalTextColor Black -BackgroundColor Orange
    New-ConditionalText -Text 'disabled'                          -ConditionalType Equal        -ConditionalTextColor White -BackgroundColor Gray
    New-ConditionalText -Text 'lockout risk'                      -ConditionalType ContainsText -ConditionalTextColor White -BackgroundColor Red
    New-ConditionalText -Text 'Block access'                      -ConditionalType ContainsText -ConditionalTextColor White -BackgroundColor Red
)
$BaselineConditionalText = @(
    New-ConditionalText -Text 'COMPLIANT'     -ConditionalType Equal -ConditionalTextColor Black -BackgroundColor GreenYellow
    New-ConditionalText -Text 'REPORT-ONLY'   -ConditionalType Equal -ConditionalTextColor Black -BackgroundColor Orange
    New-ConditionalText -Text 'NOT-COMPLIANT' -ConditionalType Equal -ConditionalTextColor White -BackgroundColor Red
)
$UnusedConditionalText = New-ConditionalText -Text 'Not used' -ConditionalType Equal -ConditionalTextColor Black -BackgroundColor Orange

if ($PolicyRows.Count) {
    $PolicyRows | Export-Excel -Path $ExcelOutputPath -WorksheetName $SheetName -ClearSheet -AutoSize -AutoFilter -FreezeTopRow `
        -TableStyle Medium15 -ConditionalText $ConditionalText
}
else {
    Write-Host "No data to export to Excel." -ForegroundColor Yellow
}

$BaselineRows | Export-Excel -Path $ExcelOutputPath -WorksheetName "$($SheetName)_Baseline" -ClearSheet -AutoSize -AutoFilter -FreezeTopRow `
    -TableStyle Medium15 -ConditionalText $BaselineConditionalText

if ($NamedLocationRows.Count) {
    $NamedLocationRows | Export-Excel -Path $ExcelOutputPath -WorksheetName "$($SheetName)_NamedLocations" -ClearSheet -AutoSize -AutoFilter -FreezeTopRow `
        -TableStyle Medium15 -ConditionalText $UnusedConditionalText
}
if ($AuthStrengthRows.Count) {
    $AuthStrengthRows | Export-Excel -Path $ExcelOutputPath -WorksheetName "$($SheetName)_AuthStrengths" -ClearSheet -AutoSize -AutoFilter -FreezeTopRow `
        -TableStyle Medium15 -ConditionalText $UnusedConditionalText
}
if ($AuthContextRows.Count) {
    $AuthContextRows | Export-Excel -Path $ExcelOutputPath -WorksheetName "$($SheetName)_AuthContexts" -ClearSheet -AutoSize -AutoFilter -FreezeTopRow `
        -TableStyle Medium15 -ConditionalText $UnusedConditionalText
}
if ($DeletedRows.Count) {
    $DeletedRows | Export-Excel -Path $ExcelOutputPath -WorksheetName "$($SheetName)_Deleted" -ClearSheet -AutoSize -AutoFilter -FreezeTopRow `
        -TableStyle Medium15
}
#endregion
