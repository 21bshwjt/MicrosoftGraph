# 38. M365 - Entra Multi Tenant Org. & B2B Partners
#region Authentication & Authorization
. (Join-Path $PSScriptRoot "..\Connect-M365Tenant.ps1")
#endregion
. (Join-Path $PSScriptRoot "..\Icovar.ps1")
. (Join-Path $PSScriptRoot "..\ExcelPathConfig.ps1")

<#
Required Graph permissions (application or delegated):
  Policy.Read.All                     - cross-tenant access policy (default + partners + identity sync)
  CrossTenantInformation.ReadBasic.All - resolve partner tenant names / domains
  MultiTenantOrganization.Read.All    - MTO definition and member tenants
  Directory.Read.All                  - resolve user / group / app names in targets (optional)
#>

#region Generic Variables
$GraphBase = 'https://graph.microsoft.com/v1.0'
$Headers = @{
    'Authorization' = "Bearer $Token"
    'Content-Type'  = 'application/json'
}

# Special target values that are not object IDs
$WellKnownTargets = @('AllUsers', 'AllApplications', 'Office365', 'AllPrincipals')

# Setting blocks present on both default policy and partner configurations
$B2BSections = [ordered]@{
    'B2BCollabInbound'      = 'b2bCollaborationInbound'
    'B2BCollabOutbound'     = 'b2bCollaborationOutbound'
    'DirectConnectInbound'  = 'b2bDirectConnectInbound'
    'DirectConnectOutbound' = 'b2bDirectConnectOutbound'
    'TenantRestrictions'    = 'tenantRestrictions'
}

$NameCache   = @{}
$TargetRows  = [System.Collections.Generic.List[object]]::new()
$IdSyncRows  = [System.Collections.Generic.List[object]]::new()
#endregion

#region Helper Functions
function Invoke-GraphGet {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [switch]$AllPages,
        [switch]$IgnoreNotFound,
        [switch]$Silent
    )
    try {
        if ($AllPages) {
            $items = [System.Collections.Generic.List[object]]::new()
            $next = $Uri
            while ($next) {
                $resp = Invoke-RestMethod -Uri $next -Headers $Headers -Method GET
                if ($resp.value) { $items.AddRange([object[]]$resp.value) }
                $next = $resp.'@odata.nextLink'
            }
            return , $items.ToArray()
        }
        return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method GET
    }
    catch {
        $status = $_.Exception.Response.StatusCode.value__
        if ($IgnoreNotFound -and $status -eq 404) { return $null }
        if (-not $Silent) { Write-Warning "GET $Uri failed ($status): $($_.Exception.Message)" }
        return $null
    }
}

function Resolve-ObjectName {
    # Resolves IDs that live in THIS tenant. Inbound user/group IDs belong to the partner
    # tenant and outbound app IDs to the partner tenant, so those usually stay unresolved.
    param([string]$Id, [string]$Type)

    if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
    if ($Id -in $WellKnownTargets) { return $Id }
    if ($Id -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return $Id }

    $key = "$Type|$Id"
    if ($NameCache.ContainsKey($key)) { return $NameCache[$key] }

    $name = $null
    switch ($Type) {
        'user' {
            $r = Invoke-GraphGet -Uri "$GraphBase/users/$Id`?`$select=displayName,userPrincipalName" -IgnoreNotFound -Silent
            if ($r) { $name = "$($r.displayName) <$($r.userPrincipalName)>" }
        }
        'group' {
            $r = Invoke-GraphGet -Uri "$GraphBase/groups/$Id`?`$select=displayName" -IgnoreNotFound -Silent
            if ($r) { $name = $r.displayName }
        }
        'application' {
            $r = Invoke-GraphGet -Uri "$GraphBase/servicePrincipals?`$filter=appId eq '$Id'&`$select=displayName,appId" -IgnoreNotFound -Silent
            if ($r.value) { $name = $r.value[0].displayName }
        }
    }
    if (-not $name) { $name = '(not resolvable in this tenant)' }
    $NameCache[$key] = $name
    return $name
}

function Get-TenantInfo {
    param([string]$TenantId)
    $r = Invoke-GraphGet -Uri "$GraphBase/tenantRelationships/findTenantInformationByTenantId(tenantId='$TenantId')" -IgnoreNotFound -Silent
    [PSCustomObject]@{
        DisplayName       = $r.displayName
        DefaultDomainName = $r.defaultDomainName
        FederationBrand   = $r.federationBrandName
    }
}

function Format-Targets {
    param($TargetConfig)
    if (-not $TargetConfig -or -not $TargetConfig.targets) { return '' }
    ($TargetConfig.targets | ForEach-Object {
            $n = Resolve-ObjectName -Id $_.target -Type $_.targetType
            if ($n -and $n -ne $_.target) { "$n [$($_.target)]" } else { "$($_.target) ($($_.targetType))" }
        }) -join '; '
}

function Add-SectionColumns {
    # Adds effective Users/Apps columns for one setting block and records each target in $TargetRows.
    param(
        [System.Collections.Specialized.OrderedDictionary]$Row,
        [string]$Prefix,
        [string]$SettingName,
        $PartnerSection,
        $DefaultSection,
        [string]$TenantId,
        [string]$TenantName,
        [bool]$IsDefault
    )

    foreach ($part in 'usersAndGroups', 'applications') {
        $short = if ($part -eq 'usersAndGroups') { 'Users' } else { 'Apps' }

        if ($PartnerSection -and $PartnerSection.$part) {
            $src = if ($IsDefault) { 'Default' } else { 'Partner (custom)' }
            $val = $PartnerSection.$part
        }
        elseif ($DefaultSection -and $DefaultSection.$part) {
            $src = 'Inherited (Default)'
            $val = $DefaultSection.$part
        }
        else {
            $src = 'Not configured'
            $val = $null
        }

        $Row["${Prefix}_${short}_Source"]  = $src
        $Row["${Prefix}_${short}_Access"]  = $val.accessType
        $Row["${Prefix}_${short}_Targets"] = Format-Targets $val

        foreach ($t in $val.targets) {
            $TargetRows.Add([PSCustomObject]@{
                    Partner_TenantId = $TenantId
                    Partner_Name     = $TenantName
                    Setting          = $SettingName
                    Scope            = $short
                    Source           = $src
                    AccessType       = $val.accessType
                    Target           = $t.target
                    TargetType       = $t.targetType
                    ResolvedName     = Resolve-ObjectName -Id $t.target -Type $t.targetType
                })
        }
    }
}

function ConvertTo-PolicyRow {
    param($Policy, $Default, [bool]$IsDefault)

    if ($IsDefault) {
        $tenantId = 'DEFAULT POLICY'
        $info = [PSCustomObject]@{ DisplayName = '(applies to all tenants without a partner config)'; DefaultDomainName = $null; FederationBrand = $null }
    }
    else {
        $tenantId = $Policy.tenantId
        $info = Get-TenantInfo -TenantId $tenantId
    }

    $row = [ordered]@{
        Partner_TenantId            = $tenantId
        Partner_DisplayName         = $info.DisplayName
        Partner_DefaultDomain       = $info.DefaultDomainName
        Partner_FederationBrand     = $info.FederationBrand
        IsServiceProvider           = $Policy.isServiceProvider
        IsInMultiTenantOrganization = $Policy.isInMultiTenantOrganization
        IsServiceDefault            = $Policy.isServiceDefault
    }

    # Automatic user consent (partner-only meaningful; default is always false)
    $row['Consent_InboundAllowed']  = $Policy.automaticUserConsentSettings.inboundAllowed
    $row['Consent_OutboundAllowed'] = $Policy.automaticUserConsentSettings.outboundAllowed

    # Inbound trust (effective)
    $trust = if ($Policy.inboundTrust) { $Policy.inboundTrust } else { $Default.inboundTrust }
    $row['Trust_Source']             = if ($IsDefault) { 'Default' } elseif ($Policy.inboundTrust) { 'Partner (custom)' } else { 'Inherited (Default)' }
    $row['Trust_MFA']                = $trust.isMfaAccepted
    $row['Trust_CompliantDevice']    = $trust.isCompliantDeviceAccepted
    $row['Trust_HybridJoinedDevice'] = $trust.isHybridAzureADJoinedDeviceAccepted

    # B2B collaboration, direct connect, tenant restrictions
    foreach ($prefix in $B2BSections.Keys) {
        $prop = $B2BSections[$prefix]
        Add-SectionColumns -Row $row -Prefix $prefix -SettingName $prop `
            -PartnerSection $Policy.$prop -DefaultSection $Default.$prop `
            -TenantId $tenantId -TenantName $info.DisplayName -IsDefault $IsDefault
    }

    # Tenant restrictions device filter
    $tr = if ($Policy.tenantRestrictions) { $Policy.tenantRestrictions } else { $Default.tenantRestrictions }
    $row['TenantRestrictions_Devices_Mode'] = $tr.devices.mode
    $row['TenantRestrictions_Devices_Rule'] = $tr.devices.rule

    # Default-only: invitation redemption IdP order
    if ($IsDefault) {
        $idp = $Policy.invitationRedemptionIdentityProviderConfiguration
        $row['Redemption_PrimaryIdPs']  = ($idp.primaryIdentityProviderPrecedenceOrder -join ', ')
        $row['Redemption_FallbackIdP']  = $idp.fallbackIdentityProvider
    }

    # Identity synchronization (cross-tenant sync), partner only
    if (-not $IsDefault) {
        $sync = Invoke-GraphGet -Uri "$GraphBase/policies/crossTenantAccessPolicy/partners/$tenantId/identitySynchronization" -IgnoreNotFound -Silent
        $row['IdSync_Configured']    = [bool]$sync
        $row['IdSync_DisplayName']   = $sync.displayName
        $row['IdSync_InboundAllowed'] = $sync.userSyncInbound.isSyncAllowed
        if ($sync) {
            $IdSyncRows.Add([PSCustomObject]@{
                    Partner_TenantId   = $tenantId
                    Partner_Name       = $info.DisplayName
                    PolicyDisplayName  = $sync.displayName
                    UserSyncInbound    = $sync.userSyncInbound.isSyncAllowed
                })
        }
    }

    # Full raw object for anything not flattened (Excel cell limit = 32767 chars)
    $json = $Policy | ConvertTo-Json -Depth 15 -Compress
    if ($json.Length -gt 32000) { $json = $json.Substring(0, 32000) + '...[truncated]' }
    $row['RawJson'] = $json

    [PSCustomObject]$row
}
#endregion

#region Collect Data
Write-Host "Retrieving default cross-tenant access policy..." -ForegroundColor Cyan
$DefaultPolicy = Invoke-GraphGet -Uri "$GraphBase/policies/crossTenantAccessPolicy/default"
if (-not $DefaultPolicy) {
    Write-Error "Failed to retrieve the default cross-tenant access policy. Check Policy.Read.All permission."
    return
}

Write-Host "Retrieving partner configurations..." -ForegroundColor Cyan
$Partners = Invoke-GraphGet -Uri "$GraphBase/policies/crossTenantAccessPolicy/partners" -AllPages
if ($null -eq $Partners) {
    Write-Error "Failed to retrieve B2B partner data."
    return
}
Write-Host "Found $($Partners.Count) partner configuration(s)." -ForegroundColor Cyan

$PartnerSummary = [System.Collections.Generic.List[object]]::new()
$PartnerSummary.Add((ConvertTo-PolicyRow -Policy $DefaultPolicy -Default $DefaultPolicy -IsDefault $true))

$i = 0
foreach ($partner in $Partners) {
    $i++
    Write-Progress -Activity 'Processing partners' -Status $partner.tenantId -PercentComplete (($i / [math]::Max($Partners.Count, 1)) * 100)
    $PartnerSummary.Add((ConvertTo-PolicyRow -Policy $partner -Default $DefaultPolicy -IsDefault $false))
}
Write-Progress -Activity 'Processing partners' -Completed

Write-Host "Retrieving Multi-Tenant Organization..." -ForegroundColor Cyan
$Mto = Invoke-GraphGet -Uri "$GraphBase/tenantRelationships/multiTenantOrganization" -IgnoreNotFound -Silent
$MtoRows = @()
$MtoTenantRows = @()
if ($Mto -and $Mto.state) {
    $MtoRows = @([PSCustomObject]@{
            MTO_Id          = $Mto.id
            DisplayName     = $Mto.displayName
            Description     = $Mto.description
            State           = $Mto.state
            CreatedDateTime = $Mto.createdDateTime
        })

    $MtoTenants = Invoke-GraphGet -Uri "$GraphBase/tenantRelationships/multiTenantOrganization/tenants" -AllPages
    $PartnerIds = @($Partners.tenantId)
    $MtoTenantRows = foreach ($t in $MtoTenants) {
        [PSCustomObject]@{
            TenantId                 = $t.tenantId
            DisplayName              = $t.displayName
            Role                     = $t.role
            State                    = $t.state
            AddedDateTime            = $t.addedDateTime
            JoinedDateTime           = $t.joinedDateTime
            AddedByTenantId          = $t.addedByTenantId
            Transition_DesiredState  = $t.transitionDetails.desiredState
            Transition_DesiredRole   = $t.transitionDetails.desiredRole
            Transition_Status        = $t.transitionDetails.status
            Transition_Details       = $t.transitionDetails.details
            HasPartnerConfig         = ($t.tenantId -in $PartnerIds)
        }
    }
}
else {
    Write-Host "No Multi-Tenant Organization configured (or no permission)." -ForegroundColor Yellow
}
#endregion

#region HTML & Excel Output
$Ps1FileName = $($MyInvocation.MyCommand.Name)
$DirName = ($Ps1FileName -split "_")[0]
$HtmFileName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)

$OutputDir = Join-Path $PSScriptRoot "..\Output\$DirName"
if (!(Test-Path $OutputDir)) {
    [void](New-Item -ItemType Directory -Path $OutputDir -Force)
}

$FirstLine = Get-Content $MyInvocation.MyCommand.Path | Select-Object -First 1
$Title = $FirstLine -replace '^#\s*\d+\.\s*', ''
$date = (Get-Date).ToString('MM-dd-yyyy')
$headertxt = "<H2><Center>$Title | $date </Center></H2>"

$HtmlSummary   = $PartnerSummary | Select-Object * -ExcludeProperty RawJson
$AccessColumns = $HtmlSummary[0].PSObject.Properties.Name | Where-Object { $_ -like '*_Access' }
$SourceColumns = $HtmlSummary[0].PSObject.Properties.Name | Where-Object { $_ -like '*_Source' }

New-HTML -FavIcon $icon -TitleText $Title {
    New-HTMLContent -HeaderText "<center>$headertxt</center>" {
        New-HTMLTab -Name 'Partner Summary' {
            New-HTMLTable -Title 'Effective settings per partner' -DataTable $HtmlSummary -HideFooter -ScrollX -PagingOptions @(100, 200, 300) {
                foreach ($c in $AccessColumns) {
                    TableConditionalFormatting -Name $c -ComparisonType string -Operator eq -Value 'blocked' -Color White -BackgroundColor IndianRed
                    TableConditionalFormatting -Name $c -ComparisonType string -Operator eq -Value 'allowed' -Color White -BackgroundColor SeaGreen
                }
                foreach ($c in $SourceColumns) {
                    TableConditionalFormatting -Name $c -ComparisonType string -Operator eq -Value 'Partner (custom)' -BackgroundColor LightSkyBlue
                }
                foreach ($c in 'Consent_InboundAllowed', 'Consent_OutboundAllowed', 'Trust_MFA', 'Trust_CompliantDevice', 'Trust_HybridJoinedDevice', 'IdSync_InboundAllowed') {
                    TableConditionalFormatting -Name $c -ComparisonType string -Operator eq -Value 'True' -BackgroundColor Khaki
                }
            }
        }
        New-HTMLTab -Name 'Targets (detail)' {
            New-HTMLTable -Title 'One row per user / group / app target' -DataTable $TargetRows -HideFooter -PagingOptions @(100, 200, 300) {
                TableConditionalFormatting -Name 'AccessType' -ComparisonType string -Operator eq -Value 'blocked' -Color White -BackgroundColor IndianRed
                TableConditionalFormatting -Name 'AccessType' -ComparisonType string -Operator eq -Value 'allowed' -Color White -BackgroundColor SeaGreen
            }
        }
        New-HTMLTab -Name 'Cross-Tenant Sync' {
            New-HTMLTable -Title 'Identity synchronization policies' -DataTable $IdSyncRows -HideFooter
        }
        New-HTMLTab -Name 'Multi-Tenant Org' {
            New-HTMLTable -Title 'MTO definition' -DataTable $MtoRows -HideFooter
            New-HTMLTable -Title 'MTO member tenants' -DataTable $MtoTenantRows -HideFooter {
                TableConditionalFormatting -Name 'HasPartnerConfig' -ComparisonType string -Operator eq -Value 'False' -BackgroundColor Khaki
            }
        }
    }
} -FilePath "$OutputDir\$HtmFileName.htm"

# Export to Excel (one worksheet per dataset; names kept under 31 chars)
$ExcelCommon = @{ Path = $ExcelOutputPath; AutoSize = $true; TableStyle = 'Medium21'; FreezeTopRow = $true; ClearSheet = $true }

if ($PartnerSummary.Count) { $PartnerSummary | Export-Excel @ExcelCommon -WorksheetName $HtmFileName }
if ($TargetRows.Count)     { $TargetRows     | Export-Excel @ExcelCommon -WorksheetName "$DirName-Targets" }
if ($IdSyncRows.Count)     { $IdSyncRows     | Export-Excel @ExcelCommon -WorksheetName "$DirName-CrossTenantSync" }
if ($MtoRows)              { $MtoRows        | Export-Excel @ExcelCommon -WorksheetName "$DirName-MTO" }
if ($MtoTenantRows)        { $MtoTenantRows  | Export-Excel @ExcelCommon -WorksheetName "$DirName-MTOTenants" }

Write-Host "Report written to $OutputDir\$HtmFileName.htm and $ExcelOutputPath" -ForegroundColor Green
#endregion

