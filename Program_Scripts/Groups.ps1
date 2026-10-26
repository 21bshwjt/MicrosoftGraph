# 02. M365 - Entra Group List

#region Authentication & Authorization
. (Join-Path $PSScriptRoot "..\Connect-M365Tenant.ps1")
#endregion

. (Join-Path $PSScriptRoot "..\Icovar.ps1")
. (Join-Path $PSScriptRoot "..\ExcelPathConfig.ps1")
if (-not $Token) {
    Write-Error "Authentication failed: Token is null or empty."
    exit
}
#endregion

#region API Setup
$BaseApi = 'https://graph.microsoft.com'
$ApiVersion = 'v1.0'

# Only request the properties we report on, and expand owners inline so we don't need
# one extra /owners call per group (that was ~250k extra requests on large tenants).
# Note: $expand on directory objects returns at most 20 owners per group.
$SelectProps = @(
    'id', 'displayName', 'groupTypes', 'membershipRule', 'visibility', 'deletedDateTime', 'classification',
    'createdDateTime', 'creationOptions', 'description', 'expirationDateTime', 'isAssignableToRole', 'mail',
    'mailEnabled', 'mailNickname', 'membershipRuleProcessingState', 'onPremisesDomainName',
    'onPremisesLastSyncDateTime', 'onPremisesNetBiosName', 'onPremisesSamAccountName',
    'onPremisesSecurityIdentifier', 'onPremisesSyncEnabled', 'preferredDataLocation', 'preferredLanguage',
    'proxyAddresses', 'renewedDateTime', 'resourceBehaviorOptions', 'resourceProvisioningOptions',
    'securityEnabled', 'securityIdentifier', 'theme', 'uniqueName', 'onPremisesProvisioningErrors',
    'serviceProvisioningErrors'
) -join ','
$Uri = "$BaseApi/$ApiVersion/groups?`$top=999&`$select=$SelectProps&`$expand=owners(`$select=displayName)"

$Headers = @{
    'Authorization' = "Bearer $Token"
    'Content-Type'  = 'application/json'
}
#endregion

#region Graph request with throttling / token refresh handling
function Invoke-GraphGet {
    param ([string]$Uri)

    $MaxRetries = 6
    for ($Attempt = 1; $Attempt -le $MaxRetries; $Attempt++) {
        try {
            return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method 'GET' -ErrorAction Stop
        }
        catch {
            $Status = [int]$_.Exception.Response.StatusCode
            if ($Attempt -eq $MaxRetries) { throw }

            if ($Status -eq 401) {
                # Token expired during a long run - request a new one
                $NewToken = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $tokenParams -ContentType 'application/x-www-form-urlencoded'
                $script:Headers['Authorization'] = "Bearer $($NewToken.access_token)"
                continue
            }
            if ($Status -eq 429 -or $Status -ge 500) {
                $RetryAfter = $_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds
                if (-not $RetryAfter) { $RetryAfter = [math]::Pow(2, $Attempt) }
                Write-Warning "Graph returned $Status, retrying in $RetryAfter s (attempt $Attempt/$MaxRetries)"
                Start-Sleep -Seconds $RetryAfter
                continue
            }
            throw
        }
    }
}
#endregion

#region Get All Groups with Pagination
$AllGroups = [System.Collections.Generic.List[object]]::new()

try {
    do {
        $Response = Invoke-GraphGet -Uri $Uri
        $AllGroups.AddRange([object[]]$Response.value)
        $Uri = $Response.'@odata.nextLink'
        Write-Progress -Activity "Retrieving groups" -Status "$($AllGroups.Count) groups retrieved"
    } while ($Uri)
    Write-Progress -Activity "Retrieving groups" -Completed
}
catch {
    Write-Error "Failed to retrieve groups: $_"
    exit
}
#endregion

#region Format Output with All Properties + Owners
$HTMLResult = foreach ($Group in $AllGroups) {
    $source = if ($Group.onPremisesSyncEnabled -eq $true) { "Synced" } else { "Cloud" }

    # Graph's groupTypes is empty for security groups and distribution lists, so derive a readable type
    $groupType = if ($Group.groupTypes -contains 'Unified') { "Microsoft 365" }
    elseif ($Group.securityEnabled -and $Group.mailEnabled) { "Mail-enabled Security" }
    elseif ($Group.securityEnabled) { "Security" }
    elseif ($Group.mailEnabled) { "Distribution" }
    else { "Unknown" }
    if ($Group.groupTypes -contains 'DynamicMembership') { $groupType += " (Dynamic)" }

    [PSCustomObject]@{
        DisplayName                   = $Group.displayName
        Owners                        = $Group.owners.displayName -join ", "
        GroupTypes                    = $groupType
        Source                        = $source
        MembershipRule                = $Group.membershipRule
        Visibility                    = $Group.visibility # CIS Control
        DeletedDateTime               = $Group.deletedDateTime
        Classification                = $Group.classification
        CreatedDateTime               = $Group.createdDateTime
        CreationOptions               = $Group.creationOptions -join ", "
        Description                   = $Group.description
        ExpirationDateTime            = $Group.expirationDateTime
        IsAssignableToRole            = $Group.isAssignableToRole
        Mail                          = $Group.mail
        MailEnabled                   = $Group.mailEnabled
        MailNickname                  = $Group.mailNickname
        MembershipRuleProcessingState = $Group.membershipRuleProcessingState
        OnPremisesDomainName          = $Group.onPremisesDomainName
        OnPremisesLastSyncDateTime    = $Group.onPremisesLastSyncDateTime
        OnPremisesNetBiosName         = $Group.onPremisesNetBiosName
        OnPremisesSamAccountName      = $Group.onPremisesSamAccountName
        OnPremisesSecurityIdentifier  = $Group.onPremisesSecurityIdentifier
        OnPremisesSyncEnabled         = $Group.onPremisesSyncEnabled
        PreferredDataLocation         = $Group.preferredDataLocation
        PreferredLanguage             = $Group.preferredLanguage
        ProxyAddresses                = $Group.proxyAddresses -join ", "
        RenewedDateTime               = $Group.renewedDateTime
        ResourceBehaviorOptions       = $Group.resourceBehaviorOptions -join ", "
        ResourceProvisioningOptions   = $Group.resourceProvisioningOptions -join ", "
        SecurityEnabled               = $Group.securityEnabled
        SecurityIdentifier            = $Group.securityIdentifier
        Theme                         = $Group.theme
        UniqueName                    = $Group.uniqueName
        OnPremisesProvisioningErrors  = $Group.onPremisesProvisioningErrors -join ", "
        ServiceProvisioningErrors     = $Group.serviceProvisioningErrors -join ", "
        Id                            = $Group.id
    }
}
#endregion


#region Output
# Print to console (optional)
#$HTMLResult | Format-Table -AutoSize


#endregion

#region HTML Output
$Ps1FileName = $($MyInvocation.MyCommand.Name)
$DirName = ($Ps1FileName -split "_")[0]
$HtmFileName = [System.IO.Path]::GetFileNameWithoutExtension($Ps1FileName)

# Ensure the output directory exists
$OutputDir = Join-Path $PSScriptRoot "..\Output\$DirName"
if (!(Test-Path $OutputDir)) {
    [void](New-Item -ItemType Directory -Path $OutputDir -Force)
}

# Extract title from script comments
$FirstLine = Get-Content $MyInvocation.MyCommand.Path | Select-Object -First 1
$Title = $FirstLine -replace '^#\s*\d+\.\s*', ''

# Generate HTML Report
$date = (Get-Date).ToString('MM-dd-yyyy')
$headertxt = "<H2><Center>$Title | $date </Center></H2>"

# -DataStore JavaScript keeps the data as a JS array instead of a 250k-row HTML table,
# which is much faster to generate and to open in the browser.
New-HTML -FavIcon $icon -TitleText $Title {
    New-HTMLContent -HeaderText "<center>$headertxt</center>" {
        New-HTMLTable -Title $Title -DataTable $HTMLResult -HideFooter -DataStore JavaScript -PagingOptions @(500, 1000, 1500) {
            # Conditional Formatting
            TableConditionalFormatting -Name 'DisplayName' -ComparisonType string -Operator ne -Value "bshwjt" -Color NavyBlue -BackgroundColor YellowGreen
            TableConditionalFormatting -Name 'GroupTypes' -ComparisonType string -Operator eq -Value "Microsoft 365" -Color BlackPearl -BackgroundColor Orange
            TableConditionalFormatting -Name 'GroupTypes' -ComparisonType string -Operator contains -Value "Dynamic" -Color White -BackgroundColor GreenLeaf
            TableConditionalFormatting -Name 'IsAssignableToRole' -ComparisonType string -Operator eq -Value "True" -Color white -BackgroundColor Green
            TableConditionalFormatting -Name 'Source' -ComparisonType string -Operator eq -Value "Cloud" -Color white -BackgroundColor DarkViolet
            TableConditionalFormatting -Name 'Source' -ComparisonType string -Operator eq -Value "Synced" -Color BlackPearl -BackgroundColor Orange
            TableConditionalFormatting -Name 'Visibility' -ComparisonType string -Operator eq -Value "Public" -Color White -BackgroundColor Red

        }
    }
} -FilePath (Join-Path $OutputDir "$HtmFileName.htm")

$ConditionalText1 = New-ConditionalText -ConditionalType Equal "Public"
$ConditionalText2 = New-ConditionalText -ConditionalType Equal "Private" Black GreenYellow
$ConditionalText3 = New-ConditionalText -ConditionalType ContainsText "(Dynamic)" Black GreenYellow

# -AutoSize is skipped: it measures every cell and is extremely slow at this row count
$HTMLResult | Export-Excel -Path $ExcelOutputPath -WorksheetName $HtmFileName -TableStyle Medium15 -ConditionalFormat $ConditionalText1, $ConditionalText2, $ConditionalText3

# Export to CSV
$ExportPath = Join-Path $OutputDir "EntraID_Groups.csv"
$HTMLResult | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8

Write-Host "`nGroup export complete: $ExportPath" -ForegroundColor Green
#endregion
