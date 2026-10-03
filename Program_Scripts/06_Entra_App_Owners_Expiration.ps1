# 06. M365 - Entra Application Registration Owners & Expiration

#region Authentication & Authorization
. (Join-Path $PSScriptRoot "..\Connect-M365Tenant.ps1")
#endregion
. (Join-Path $PSScriptRoot "..\Icovar.ps1")
. (Join-Path $PSScriptRoot "..\ExcelPathConfig.ps1")

#region Configuration (edit here - no script parameters)
$ExpiryWarningDays = 30     # Flag credentials expiring within this many days
$MaxSecretLifetimeDays = 365    # Active client secrets valid longer than this are flagged in Findings
$BatchSize = 20     # Microsoft Graph $batch hard limit
$MaxConcurrency = 4      # Parallel $batch calls in flight (keep 2-5 to avoid throttling)
$MaxRetries = 5      # Retries for throttling (429) / transient (5xx) errors
$ProgressInterval = 50     # Update progress bar every N apps (Write-Progress is slow)
#endregion

#region Generic Variables
if (-not $Token) { throw 'No access token found in $Token. Check Connect-M365Tenant.ps1.' }

$BaseApi = 'https://graph.microsoft.com'
$ApiVersion = 'v1.0'
$BatchUri = "$BaseApi/$ApiVersion/`$batch"
$Now = Get-Date

$Headers = @{ 'Authorization' = "Bearer $Token" }

# Credentials are returned inline on the application/servicePrincipal objects - no extra calls needed
$AppSelect = 'id,appId,displayName,signInAudience,createdDateTime,isDisabled,passwordCredentials,keyCredentials'
$SpSelect = 'appId,accountEnabled,preferredSingleSignOnMode,passwordCredentials,keyCredentials'
$OwnerSelect = 'id,displayName,userPrincipalName,userType,accountEnabled'
#endregion

#region Helper Functions
function Invoke-GraphRequest {
    # Graph call with retry on throttling (429) and transient server errors (5xx)
    param([string]$Uri, [string]$Method = 'GET', [object]$Body)

    $Attempt = 0
    while ($true) {
        try {
            $Splat = @{ Uri = $Uri; Headers = $Headers; Method = $Method; ErrorAction = 'Stop' }
            if ($Body) {
                $Splat.Body = $Body | ConvertTo-Json -Depth 10 -Compress
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

function Get-GraphAll {
    # Follows @odata.nextLink until all pages are retrieved
    param([string]$Uri)

    $Items = [System.Collections.Generic.List[object]]::new()
    while ($Uri) {
        $Response = Invoke-GraphRequest -Uri $Uri
        if ($Response.value) { $Items.AddRange([object[]]$Response.value) }
        $Uri = $Response.'@odata.nextLink'
    }
    , $Items
}

# Runs inside a runspace: posts one $batch payload with its own retry loop
$BatchWorker = {
    param($Uri, $Headers, $Json, $MaxRetries)

    $Attempt = 0
    while ($true) {
        try {
            return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method POST -Body $Json -ContentType 'application/json' -ErrorAction Stop
        }
        catch {
            $Response = $_.Exception.Response
            $StatusCode = if ($Response) { [int]$Response.StatusCode } else { 0 }
            if (($StatusCode -eq 429 -or $StatusCode -ge 500) -and $Attempt -lt $MaxRetries) {
                $Attempt++
                Start-Sleep -Seconds ([math]::Min(60, [math]::Pow(2, $Attempt) * 2))
                continue
            }
            return [PSCustomObject]@{ error = "HTTP $StatusCode - $($_.Exception.Message)" }
        }
    }
}

function Invoke-GraphBatch {
    # Sends $batch calls (20 requests each) in parallel via a runspace pool (works on PS 5.1 and 7)
    # and re-queues throttled sub-requests
    param([object[]]$Requests, [string]$Activity = 'Running Graph batch')

    $Results = @{}
    $Retries = @{}
    $ById = @{}
    $Queue = [System.Collections.Generic.Queue[object]]::new()
    foreach ($Request in $Requests) { $ById[$Request.id] = $Request; $Queue.Enqueue($Request) }
    $Total = $Queue.Count
    if ($Total -eq 0) { return $Results }

    $Pool = [runspacefactory]::CreateRunspacePool(1, $MaxConcurrency)
    $Pool.Open()
    try {
        while ($Queue.Count -gt 0) {
            # Launch up to $MaxConcurrency batch calls at once
            $Jobs = [System.Collections.Generic.List[object]]::new()
            for ($n = 0; $n -lt $MaxConcurrency -and $Queue.Count -gt 0; $n++) {
                $Chunk = [System.Collections.Generic.List[object]]::new()
                while ($Chunk.Count -lt $BatchSize -and $Queue.Count -gt 0) { $Chunk.Add($Queue.Dequeue()) }

                $Json = @{ requests = $Chunk.ToArray() } | ConvertTo-Json -Depth 10 -Compress
                $Ps = [powershell]::Create().AddScript($BatchWorker).
                AddArgument($BatchUri).AddArgument($Headers).AddArgument($Json).AddArgument($MaxRetries)
                $Ps.RunspacePool = $Pool
                $Jobs.Add([PSCustomObject]@{ Ps = $Ps; Handle = $Ps.BeginInvoke(); Chunk = $Chunk })
            }

            # Collect results
            $Wait = 0
            foreach ($Job in $Jobs) {
                $Output = $Job.Ps.EndInvoke($Job.Handle)
                $Job.Ps.Dispose()
                $Response = if ($Output.Count) { $Output[$Output.Count - 1] } else { $null }

                if (-not $Response -or $Response.error) {
                    $Msg = if ($Response.error) { $Response.error } else { 'No response' }
                    foreach ($Req in $Job.Chunk) { $Results[$Req.id] = [PSCustomObject]@{ id = $Req.id; status = 0; error = $Msg } }
                    continue
                }

                foreach ($Item in $Response.responses) {
                    $Status = [int]$Item.status
                    if (($Status -eq 429 -or $Status -ge 500) -and $Retries[$Item.id] -lt $MaxRetries) {
                        $Retries[$Item.id]++
                        $Queue.Enqueue($ById[$Item.id])
                        $RetryAfter = [int]($Item.headers.'Retry-After')
                        $Wait = [math]::Max($Wait, [math]::Max($RetryAfter, 5))
                    }
                    else {
                        $Results[$Item.id] = $Item
                    }
                }
            }

            $Done = $Results.Count
            Write-Progress -Activity $Activity -Status "$Done of $Total" -PercentComplete (($Done / $Total) * 100)
            if ($Wait) { Start-Sleep -Seconds $Wait }
        }
    }
    finally {
        $Pool.Close()
        $Pool.Dispose()
        Write-Progress -Activity $Activity -Completed
    }
    $Results
}

function Get-CredentialSummary {
    # Per-credential lists (aligned, ' | ' separated): active soonest-first, then expired.
    # Also returns single values (soonest days left, longest active lifetime) used for Findings.
    param([object[]]$Credentials)

    $Items = [System.Collections.Generic.List[object]]::new()
    foreach ($C in $Credentials) {
        if (-not $C -or -not $C.endDateTime) { continue }
        $End = [datetime]$C.endDateTime
        $Start = if ($C.startDateTime) { [datetime]$C.startDateTime } else { $null }
        $Items.Add([PSCustomObject]@{
                End      = $End
                IsActive = $End -gt $Now
                Lifetime = if ($Start) { [int]($End - $Start).TotalDays } else { $null }
            })
    }

    $Sorted = @($Items | Sort-Object @{ Expression = 'IsActive'; Descending = $true }, @{ Expression = 'End'; Ascending = $true })
    $Active = @($Sorted.Where({ $_.IsActive }))
    $Next = if ($Active.Count) { $Active[0].End } else { $null }
    $MaxLife = ($Active.Where({ $null -ne $_.Lifetime }) | Measure-Object -Property Lifetime -Maximum).Maximum

    $Dates = [System.Collections.Generic.List[string]]::new()
    $Days = [System.Collections.Generic.List[string]]::new()
    $Lives = [System.Collections.Generic.List[string]]::new()
    foreach ($I in $Sorted) {
        if ($I.IsActive) {
            $Dates.Add($I.End.ToString('yyyy-MM-dd'))
            $Days.Add([string][int][math]::Floor(($I.End - $Now).TotalDays))
        }
        else {
            $Dates.Add("$($I.End.ToString('yyyy-MM-dd')) (Expired)")
            $Days.Add('Expired')
        }
        $Lives.Add($(if ($null -ne $I.Lifetime) { [string]$I.Lifetime } else { 'N/A' }))
    }

    [PSCustomObject]@{
        Active          = $Active.Count
        Expired         = $Sorted.Count - $Active.Count
        AllExpiry       = if ($Dates.Count) { $Dates -join ' | ' } else { 'N/A' }
        AllDaysLeft     = if ($Days.Count) { $Days -join ' | ' } else { 'N/A' }
        AllLifetime     = if ($Lives.Count) { $Lives -join ' | ' } else { 'N/A' }
        DaysLeft        = if ($Next) { [int][math]::Floor(($Next - $Now).TotalDays) } else { 'N/A' }
        MaxLifetimeDays = if ($MaxLife) { [int]$MaxLife } else { 'N/A' }
    }
}
#endregion

#region Fetch Applications (owners expanded inline where supported)
Write-Host 'Fetching application registrations...' -ForegroundColor Cyan
$OwnerMap = @{}   # objectId -> owners array (only for apps where $expand returned owners)

try {
    # One call returns apps + owners: removes one batched request per app.
    # $expand returns max 20 owners per app - enough for the "has owners" compliance rule.
    $Applications = Get-GraphAll -Uri "$BaseApi/$ApiVersion/applications?`$select=$AppSelect&`$expand=owners(`$select=$OwnerSelect)&`$top=999"
}
catch {
    Write-Warning "Owner `$expand failed ($($_.Exception.Message)). Falling back to batched owner lookups."
    $Applications = Get-GraphAll -Uri "$BaseApi/$ApiVersion/applications?`$select=$AppSelect&`$top=999"
}

if ($Applications.Count -eq 0) {
    Write-Warning 'No applications returned. Check the token permissions (Application.Read.All).'
    return
}
Write-Host "Found $($Applications.Count) application registrations." -ForegroundColor Green

foreach ($App in $Applications) {
    if ($App.PSObject.Properties['owners']) {
        $OwnerMap[$App.id] = @(@($App.owners).Where({ $null -ne $_ }))
    }
}
#endregion

#region Retrieve Service Principals, Federated Credentials (+ owners where not expanded) - parallel batches
$Requests = [System.Collections.Generic.List[object]]::new()
foreach ($App in $Applications) {
    if (-not $OwnerMap.ContainsKey($App.id)) {
        $Requests.Add(@{ id = "owners-$($App.id)"; method = 'GET'; url = "/applications/$($App.id)/owners?`$select=$OwnerSelect" })
    }
    $Requests.Add(@{ id = "fic-$($App.id)"; method = 'GET'; url = "/applications/$($App.id)/federatedIdentityCredentials?`$select=name" })
}
# Service principals: look up only the SPs for these apps, 15 appIds per request ($filter 'in' limit)
$SpChunks = @{}
$AppIds = @($Applications | ForEach-Object { $_.appId })
for ($i = 0; $i -lt $AppIds.Count; $i += 15) {
    $Chunk = $AppIds[$i..([math]::Min($i + 14, $AppIds.Count - 1))]
    $Filter = [uri]::EscapeDataString("appId in ('" + ($Chunk -join "','") + "')")
    $Id = "sp-$i"
    $SpChunks[$Id] = $Chunk
    $Requests.Add(@{ id = $Id; method = 'GET'; url = "/servicePrincipals?`$filter=$Filter&`$select=$SpSelect" })
}

$BatchResults = Invoke-GraphBatch -Requests $Requests.ToArray() -Activity 'Retrieving service principals, federated credentials & owners'

$SpByAppId = @{}
$SpLookupFailed = @{}
foreach ($Id in $SpChunks.Keys) {
    $Resp = $BatchResults[$Id]
    if ($Resp -and [int]$Resp.status -eq 200) {
        foreach ($Sp in $Resp.body.value) { $SpByAppId[$Sp.appId] = $Sp }
    }
    else {
        foreach ($AppId in $SpChunks[$Id]) { $SpLookupFailed[$AppId] = $true }
        Write-Warning "Service principal lookup failed for $($SpChunks[$Id].Count) app(s) (HTTP $($Resp.status))."
    }
}
#endregion

#region Analyse Each Application
$HTMLResult = [System.Collections.Generic.List[PSObject]]::new($Applications.Count)
$AppTotal = $Applications.Count
$Counter = 0

foreach ($App in $Applications) {
    $Counter++
    if ($Counter % $ProgressInterval -eq 0 -or $Counter -eq $AppTotal) {
        Write-Progress -Activity 'Analysing applications' -Status "$Counter of $AppTotal" -PercentComplete (($Counter / $AppTotal) * 100)
    }

    $Critical = [System.Collections.Generic.List[string]]::new()   # High-risk findings (informational)
    $Review = [System.Collections.Generic.List[string]]::new()   # Hygiene findings (informational)

    # Tenant type
    $TenantType = switch ($App.signInAudience) {
        'AzureADMyOrg' { 'Single Tenant' }
        'AzureADMultipleOrgs' { 'Multi-Tenant' }
        'AzureADandPersonalMicrosoftAccount' { 'Multi-Tenant (+ Personal)' }
        'PersonalMicrosoftAccount' { 'Personal Account Only' }
        default { 'Unknown' }
    }
    if ($App.signInAudience -ne 'AzureADMyOrg') { $Review.Add('Multi-tenant / personal accounts allowed') }

    # State
    #   Disabled         = app registration deactivated (application.isDisabled = true) - same as original script
    #   Sign-in disabled = app active, but its enterprise app / SP has "Enabled for users to sign in" = No
    $Sp = $SpByAppId[$App.appId]
    $State = if ($App.isDisabled -eq $true) { 'Disabled' }
    elseif ($SpLookupFailed[$App.appId]) { 'Enabled (SP lookup failed)' }
    elseif (-not $Sp) { 'Enabled (No Service Principal)' }
    elseif ($Sp.accountEnabled -eq $false) { 'Sign-in disabled' }
    else { 'Enabled' }

    # Owners: from $expand, otherwise from the batch
    $OwnerList = $null
    $OwnerErr = $null
    if ($OwnerMap.ContainsKey($App.id)) {
        $OwnerList = $OwnerMap[$App.id]
    }
    else {
        $OwnerResp = $BatchResults["owners-$($App.id)"]
        if ($OwnerResp -and [int]$OwnerResp.status -eq 200) { $OwnerList = @(@($OwnerResp.body.value).Where({ $null -ne $_ })) }
        else { $OwnerErr = $OwnerResp.status }
    }

    $OwnerLookupFailed = $null -eq $OwnerList
    if ($OwnerLookupFailed) {
        $OwnerCount = 'N/A'
        $Owners = 'Lookup failed'
        $OwnerUPN = 'N/A'
        $Review.Add("Owner lookup failed (HTTP $OwnerErr)")
    }
    elseif ($OwnerList.Count -eq 0) {
        $OwnerCount = 0
        $Owners = 'No owners found'
        $OwnerUPN = 'N/A'
        $Critical.Add('No owners')
    }
    else {
        $OwnerCount = $OwnerList.Count
        $Names = [System.Collections.Generic.List[string]]::new()
        $Upns = [System.Collections.Generic.List[string]]::new()
        $GuestCount = 0; $DisabledCount = 0

        foreach ($O in $OwnerList) {
            if ($O.'@odata.type' -eq '#microsoft.graph.servicePrincipal') { $Names.Add("$($O.displayName) (SP)") } else { $Names.Add($O.displayName) }
            if ($O.userPrincipalName) { $Upns.Add($O.userPrincipalName) }
            if ($O.userType -eq 'Guest' -or $O.userPrincipalName -like '*#EXT#*') { $GuestCount++ }
            if ($O.accountEnabled -eq $false) { $DisabledCount++ }
        }

        $Owners = $Names -join ' | '
        $OwnerUPN = if ($Upns.Count) { $Upns -join ' | ' } else { 'N/A' }

        if ($GuestCount) { $Review.Add("Guest owner(s): $GuestCount") }
        if ($DisabledCount -eq $OwnerCount) { $Critical.Add('All owners disabled') }
        elseif ($DisabledCount) { $Review.Add("Disabled owner(s): $DisabledCount") }
    }

    # Federated identity credentials
    $FicResp = $BatchResults["fic-$($App.id)"]
    $FicLookupFailed = -not ($FicResp -and [int]$FicResp.status -eq 200)
    if (-not $FicLookupFailed) {
        $FicList = @(@($FicResp.body.value).Where({ $null -ne $_ }))
        $FederatedCreds = if ($FicList.Count) { ($FicList.name) -join ' | ' } else { 'N/A' }
    }
    else {
        $FicList = @()
        $FederatedCreds = 'Lookup failed'
        $Review.Add("Federated credential lookup failed (HTTP $($FicResp.status))")
    }

    # Secrets & certificates (from the application object itself)
    $Sec = Get-CredentialSummary -Credentials $App.passwordCredentials
    $Cert = Get-CredentialSummary -Credentials $App.keyCredentials

    if ($Sec.Active -gt 0) {
        if ($Sec.MaxLifetimeDays -ne 'N/A' -and $Sec.MaxLifetimeDays -gt $MaxSecretLifetimeDays) {
            $Critical.Add("Secret lifetime > $MaxSecretLifetimeDays days")
        }
        else {
            $Review.Add('Client secret in use (prefer certificate / federated)')
        }
    }
    if (($Sec.Expired + $Cert.Expired) -gt 0) { $Review.Add('Expired credentials not removed') }

    if ($Sec.DaysLeft -ne 'N/A' -and $Sec.DaysLeft -le $ExpiryWarningDays) {
        $Review.Add("Secret expiring within $ExpiryWarningDays days")
    }
    if ($Cert.DaysLeft -ne 'N/A' -and $Cert.DaysLeft -le $ExpiryWarningDays) {
        $Review.Add("App certificate expiring within $ExpiryWarningDays days")
    }

    if (($Sec.Active + $Cert.Active + $FicList.Count) -eq 0) { $Review.Add('No active credentials (verify app is still used)') }

    # Credentials on the service principal are hidden from the App registrations blade.
    # SAML apps store their token-signing certificate on the SP as keyCredentials (Sign + Verify)
    # plus a passwordCredential (the private-key password). These are NOT client secrets, so they
    # are reported separately as the SAML signing certificate and excluded from SPCredentials.
    $SpCredCount = 0
    $SamlCert = $null
    if ($Sp) {
        $SpKeys = @(@($Sp.keyCredentials).Where({ $null -ne $_ }))
        $SpPwds = @(@($Sp.passwordCredentials).Where({ $null -ne $_ }))

        if ($Sp.preferredSingleSignOnMode -eq 'saml') {
            $SigningKeys = @($SpKeys.Where({ $_.usage -in 'Sign', 'Verify' }))
            $SigningIds = @($SigningKeys.ForEach({ $_.customKeyIdentifier }))
            $SigningNames = @($SigningKeys.ForEach({ $_.displayName }))

            # One 'Verify' entry per physical certificate
            $SamlCert = Get-CredentialSummary -Credentials $SigningKeys.Where({ $_.usage -eq 'Verify' })

            $SpKeys = @($SpKeys.Where({ $_.usage -notin 'Sign', 'Verify' }))
            $SpPwds = @($SpPwds.Where({ $_.customKeyIdentifier -notin $SigningIds -and $_.displayName -notin $SigningNames }))

            if ($SamlCert.Active -eq 0 -and $SamlCert.Expired -gt 0) { $Critical.Add('SAML signing certificate expired') }
            elseif ($SamlCert.DaysLeft -ne 'N/A' -and $SamlCert.DaysLeft -le $ExpiryWarningDays) {
                $Review.Add("SAML signing certificate expiring within $ExpiryWarningDays days")
            }
        }

        $SpCredCount = $SpKeys.Count + $SpPwds.Count
        if ($SpCredCount -gt 0) { $Critical.Add('Credentials on service principal') }
    }

    # Overall status
    # Rule: Non-Compliant = app has a secret and/or certificate and/or federated credential, but NO owners.
    # Other findings are informational only (Findings column) and do not affect Status.
    $CredentialCount = ($Sec.Active + $Sec.Expired) + ($Cert.Active + $Cert.Expired) + $FicList.Count
    $HasCredentials = $CredentialCount -gt 0

    $Status = if ($State -in 'Disabled', 'Sign-in disabled') { 'Disabled' }
    elseif ($OwnerLookupFailed) { 'Unknown' }   # can't confirm owners
    elseif ($HasCredentials -and $OwnerCount -eq 0) { 'Non-Compliant' }
    elseif (-not $HasCredentials -and $FicLookupFailed -and $OwnerCount -eq 0) { 'Unknown' }   # can't confirm credentials
    else { 'Compliant' }

    $Findings = (@($Critical) + @($Review)) -join '; '

    $HTMLResult.Add([PSCustomObject][ordered]@{
            ApplicationName    = $App.displayName
            AppID              = $App.appId
            ObjectID           = $App.id
            TenantType         = $TenantType
            State              = $State
            Created            = if ($App.createdDateTime) { ([datetime]$App.createdDateTime).ToString('yyyy-MM-dd') } else { 'N/A' }
            OwnerCount         = $OwnerCount
            Owners             = $Owners
            OwnerUPN           = $OwnerUPN
            ActiveSecrets      = $Sec.Active
            SecretExpiryDate   = $Sec.AllExpiry
            SecretDaysLeft     = $Sec.AllDaysLeft
            SecretLifetimeDays = $Sec.AllLifetime
            ActiveCerts        = $Cert.Active
            CertExpiryDate     = $Cert.AllExpiry
            CertDaysLeft       = $Cert.AllDaysLeft
            ExpiredCredentials = $Sec.Expired + $Cert.Expired
            FederatedCredCount = if ($FicLookupFailed) { 'N/A' } else { $FicList.Count }
            FederatedCreds     = $FederatedCreds
            SPCredentials      = $SpCredCount
            SAMLCertExpiryDate = if ($SamlCert) { $SamlCert.AllExpiry } else { 'N/A' }
            SAMLCertDaysLeft   = if ($SamlCert) { $SamlCert.AllDaysLeft } else { 'N/A' }
            Status             = $Status
            Findings           = if ($Findings) { $Findings } else { 'None' }
        })
}
Write-Progress -Activity 'Analysing applications' -Completed

Write-Host "`nSummary" -ForegroundColor Cyan
$HTMLResult | Group-Object Status | Sort-Object Name | ForEach-Object { Write-Host ('{0,-15} {1}' -f $_.Name, $_.Count) }
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
$TableTitle = $Title

New-HTML -FavIcon $icon -TitleText $Title {
    New-HTMLContent -HeaderText "<center>$headertxt</center>" {
        New-HTMLTable -Title $TableTitle -DataTable $HTMLResult -HideFooter -PagingOptions @(100, 200, 300) {
            TableConditionalFormatting -Name 'ApplicationName' -ComparisonType string -Operator ne -Value "bshwjt" -Color White -BackgroundColor BlueDiamond
            TableConditionalFormatting -Name 'AppID' -ComparisonType string -Operator ne -Value "bshwjt" -Color Black -BackgroundColor Akaroa

            TableConditionalFormatting -Name 'TenantType' -ComparisonType string -Operator eq -Value "Single Tenant" -Color NavyBlue -BackgroundColor LemonChiffon
            TableConditionalFormatting -Name 'TenantType' -ComparisonType string -Operator contains -Value "Multi-Tenant" -Color White -BackgroundColor Teal

            TableConditionalFormatting -Name 'State' -ComparisonType string -Operator eq -Value "Enabled" -Color NavyBlue -BackgroundColor GreenYellow
            TableConditionalFormatting -Name 'State' -ComparisonType string -Operator eq -Value "Disabled" -Color RedBerry -BackgroundColor Orange
            TableConditionalFormatting -Name 'State' -ComparisonType string -Operator eq -Value "Sign-in disabled" -Color RedBerry -BackgroundColor Orange
            TableConditionalFormatting -Name 'State' -ComparisonType string -Operator contains -Value "(" -Color Black -BackgroundColor Yellow

            TableConditionalFormatting -Name 'OwnerCount' -ComparisonType number -Operator eq -Value 0 -Color White -BackgroundColor Red
            TableConditionalFormatting -Name 'Owners' -ComparisonType string -Operator contains -Value "ZTNA" -Color White -BackgroundColor Bordeaux
            TableConditionalFormatting -Name 'Owners' -ComparisonType string -Operator eq -Value "No owners found" -Color White -BackgroundColor Red
            TableConditionalFormatting -Name 'OwnerUPN' -ComparisonType string -Operator eq -Value "N/A" -Color Black -BackgroundColor Yellow
            TableConditionalFormatting -Name 'OwnerUPN' -ComparisonType string -Operator ne -Value "N/A" -Color White -BackgroundColor Green

            TableConditionalFormatting -Name 'Findings' -ComparisonType string -Operator contains -Value "Secret expiring within" -Color White -BackgroundColor Red -HighlightHeaders 'SecretDaysLeft', 'SecretExpiryDate'
            TableConditionalFormatting -Name 'Findings' -ComparisonType string -Operator contains -Value "Secret lifetime >" -Color Black -BackgroundColor DarkOrange -HighlightHeaders 'SecretLifetimeDays'
            TableConditionalFormatting -Name 'Findings' -ComparisonType string -Operator contains -Value "App certificate expiring within" -Color Black -BackgroundColor YellowOrange -HighlightHeaders 'CertDaysLeft', 'CertExpiryDate'
            TableConditionalFormatting -Name 'ExpiredCredentials' -ComparisonType number -Operator gt -Value 0 -Color Black -BackgroundColor Orange
            TableConditionalFormatting -Name 'FederatedCreds' -ComparisonType string -Operator ne -Value "N/A" -Color NavyBlue -BackgroundColor GreenYellow
            TableConditionalFormatting -Name 'SPCredentials' -ComparisonType number -Operator gt -Value 0 -Color White -BackgroundColor Red
            TableConditionalFormatting -Name 'Findings' -ComparisonType string -Operator contains -Value "SAML signing certificate expiring" -Color Black -BackgroundColor YellowOrange -HighlightHeaders 'SAMLCertDaysLeft', 'SAMLCertExpiryDate'

            TableConditionalFormatting -Name 'Status' -ComparisonType string -Operator eq -Value "Compliant" -Color NavyBlue -BackgroundColor GreenYellow
            TableConditionalFormatting -Name 'Status' -ComparisonType string -Operator eq -Value "Unknown" -Color Black -BackgroundColor Yellow
            TableConditionalFormatting -Name 'Status' -ComparisonType string -Operator eq -Value "Non-Compliant" -Color White -BackgroundColor Red
            TableConditionalFormatting -Name 'Status' -ComparisonType string -Operator eq -Value "Disabled" -Color White -BackgroundColor BlueDiamond
        }
    }
} -FilePath (Join-Path $OutputDir "$HtmFileName.htm")
#endregion

#region Excel Output
$SheetName = if ($HtmFileName.Length -gt 31) { $HtmFileName.Substring(0, 31) } else { $HtmFileName }   # Excel sheet name limit

$ConditionalText = @(
    New-ConditionalText -Text 'No owners found' -ConditionalType Equal
    New-ConditionalText -Text 'Multi-Tenant' -ConditionalType Equal
    New-ConditionalText -Text 'Compliant'       -ConditionalType Equal -ConditionalTextColor Black -BackgroundColor GreenYellow
    New-ConditionalText -Text 'Unknown'         -ConditionalType Equal -ConditionalTextColor Black -BackgroundColor Yellow
    New-ConditionalText -Text 'Non-Compliant'   -ConditionalType Equal
    New-ConditionalText -Text 'Disabled'        -ConditionalType Equal -ConditionalTextColor White -BackgroundColor SteelBlue
)

if ($HTMLResult.Count) {
    $HTMLResult | Export-Excel -Path $ExcelOutputPath -WorksheetName $SheetName -ClearSheet -AutoSize -AutoFilter -FreezeTopRow `
        -TableStyle Medium15 -ConditionalText $ConditionalText
}
else {
    Write-Host "No data to export to Excel." -ForegroundColor Yellow
}
#endregion