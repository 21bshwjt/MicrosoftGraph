# Microsoft Graph API
[Microsoft Graph](https://developer.microsoft.com/en-us/graph/graph-explorer)  or  [https://aka.ms/ge](https://aka.ms/ge)  or  [https://ge.cmd.ms/](https://ge.cmd.ms/)

### Graph Explorer

```powershell
# Default Query
https://graph.microsoft.com/v1.0/me

# Filtered Attributes
https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName

# User.Read.All - Permission is needed to run the below query
https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName

# Get Top three users
https://graph.microsoft.com/v1.0/users?$top=3&$select=id,userPrincipalName
```

### Retrieve users from the Microsoft Graph API using a User account (Tested with Global Admin)

```powershell
$url = "https://graph.microsoft.com/v1.0/users"
$token = "*************************************"
$header = @{Authorization = "Bearer $token"}
invoke-RestMethod -uri $url -Headers $header
$result =invoke-RestMethod -uri $url -Headers $header
$result.value
$result.value | Measure-Object
$result.value | Select-Object id,userPrincipalName
```

### Retrieve AAD users & Azure resources from the Microsoft Graph API using an Azure Service Principal

<img src="https://github.com/21bshwjt/MicrosoftGraph/blob/main/Screenshots/perms.png?raw=true" width="800" height="320">

#### Above permissions are needed for that Application to work all the scripts mentioned here.
- [**scope**](https://graph.microsoft.com/.default) uri is needed to query the AAD users & [**resource**](https://management.core.windows.net) uri is needed to query the AZ resources.
- Authorization endpoint is not needed when "**grant_type**" is  "**client_credentials**". The token endpoint is only needed. **Token type: Access_Token**
- Token Endpoint (V1) : [https://login.microsoftonline.com/<tenant_Id>/oauth2/token](https://login.microsoftonline.com/<tenant_Id>/oauth2/token) - Use that for Azure Resouces
- Token Endpoint (V2) : [https://login.microsoftonline.com/<tenant_Id>/oauth2/v2.0/token](https://login.microsoftonline.com/<tenant_Id>/oauth2/v2.0/token) - Use that for Entra ID

```powershell
<##
.Description
Retrieve users from the Microsoft Graph API using an Azure Service Principal

Source: https://github.com/goodworkaround/bluescreen_scripts/blob/main/Working%20with%20the%20Microsoft%20Graph%20from%20PowerShell/get-access-token-manual.ps1
https://github.com/goodworkaround/bluescreen_scripts/blob/main/Working%20with%20the%20Microsoft%20Graph%20from%20PowerShell/get-access-token-sdk.ps1
https://github.com/BohrenAn/GitHub_PowerShellScripts/blob/main/AzureAD/CreateAADApp-MgGraph.ps1
##>

# Define variables
$tenantId = "*********************"
$clientId = "*********************"
$clientSecret = "*****************"

# Define API endpoint and parameters
$tokenEndpoint = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$tokenParams = @{
    grant_type    = "client_credentials"
    client_id     = $clientId
    client_secret = $clientSecret
    scope         = "https://graph.microsoft.com/.default"
}

# Get access token
$accessToken = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $tokenParams

# Output access token
#Write-Output $accessToken.access_token

$result = Invoke-RestMethod "https://graph.microsoft.com/v1.0/users" -Headers @{Authorization = "Bearer $($accessToken.access_token)"}
$result.value | Measure-Object
$result.value | Select-Object id,userPrincipalName
```

### Microsoft Azure REST API's using Client credential flow

```powershell
# Microsoft Azure REST API's using Client credential flow
Connect-AzAccount -Identity
$tenantid = Get-AzKeyVaultSecret -VaultName "<KeyVault>" -Name "<tenantId_Seceret>" -AsPlainText
$openid = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantid/.well-known/openid-configuration"
$tokenendpoint = $openid.token_endpoint

$body = @{
    grant_type    = "client_credentials"
    client_id     = "<Client_Id>"
    client_secret = "<Client_Secret>"
    redirect_uri = "https://localhost"
    resource = "https://management.core.windows.net"
    tenant = "<Domainname.com>" # optional
    
}

$token = Invoke-RestMethod -Uri $tokenendpoint -Body $body -Method Post
$access_token = $token.access_token

$url = "https://management.azure.com/subscriptions/<Subscription_id>/resources?api-version=2021-04-01"
$az_resources = Invoke-RestMethod $url -Headers @{Authorization = "Bearer $($access_token)"} -Method Get
```

### Retrieve AAD Users from the Microsoft Graph PowerShell using System Assigned Managed Identity(MSI) & KeyVault

```powershell
#Script is tested from Azure Automation Account & Azure VM
#Requires -Module @{ ModuleName = 'Az.Accounts'; ModuleVersion = '2.13.2' }
#Requires -Module @{ ModuleName = 'Az.KeyVault'; ModuleVersion = '5.0.1' }
#Requires -Module @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.10.0' }
#Requires -Module @{ ModuleName = 'Microsoft.Graph.Users'; ModuleVersion = '2.10.0' }
Connect-AzAccount -Identity
$ApplicationId = Get-AzKeyVaultSecret -VaultName "<Your_KeyVault>" -Name "<ClientId_Secret>" -AsPlainText
$SecuredPassword = Get-AzKeyVaultSecret -VaultName "<Your_KeyVault>" -Name "<Client_Secret>" -AsPlainText
$tenantID = Get-AzKeyVaultSecret -VaultName "<Your_KeyVault>" -Name "<TenantID_Secret>" -AsPlainText

$SecuredPasswordPassword = ConvertTo-SecureString -String $SecuredPassword -AsPlainText -Force
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList `
$ApplicationId, $SecuredPasswordPassword
Connect-MgGraph -TenantId $tenantID -ClientSecretCredential $ClientSecretCredential -NoWelcome
Get-MgUser | Select-Object DisplayName, Id, UserPrincipalName
```

### Graph SDK - Certificate based authentication using Service principle name

```powershell
# Permissions are needed as per the above screenshot. 
$client_id = "*****************"
$tenant_id = "********************"
$thumb_print = (Get-ChildItem "Cert:\LocalMachine\my" | Where-Object { $_.Subject -eq "CN=*******" }).Thumbprint

Connect-MgGraph -ClientId $client_id -TenantId $tenant_id -CertificateThumbprint $thumb_print

$result = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users"
$result.value
$result.value | Select-Object id,displayName,userPrincipalName
```

### Create an Azure Application using Graph API

```powershell
# 'Application.ReadWrite.OwnedBy' - Permission is required
$client_id = "*****************"
$tenant_id = "********************"
$thumb_print = (Get-ChildItem "Cert:\LocalMachine\my" | Where-Object { $_.Subject -eq "CN=*******" }).Thumbprint
Connect-MgGraph -ClientId $client_id -TenantId $tenant_id -CertificateThumbprint $thumb_print
New-MgApplication -DisplayName <My_New_App1>
```

### Get AAD Users from Azure Automation PowerShell RunBook
```powershell
# Get the Azure Automation connection object
$connection = Get-AutomationConnection -Name "<Azure_SPI>"

# Connect to Azure using the connection object
Try {
    Connect-MgGraph -ClientId $connection.ApplicationID `
        -TenantId $connection.TenantID `
        -CertificateThumbprint $connection.CertificateThumbprint
}    
catch {
    Write-Error -Message $_.Exception
    throw $_.Exception
}
# Set the subscription context
Set-AzContext -SubscriptionId "<Sub_Id>" | Out-Null
Connect-MgGraph -ClientId $client_id -TenantId $tenant_id -CertificateThumbprint $thumb_print -NoWelcome
$result = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users"
#$result.value
$result.value | Select-Object id,displayName,userPrincipalName
```
### Get Tenant Creation Date Using Postman
- API : https://graph.microsoft.com/v1.0/organization
- Access Token URL
- Client ID
- Client Secret
- Scope : https://graph.microsoft.com/.default
- Client Authentication:  Send as Basic Auth Header
- Attribute : **createdDateTime**

### Get Tenant Creation Date Using PowerShell

```powershell
# MSFT Graph API : https://learn.microsoft.com/en-us/graph/api/organization-list?view=graph-rest-1.0&tabs=http
# Define variables
$tenantId = "************************"
$clientId = "************************"
$clientSecret = "************************"

# Define API endpoint and parameters
$tokenEndpoint = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$tokenParams = @{
    grant_type    = "client_credentials"
    client_id     = $clientId
    client_secret = $clientSecret
    scope         = "https://graph.microsoft.com/.default"
}

# Get access token
$accessToken = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $tokenParams

# Output access token
#Write-Output $accessToken.access_token

$result = Invoke-RestMethod "https://graph.microsoft.com/v1.0/organization" -Headers @{Authorization = "Bearer $($accessToken.access_token)" }

[PSCustomObject]@{
    TenantCreationDate         = $($result.value.createdDateTime)
    CustomDomain               = $($result.value.verifiedDomains.Name)
    onPremisesSyncEnabled      = $($result.value.onPremisesSyncEnabled)
    onPremisesLastSyncDateTime = $($result.value.onPremisesLastSyncDateTime)  
    countryCode                = $($result.value.countryLetterCode)
}

```

#### Output
<img src="https://github.com/21bshwjt/MicrosoftGraph/blob/main/Screenshots/customdomain.png?raw=true" width="800" height="125">

### Authentication using SPN & Certificate 
```powershell
function New-JwtToken {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )

    $header = @{
        alg = "RS256"
        typ = "JWT"
        x5t = [System.Convert]::ToBase64String($Certificate.GetCertHash())
    }

    $claims = @{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        iss = $ClientId
        sub = $ClientId
        jti = [System.Guid]::NewGuid().ToString()
        exp = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 3600
        nbf = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    }

    $encodedHeader = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $header -Compress)))
    $encodedClaims = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $claims -Compress)))
    $unsignedToken = "$encodedHeader.$encodedClaims"
    
    $rsaProvider = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    $signatureBytes = $rsaProvider.SignData([System.Text.Encoding]::UTF8.GetBytes($unsignedToken), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $signature = [System.Convert]::ToBase64String($signatureBytes)
    
    return "$unsignedToken.$signature"
}
# Enter Your TenantID, ClientID & Thumbprint
$tenantId = ""
$clientId = ""
$certificateThumbprint = ""

# Define API endpoint and parameters
$tokenEndpoint = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$tokenParams = @{
    grant_type = "client_credentials"
    client_id  = $clientId
    scope      = "https://graph.microsoft.com/.default"
}

# Get the certificate
$cert = Get-Item -Path "Cert:\LocalMachine\My\$certificateThumbprint"

# Get access token
$tokenParams["client_assertion"] = New-JwtToken -Certificate $cert -ClientId $clientId -TenantId $tenantId
$tokenParams["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

$accessToken = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $tokenParams

# Output access token
Write-Output $accessToken.access_token

Invoke-RestMethod "https://graph.microsoft.com/v1.0/users" -Headers @{Authorization = "Bearer $($accessToken.access_token)" }
```
### Multi-Tenant Organization (B2B)
```powershell
# 38. Multi Tenant Org. & B2B Partners
#region Authentication & Authorization
$Token = "*******************"
#endregion

#region Generic Variables
$BaseApi = 'https://graph.microsoft.com'
$ApiVersion = 'v1.0'
$Endpoint = '/policies/crossTenantAccessPolicy/partners'

$Uri = "{0}/{1}{2}" -f $BaseApi, $ApiVersion, $Endpoint

$Headers = @{
    'Authorization' = "Bearer $Token"
    'Content-Type'  = 'application/json'
}

$RequestProperties = @{
    Uri     = $Uri
    Method  = 'GET'
    Headers = $Headers
}
#endregion

#region Get Partner Info
try {
    $Get_Partners = Invoke-RestMethod @RequestProperties
    $RawResults = $Get_Partners.value
}
catch {
    Write-Error "Failed to retrieve B2B partner data: $_"
    return
}

# Flatten the results
$HTMLResult = foreach ($partner in $RawResults) {
    [PSCustomObject]@{
        Partner_TenantId               = $partner.tenantId
        IsServiceProvider              = $partner.isServiceProvider
        IsInMultiTenantOrganization    = $partner.isInMultiTenantOrganization

        # Consent
        Consent_InboundAllowed         = $partner.automaticUserConsentSettings?.inboundAllowed
        Consent_OutboundAllowed        = $partner.automaticUserConsentSettings?.outboundAllowed

        # Inbound Trust
        TrustMFA                       = $partner.inboundTrust?.isMfaAccepted
        TrustCompliantDevice           = $partner.inboundTrust?.isCompliantDeviceAccepted
        TrustHybridJoinedDevice        = $partner.inboundTrust?.isHybridAzureADJoinedDeviceAccepted

        # B2B Inbound Collaboration
        B2BInbound_AllowApps           = ($partner.b2bCollaborationInbound?.accessSettings?.application?.targets | ForEach-Object { $_.target }) -join ', '
        B2BInbound_BlockApps           = ($partner.b2bCollaborationInbound?.accessSettings?.application?.exclusions | ForEach-Object { $_.target }) -join ', '

        # B2B Outbound Collaboration
        B2BOutbound_AllowApps          = ($partner.b2bCollaborationOutbound?.accessSettings?.application?.targets | ForEach-Object { $_.target }) -join ', '
        B2BOutbound_BlockApps          = ($partner.b2bCollaborationOutbound?.accessSettings?.application?.exclusions | ForEach-Object { $_.target }) -join ', '

        # Direct Connect
        DirectConnect_Inbound_Enabled  = $partner.b2bDirectConnectInbound?.isEnabled
        DirectConnect_Outbound_Enabled = $partner.b2bDirectConnectOutbound?.isEnabled


    }
}
#endregion

#region HTML & Excel Output
$Ps1FileName = $($MyInvocation.MyCommand.Name)
$DirName = ($Ps1FileName -split "_")[0]
$HtmFileName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)

# Ensure output directory exists
$OutputDir = ".\Output\$DirName"
if (!(Test-Path $OutputDir)) {
    [void](New-Item -ItemType Directory -Path $OutputDir -Force)
}

# Set title from comment
$FirstLine = Get-Content $MyInvocation.MyCommand.Path | Select-Object -First 1
$Title = $FirstLine -replace '^#\s*\d+\.\s*', ''
$date = (Get-Date).ToString('MM-dd-yyyy')
$headertxt = "<H2><Center>$Title | $date </Center></H2>"

# Generate HTML Report
New-HTML -TitleText $Title {
    New-HTMLContent -HeaderText "<center>$headertxt</center>" {
        New-HTMLTable -Title $Title -DataTable $HTMLResult -HideFooter -PagingOptions @(100, 200, 300) {
        }
    }
} -FilePath "$OutputDir\$HtmFileName.htm"

# Export to Excel
if ($HTMLResult) {
    $HTMLResult | Export-Excel -Path ".\Output\Entra_Posture_Management.xlsx" -WorksheetName $HtmFileName -AutoSize -TableStyle Medium21
}
else {
    Write-Host "No data to export to Excel." -ForegroundColor Yellow
}
#endregion

```
### Email via Graph API - App Based Auth
```powershell
# Define your app details
# Mail.Send under "Application" type is listed
$tenantId = "" # Your Tenant ID
$clientId = "" # Your Application ID
$clientSecret = "" # App Secret
$sender = "" # Sender Email
$recipient = "" # Recipient Email

# Get a token
$body = @{
    grant_type    = "client_credentials"
    scope         = "https://graph.microsoft.com/.default"
    client_id     = $clientId
    client_secret = $clientSecret
}

$tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $body
$accessToken = $tokenResponse.access_token

# Step 1: Define table data
$tableData = @(
    @{ Name = "Alice Smith"; Department = "IT"; Status = "Active" },
    @{ Name = "Bob Johnson"; Department = "Finance"; Status = "Inactive" },
    @{ Name = "Charlie Brown"; Department = "HR"; Status = "Active" }
)

# Step 2: Generate HTML table rows
$htmlRows = foreach ($row in $tableData) {
    "<tr><td>$($row.Name)</td><td>$($row.Department)</td><td>$($row.Status)</td></tr>"
} -join "`n"

# Step 3: Define the main email body with table rows injected
$emailBody = @{
    message         = @{
        subject      = "📧 Email via Graph API - App Based Auth"
        body         = @{
            contentType = "HTML"
            content     = @"
<html>
<head>
  <style>
    body { font-family: Segoe UI, sans-serif; background-color: #f9f9f9; padding: 20px; color: #333; }
    .container { background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    h2 { color: #0078D4; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
    th { background-color: #0078D4; color: white; }
    tr:nth-child(even) { background-color: #f2f2f2; }
  </style>
</head>
<body>
  <div class="container">
    <h2>Hello,</h2>
    <p>This message was sent using <strong>Microsoft Graph API</strong> with <em>app-only authentication</em>.</p>

    <table>
      <tr>
        <th>Name</th>
        <th>Department</th>
        <th>Status</th>
      </tr>
      $htmlRows
    </table>

    <p style="margin-top:20px;">Regards,<br/>Graph API Bot</p>
  </div>
</body>
</html>
"@
        }
        toRecipients = @(
            @{
                emailAddress = @{
                    address = $recipient
                }
            }
        )
        from         = @{
            emailAddress = @{
                address = $sender
            }
        }
    }
    saveToSentItems = "false"
} | ConvertTo-Json -Depth 10



# Send the email
$response = Invoke-RestMethod -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/users/$sender/sendMail" `
    -Headers @{ Authorization = "Bearer $accessToken" } `
    -Body $emailBody `
    -ContentType "application/json"
$response
Write-Host "Email sent successfully." -ForegroundColor Green

```
### Email via Graph API - App Based Auth with Shared Mailbox
```powershell
# === CONFIGURE VARIABLES ===
# Define your app and email details
$tenantId     = ""   # Your tenant ID
$clientId     = ""   # Your application (client) ID
$clientSecret = ""   # Your client secret
$sender       = ""  # The sender's email address (must be a mailbox your app can send as)

# Define recipients
$recipients = @("Email1", "Email2")

# === AUTHENTICATE TO GRAPH ===
$tokenRequestBody = @{
    grant_type    = "client_credentials"
    scope         = "https://graph.microsoft.com/.default"
    client_id     = $clientId
    client_secret = $clientSecret
}
$tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $tokenRequestBody
$accessToken = $tokenResponse.access_token

# === BUILD HTML TABLE DATA ===
$tableData = @(
    @{ Name = "Alice Smith"; Department = "IT"; Status = "Active" },
    @{ Name = "Bob Johnson"; Department = "Finance"; Status = "Inactive" },
    @{ Name = "Charlie Brown"; Department = "HR"; Status = "Active" }
)

$htmlRows = foreach ($row in $tableData) {
    "<tr><td>$($row.Name)</td><td>$($row.Department)</td><td>$($row.Status)</td></tr>"
} -join "`n"

# === GENERATE HTML BODY ===
$htmlBody = @"
<html>
<head>
  <style>
    body { font-family: Segoe UI, sans-serif; background-color: #f9f9f9; padding: 20px; color: #333; }
    .container { background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    h2 { color: #0078D4; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
    th { background-color: #0078D4; color: white; }
    tr:nth-child(even) { background-color: #f2f2f2; }
  </style>
</head>
<body>
  <div class="container">
    <h2>Hello,</h2>
    <p>This email was sent via <strong>Microsoft Graph API</strong> using <em>App-only authentication</em>.</p>

    <table>
      <tr><th>Name</th><th>Department</th><th>Status</th></tr>
      $htmlRows
    </table>

    <p style="margin-top:20px;">Regards,<br/>Graph API Bot</p>
  </div>
</body>
</html>
"@

# === BUILD JSON PAYLOAD ===
$toRecipientsJson = @(
    foreach ($email in $recipients) {
        @{
            emailAddress = @{
                address = $email
            }
        }
    }
)

$emailPayload = @{
    message = @{
        subject = "📧 Email from Graph API using App-only Auth"
        body = @{
            contentType = "HTML"
            content = $htmlBody
        }
        toRecipients = $toRecipientsJson
    }
    saveToSentItems = $false
} | ConvertTo-Json -Depth 10

# === SEND EMAIL VIA GRAPH API ===
$response = Invoke-RestMethod -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/users/$sender/sendMail" `
    -Headers @{ Authorization = "Bearer $accessToken" } `
    -Body $emailPayload `
    -ContentType "application/json"
$response

Write-Host "✅ Email sent successfully." -ForegroundColor Green

```
### Connect-MgGraph With App & Secret - SDK
```powershell
$ApplicationId = ""
$TenantId = ""
$ClientSecret = ""

# Secure the Client Secret
$ClientSecretSecure = $ClientSecret | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $ClientSecretSecure

# Connect to Microsoft Graph
Connect-MgGraph -TenantId $TenantId -Credential $Credential

# Validate connection
Get-MgContext
```
### Entra ID - Get Extension Attributes - SDK 
```powershell
(Get-MgUser -UserId "UPN" -Property extension_46a8f918361f4d8fb5e505453a0e21a8_msDS_cloudExtensionAttribute1).AdditionalProperties

# Get only top-level keys (property names)
$user = Get-MgUser -UserId "bshwjt@contoso.com" -Property *
$user.PSObject.Properties.Name
```
### Get onPremisesExtensionAttributes
```powershell
https://graph.microsoft.com/v1.0/users?$select=displayName,userPrincipalName,mail,jobTitle,department,accountEnabled,userType,createdDateTime,lastModifiedDateTime,telephoneNumber,physicalDeliveryOfficeName,city,state,country,companyName,employeeId,streetAddress,mobilePhone,preferredLanguage,onPremisesSyncEnabled,onPremisesDistinguishedName,onPremisesImmutableId,onPremisesExtensionAttributes
```
### Get Custom Attributes
```powershell
# Cmdlet: Get-MgDirectoryObjectAvailableExtensionProperty
#region Authentication & Authorization
. ".\AuthN_AuthZ.ps1"
#endregion

#region Generic Variables
$BaseApi = 'https://graph.microsoft.com'
$ApiVersion = 'v1.0'
$Endpoint = "/directoryObjects/microsoft.graph.getAvailableExtensionProperties"

$Uri = "{0}/{1}{2}" -f $BaseApi, $ApiVersion, $Endpoint

$Headers = @{
    'Authorization' = 'Bearer ' + $accessToken
    'Content-Type'  = 'application/json'
}

# Body is required even if minimal
$Body = @{
    isSyncedFromOnPremises = $false  # Set to true if you only want synced extension properties
} | ConvertTo-Json

$RequestProperties = @{
    Uri     = $Uri
    Method  = 'POST'  # Must be POST
    Headers = $Headers
    Body    = $Body
}
#endregion

#region Invoke-RestMethod
$Response = Invoke-RestMethod @RequestProperties
$Response.value.Name | Sort-Object | ForEach-Object {
    Write-Host $_ -ForegroundColor Magenta
}
#endregion

```
### Evaluate Entra Conditional Access Policy
```powershell
# Permissions: Directory.Read.All & Policy.Read.All
# KB: https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-evaluate?view=graph-rest-beta
# Step 1: Get access token
$tenantId = ""
$clientId = ""
$clientSecret = ""

$userObjectId = "b23b252e-0f36-4d56-9538-03fcd97e8805"  # Replace with actual user object ID
$appObjectId = "00000003-0000-0000-c000-000000000000"  # Replace with app's service principal ID (e.g., Graph)

# ========== GET ACCESS TOKEN ==========
$tokenResponse = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body @{
    grant_type    = "client_credentials"
    client_id     = $clientId
    client_secret = $clientSecret
    scope         = "https://graph.microsoft.com/.default"
}
$accessToken = $tokenResponse.access_token

# ========== BUILD EVALUATION REQUEST BODY ==========
$body = @{
    signInIdentity      = @{
        "@odata.type" = "#microsoft.graph.userSignIn"
        userId        = $userObjectId
    }
    signInContext       = @{
        "@odata.type"       = "#microsoft.graph.applicationContext"
        includeApplications = @($appObjectId)
    }
    signInConditions    = @{
        clientAppType   = "browser"
        ipAddress       = "203.0.113.10"
        signInRiskLevel = "low"
        userRiskLevel   = "none"
        devicePlatform  = "windows"
        country         = "IN"
    }
    appliedPoliciesOnly = $true
} | ConvertTo-Json -Depth 6

# ========== CALL THE EVALUATE API ==========
$uri = "https://graph.microsoft.com/beta/identity/conditionalAccess/evaluate"
$response = Invoke-RestMethod -Method POST -Uri $uri -Headers @{
    Authorization  = "Bearer $accessToken"
    "Content-Type" = "application/json"
} -Body $body

# ========== DISPLAY RESULTS ==========
function Show-CAEvaluationResult {
    param (
        [Parameter(Mandatory)]
        $Policy
    )

    Write-Host "`n===================================" -ForegroundColor Cyan
    Write-Host "Policy Name:      $($Policy.displayName)"
    Write-Host "Policy Applies:   $($Policy.policyApplies)"
    Write-Host "Analysis Reason:  $($Policy.analysisReasons)"

    Write-Host "`n--- Conditions ---" -ForegroundColor Yellow
    $c = $Policy.conditions
    if ($c) {
        Write-Host "User Risk Levels:        $($c.userRiskLevels -join ', ')"
        Write-Host "Sign-in Risk Levels:     $($c.signInRiskLevels -join ', ')"
        Write-Host "Client App Types:        $($c.clientAppTypes -join ', ')"
        if ($c.platforms) {
            Write-Host "Platforms:               $($c.platforms.includePlatforms -join ', ')"
        }
        if ($c.locations) {
            Write-Host "Locations:               $($c.locations.includeLocations -join ', ')"
        }
    }

    Write-Host "`n--- Grant Controls ---" -ForegroundColor Yellow
    $g = $Policy.grantControls
    if ($g) {
        Write-Host "Operator:                $($g.operator)"
        Write-Host "Built-in Controls:       $($g.builtInControls -join ', ')"
        Write-Host "Custom Auth Factors:     $($g.customAuthenticationFactors -join ', ')"
        Write-Host "Terms of Use:            $($g.termsOfUse -join ', ')"
        if ($g.authenticationStrength) {
            Write-Host "Authentication Strength: $($g.authenticationStrength.displayName)"
        }
    }

    Write-Host "===================================" -ForegroundColor Cyan
}

# ========== LOOP THROUGH EACH POLICY ==========
foreach ($policy in $response.value) {
    Show-CAEvaluationResult -Policy $policy
}

```
### How to find Tenant ID
```powershell
Invoke-RestMethod -Uri "https://odc.officeapps.live.com/odc/v2.1/federationprovider?domain=contoso.com"
```

### User Password Reset
```powershell
<# 
Graph API Version: v1.0
Permissions: 'User Administrator' Role & 'User.ReadWrite.All' (SPN Application permission with Admin Consent)
Note: Not Delegated Permission
Author: 
Date: 22-April-2026
#>

<#
Reset Password - Single User
#>
#region Authentication & Authorization
. ".\AuthN_AuthZ.ps1"
#endregion

$userId = "user@test.onmicrosoft.com"  # or use Object ID
$newPassword = "****" # Hard coded the password & tested with 12 charector password

$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

$body = @{
    passwordProfile = @{
        # Set it to $false if you don't want to force a password change at next logon.
        forceChangePasswordNextSignIn = $true # or $false
        password                      = $newPassword
    }
} | ConvertTo-Json -Depth 3

Invoke-RestMethod -Method Patch `
    -Uri "https://graph.microsoft.com/v1.0/users/$userId" `
    -Headers $headers `
    -Body $body
```

###  Revoke all active sessions
```powershell
###  Revoke all active sessions
<# 
Author: 
Description: Revoke all active sessions for a single Entra ID user
#>

#region Authentication
. ".\AuthN_AuthZ.ps1"
#endregion

# Normalize access token (handle object vs string)
if ($accessToken -is [System.Management.Automation.PSCustomObject]) {
    $accessToken = $accessToken.access_token
}

# Validate Access Token
if (-not $accessToken -or $accessToken.Split(".").Count -ne 3) {
    throw "Invalid or missing access token. Check AuthN_AuthZ.ps1"
}

# Input
$userId = "biswajit@contoso.onmicrosoft.com"

# Headers
$headers = @{
    Authorization = "Bearer $accessToken"
    "Content-Type" = "application/json"
}

# Validate user exists
try {
    Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/users/$userId" `
        -Headers $headers `
        -ErrorAction Stop
}
catch {
    Write-Error "User not found or not accessible: $userId"
    return
}

# Revoke sessions
try {
    Invoke-RestMethod -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/users/$userId/revokeSignInSessions" `
        -Headers $headers `
        -ErrorAction Stop

    Write-Host "Active sessions revoked successfully for $userId" -ForegroundColor Green
}
catch {
    Write-Warning ("Failed to revoke sessions for {0}. Error: {1}" -f $userId, $_.Exception.Message)

    if ($_.ErrorDetails.Message) {
        Write-Host "Graph Error Details:" -ForegroundColor Yellow
        Write-Host $_.ErrorDetails.Message
    }
}

```
### Disable an user
```powershell
$Uri = "https://graph.microsoft.com/v1.0/users/$UserId"

$Body = @{
    accountEnabled = $false
} | ConvertTo-Json

Write-Host "Disabling user: $UserId"
Write-Host $Uri

try {
    Invoke-RestMethod `
        -Method PATCH `
        -Uri $Uri `
        -Headers $Headers `
        -Body $Body

    Write-Host "✅ User disabled successfully"
}
catch {
    Write-Host "❌ Failed to disable user" -ForegroundColor Red
    Write-Host $_
}
```
### Global Admins - Audit
```powershell
# Global Administrator Audit - Final (Users + SPN + Full Summary)

#region Authentication
. ".\AuthN_AuthZ.ps1"
#endregion

$BaseApi = 'https://graph.microsoft.com'
$ApiVersion = 'v1.0'

$Headers = @{
    Authorization  = "Bearer $Token"
    'Content-Type' = 'application/json'
}

$GlobalAdminId = "62e90394-69f5-4237-9190-012177145e10"

$Results = @()
$UserIds = @{}
$SPNIds = @{}

# =========================
# 🔹 ACTIVE ASSIGNMENTS
# =========================
$Uri = "$BaseApi/$ApiVersion/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$GlobalAdminId'"

while ($Uri) {

    $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method GET

    foreach ($Item in $Response.value) {

        $Principal = $null
        try {
            $Principal = Invoke-RestMethod -Uri "$BaseApi/$ApiVersion/directoryObjects/$($Item.principalId)" -Headers $Headers
        }
        catch {
            continue
        }

        $type = $Principal.'@odata.type'

        $MemberType = if ($type -match 'user') { "User" }
        elseif ($type -match 'group') { "Group" }
        elseif ($type -match 'servicePrincipal') { "SPN" }
        else { "Other" }

        if ($MemberType -eq "User") { $UserIds[$Item.principalId] = $true }
        if ($MemberType -eq "SPN") { $SPNIds[$Item.principalId] = $true }

        $Results += [PSCustomObject]@{
            AssignmentType    = "Active-Direct"
            PrincipalType     = $MemberType
            Id                = $Item.principalId
            DisplayName       = $Principal.displayName
            UserPrincipalName = $Principal.userPrincipalName
            AppId             = $Principal.appId
            GroupName         = ""
        }

        # Group expansion
        if ($MemberType -eq "Group") {

            $GroupUri = "$BaseApi/$ApiVersion/groups/$($Item.principalId)/members"

            while ($GroupUri) {

                $GroupResponse = Invoke-RestMethod -Uri $GroupUri -Headers $Headers -Method GET

                foreach ($gm in $GroupResponse.value) {

                    $gtype = $gm.'@odata.type'
                    if (-not $gtype) {
                        try {
                            $PrincipalDetail = Invoke-RestMethod -Uri "$BaseApi/$ApiVersion/directoryObjects/$($gm.id)" -Headers $Headers
                            $gtype = $PrincipalDetail.'@odata.type'
                        }
                        catch {}
                    }

                    $gmType = if ($gtype -match 'user') { "User" }
                    elseif ($gtype -match 'group') { "Group" }
                    elseif ($gtype -match 'servicePrincipal|application') { "SPN" }
                    else { 
                        Write-Warning "Unidentified Type (Active-ViaGroup): ID $($gm.id) | Type $gtype"
                        "Other" 
                    }

                    if ($gmType -eq "User") { $UserIds[$gm.id] = $true }
                    if ($gmType -eq "SPN") { $SPNIds[$gm.id] = $true }

                    $Results += [PSCustomObject]@{
                        AssignmentType    = "Active-ViaGroup"
                        PrincipalType     = $gmType
                        Id                = $gm.id
                        DisplayName       = $gm.displayName
                        UserPrincipalName = $gm.userPrincipalName
                        AppId             = $gm.appId
                        GroupName         = $Principal.displayName
                    }
                }

                $GroupUri = $GroupResponse.'@odata.nextLink'
            }

            try {
                $SpnGroupUri = "$BaseApi/$ApiVersion/groups/$($Item.principalId)/members/microsoft.graph.servicePrincipal"
                while ($SpnGroupUri) {
                    $SpnResp = Invoke-RestMethod -Uri $SpnGroupUri -Headers $Headers -Method GET
                    foreach ($spn in $SpnResp.value) {
                        $exists = $Results | Where-Object { $_.Id -eq $spn.id -and $_.GroupName -eq $Principal.displayName -and $_.AssignmentType -eq "Active-ViaGroup" }
                        if (-not $exists) {
                            $SPNIds[$spn.id] = $true
                            $Results += [PSCustomObject]@{
                                AssignmentType    = "Active-ViaGroup"
                                PrincipalType     = "SPN"
                                Id                = $spn.id
                                DisplayName       = $spn.displayName
                                UserPrincipalName = $spn.userPrincipalName
                                AppId             = $spn.appId
                                GroupName         = $Principal.displayName
                            }
                        }
                    }
                    $SpnGroupUri = $SpnResp.'@odata.nextLink'
                }
            }
            catch {}
        }
    }

    $Uri = $Response.'@odata.nextLink'
}

# =========================
# 🔹 ELIGIBLE ASSIGNMENTS
# =========================
$EligibleUri = "$BaseApi/$ApiVersion/roleManagement/directory/roleEligibilitySchedules?`$filter=roleDefinitionId eq '$GlobalAdminId'"

while ($EligibleUri) {

    $Response = Invoke-RestMethod -Uri $EligibleUri -Headers $Headers -Method GET

    foreach ($Item in $Response.value) {

        $Principal = Invoke-RestMethod -Uri "$BaseApi/$ApiVersion/directoryObjects/$($Item.principalId)" -Headers $Headers

        $ptype = $Principal.'@odata.type'

        $PrincipalType = if ($ptype -match 'user') { "User" }
        elseif ($ptype -match 'group') { "Group" }
        elseif ($ptype -match 'servicePrincipal') { "SPN" }
        else { "Other" }

        if ($PrincipalType -eq "User") { $UserIds[$Item.principalId] = $true }
        if ($PrincipalType -eq "SPN") { $SPNIds[$Item.principalId] = $true }

        $Results += [PSCustomObject]@{
            AssignmentType    = "Eligible-Direct"
            PrincipalType     = $PrincipalType
            Id                = $Item.principalId
            DisplayName       = $Principal.displayName
            UserPrincipalName = $Principal.userPrincipalName
            AppId             = $Principal.appId
            GroupName         = ""
        }

        # Group expansion (Eligible)
        if ($PrincipalType -eq "Group") {

            $GroupUri = "$BaseApi/$ApiVersion/groups/$($Item.principalId)/members"

            while ($GroupUri) {

                $GroupResponse = Invoke-RestMethod -Uri $GroupUri -Headers $Headers -Method GET

                foreach ($gm in $GroupResponse.value) {

                    $gtype = $gm.'@odata.type'
                    if (-not $gtype) {
                        try {
                            $PrincipalDetail = Invoke-RestMethod -Uri "$BaseApi/$ApiVersion/directoryObjects/$($gm.id)" -Headers $Headers
                            $gtype = $PrincipalDetail.'@odata.type'
                        }
                        catch {}
                    }

                    $gmType = if ($gtype -match 'user') { "User" }
                    elseif ($gtype -match 'group') { "Group" }
                    elseif ($gtype -match 'servicePrincipal|application') { "SPN" }
                    else { 
                        Write-Warning "Unidentified Type (Eligible-ViaGroup): ID $($gm.id) | Type $gtype"
                        "Other" 
                    }

                    if ($gmType -eq "User") { $UserIds[$gm.id] = $true }
                    if ($gmType -eq "SPN") { $SPNIds[$gm.id] = $true }

                    $Results += [PSCustomObject]@{
                        AssignmentType    = "Eligible-ViaGroup"
                        PrincipalType     = $gmType
                        Id                = $gm.id
                        DisplayName       = $gm.displayName
                        UserPrincipalName = $gm.userPrincipalName
                        AppId             = $gm.appId
                        GroupName         = $Principal.displayName
                    }
                }

                $GroupUri = $GroupResponse.'@odata.nextLink'
            }

            try {
                $SpnGroupUri = "$BaseApi/$ApiVersion/groups/$($Item.principalId)/members/microsoft.graph.servicePrincipal"
                while ($SpnGroupUri) {
                    $SpnResp = Invoke-RestMethod -Uri $SpnGroupUri -Headers $Headers -Method GET
                    foreach ($spn in $SpnResp.value) {
                        $exists = $Results | Where-Object { $_.Id -eq $spn.id -and $_.GroupName -eq $Principal.displayName -and $_.AssignmentType -eq "Eligible-ViaGroup" }
                        if (-not $exists) {
                            $SPNIds[$spn.id] = $true
                            $Results += [PSCustomObject]@{
                                AssignmentType    = "Eligible-ViaGroup"
                                PrincipalType     = "SPN"
                                Id                = $spn.id
                                DisplayName       = $spn.displayName
                                UserPrincipalName = $spn.userPrincipalName
                                AppId             = $spn.appId
                                GroupName         = $Principal.displayName
                            }
                        }
                    }
                    $SpnGroupUri = $SpnResp.'@odata.nextLink'
                }
            }
            catch {}
        }
    }

    $EligibleUri = $Response.'@odata.nextLink'
}

# =========================
# 🔹 USER LOOKUP (BATCH)
# =========================
$UserLookup = @{}
$UserIdList = $UserIds.Keys
$BatchSize = 15

for ($i = 0; $i -lt $UserIdList.Count; $i += $BatchSize) {

    $batch = $UserIdList[$i..([Math]::Min($i + $BatchSize - 1, $UserIdList.Count - 1))]
    $filter = ($batch | ForEach-Object { "id eq '$_'" }) -join " or "

    $uri = "$BaseApi/$ApiVersion/users?`$filter=$filter&`$select=id,userPrincipalName"
    $resp = Invoke-RestMethod -Uri $uri -Headers $Headers -Method GET

    foreach ($u in $resp.value) {
        $UserLookup[$u.id] = $u
    }
}

# =========================
# 🔹 SPN LOOKUP (BATCH)
# =========================
$SPNLookup = @{}
$SPNIdList = $SPNIds.Keys

for ($i = 0; $i -lt $SPNIdList.Count; $i += $BatchSize) {

    $batch = $SPNIdList[$i..([Math]::Min($i + $BatchSize - 1, $SPNIdList.Count - 1))]
    $filter = ($batch | ForEach-Object { "id eq '$_'" }) -join " or "

    $uri = "$BaseApi/$ApiVersion/servicePrincipals?`$filter=$filter&`$select=id,appId,displayName"
    $resp = Invoke-RestMethod -Uri $uri -Headers $Headers -Method GET

    foreach ($spn in $resp.value) {
        $SPNLookup[$spn.id] = $spn
    }
}

# =========================
# 🔹 ENRICH
# =========================
foreach ($r in $Results) {

    if ($r.PrincipalType -eq "User" -and $UserLookup.ContainsKey($r.Id)) {
        $u = $UserLookup[$r.Id]
        $r.UserPrincipalName = $u.userPrincipalName
    }

    if ($r.PrincipalType -eq "SPN" -and $SPNLookup.ContainsKey($r.Id)) {
        $spn = $SPNLookup[$r.Id]
        $r.AppId = $spn.appId
        $r.DisplayName = $spn.displayName
    }
}

# =========================
# 📊 OUTPUT TABLE
# =========================
Write-Host "`n========== GLOBAL ADMIN DETAILS ==========" -ForegroundColor Cyan

$Results |
Sort-Object AssignmentType, PrincipalType, DisplayName |
Format-Table AssignmentType, PrincipalType, DisplayName, UserPrincipalName, AppId, GroupName -AutoSize

# =========================
# 📊 SUMMARY (Users + SPN)
# =========================
$TotalRecords = $Results.Count

$DirectCount = ($Results | Where-Object { $_.AssignmentType -like "*-Direct" }).Count
$ViaGroupCount = ($Results | Where-Object { $_.AssignmentType -like "*-ViaGroup" }).Count

$ActiveCount = ($Results | Where-Object { $_.AssignmentType -like "Active-*" }).Count
$EligibleCount = ($Results | Where-Object { $_.AssignmentType -like "Eligible-*" }).Count

$TotalUniqueUsers = @($Results | Where-Object { $_.PrincipalType -eq "User" } | Select-Object -ExpandProperty Id -Unique).Count
$ActiveUniqueUsers = @($Results | Where-Object { $_.PrincipalType -eq "User" -and $_.AssignmentType -like "Active-*" } | Select-Object -ExpandProperty Id -Unique).Count
$EligibleUniqueUsers = @($Results | Where-Object { $_.PrincipalType -eq "User" -and $_.AssignmentType -like "Eligible-*" } | Select-Object -ExpandProperty Id -Unique).Count

$TotalUniqueSPN = @($Results | Where-Object { $_.PrincipalType -eq "SPN" } | Select-Object -ExpandProperty Id -Unique).Count
$ActiveUniqueSPN = @($Results | Where-Object { $_.PrincipalType -eq "SPN" -and $_.AssignmentType -like "Active-*" } | Select-Object -ExpandProperty Id -Unique).Count
$EligibleUniqueSPN = @($Results | Where-Object { $_.PrincipalType -eq "SPN" -and $_.AssignmentType -like "Eligible-*" } | Select-Object -ExpandProperty Id -Unique).Count

$TotalUniqueOther = @($Results | Where-Object { $_.PrincipalType -eq "Other" } | Select-Object -ExpandProperty Id -Unique).Count

Write-Host "`n========== GLOBAL ADMIN SUMMARY ==========" -ForegroundColor Cyan

Write-Host "Total Assignments     : $TotalRecords"
Write-Host "  ├─ Active           : $ActiveCount"
Write-Host "  └─ Eligible         : $EligibleCount"
Write-Host "Direct Assignments    : $DirectCount"
Write-Host "Via Group Memberships : $ViaGroupCount"
Write-Host "Unique Users          : $TotalUniqueUsers"
Write-Host "  ├─ Active           : $ActiveUniqueUsers"
Write-Host "  └─ Eligible         : $EligibleUniqueUsers"
Write-Host "Unique SPN            : $TotalUniqueSPN"
Write-Host "  ├─ Active           : $ActiveUniqueSPN"
Write-Host "  └─ Eligible         : $EligibleUniqueSPN"
if ($TotalUniqueOther -gt 0) { Write-Host "Unique Other Objects  : $TotalUniqueOther" -ForegroundColor Yellow }

Write-Host "`nCompleted." -ForegroundColor Green
```
### Microsoft Graph Permissions & Descriptions
```powershell
$response = Invoke-WebRequest -Uri "https://graphpermissions.merill.net/permission/"

$matches = [regex]::Matches(
    $response.Content,
    '<td><a href=".*?">(.*?)</a></td>\s*<td>(.*?)</td>',
    [System.Text.RegularExpressions.RegexOptions]::Singleline
)

$result = foreach ($match in $matches) {
    [PSCustomObject]@{
        Permission  = $match.Groups[1].Value.Trim()
        Description = ($match.Groups[2].Value -replace '<.*?>','').Trim()
    }
}

$result | Format-Table -AutoSize
```
### Block-AppClientSecrets
```powershell
#==============================================================
# Block client secrets on a specific Entra app registration
#==============================================================

#--------------------------------------------------------------
# Variables
#--------------------------------------------------------------
$appDisplayName    = "Your App Name"          # <-- the app registration to protect
$policyDisplayName = "Block client secrets"

#--------------------------------------------------------------
# Connect to Microsoft Graph
#--------------------------------------------------------------
Connect-MgGraph -Scopes "Policy.Read.All","Policy.ReadWrite.ApplicationConfiguration","Application.ReadWrite.All"

#--------------------------------------------------------------
# Review the tenant default app management policy
#--------------------------------------------------------------
Get-MgPolicyDefaultAppManagementPolicy | ConvertTo-Json -Depth 10

#--------------------------------------------------------------
# Create the blocking policy (skipped if it already exists)
#--------------------------------------------------------------
$existing = (Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/policies/appManagementPolicies").value |
    Where-Object { $_.displayName -eq $policyDisplayName }

if ($existing) {
    $policy = $existing | Select-Object -First 1
    Write-Host "Policy already exists: $($policy.id)"
}
else {
    $body = @"
{
  "displayName": "$policyDisplayName",
  "description": "Blocks password and symmetric key credentials on assigned apps",
  "isEnabled": true,
  "restrictions": {
    "passwordCredentials": [
      {
        "restrictionType": "passwordAddition",
        "state": "enabled",
        "maxLifetime": null,
        "restrictForAppsCreatedAfterDateTime": "2019-01-01T00:00:00Z"
      },
      {
        "restrictionType": "symmetricKeyAddition",
        "state": "enabled",
        "maxLifetime": null,
        "restrictForAppsCreatedAfterDateTime": "2019-01-01T00:00:00Z"
      }
    ]
  }
}
"@

    $policy = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/policies/appManagementPolicies" `
        -Body $body -ContentType "application/json"

    Write-Host "Policy created: $($policy.id)"
}

#--------------------------------------------------------------
# Get the target app registration
#--------------------------------------------------------------
$app = Get-MgApplication -Filter "displayName eq '$appDisplayName'"

if (-not $app) { throw "App '$appDisplayName' not found." }
if (@($app).Count -gt 1) { throw "More than one app named '$appDisplayName'. Use Get-MgApplication -ApplicationId <object-id>." }

$app | Select-Object DisplayName, Id, AppId   # confirm it's the right app

#--------------------------------------------------------------
# Assign the policy to the app
#--------------------------------------------------------------
$refBody = @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/policies/appManagementPolicies/$($policy.id)"
} | ConvertTo-Json

Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/applications/$($app.Id)/appManagementPolicies/`$ref" `
    -Body $refBody -ContentType "application/json"

#--------------------------------------------------------------
# Verify the assignment
#--------------------------------------------------------------
(Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/applications/$($app.Id)/appManagementPolicies").value |
    ForEach-Object { [pscustomobject]$_ } |
    Select-Object displayName, id, isEnabled
```
