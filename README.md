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
- Token Endpoint (V1) : [https://login.microsoftonline.com/<tenant_Id>/oauth2/token](https://login.microsoftonline.com/<tenant_Id>/oauth2/token) - Use that for AZ Resouces
- Token Endpoint (V2) : [https://login.microsoftonline.com/<tenant_Id>/oauth2/v2.0/token](https://login.microsoftonline.com/<tenant_Id>/oauth2/v2.0/token) - Use that for AAD Users

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

### Certificate based authentication using Service principle name

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



