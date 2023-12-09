# Microsoft Graph API
[Microsoft Graph](https://developer.microsoft.com/en-us/graph/graph-explorer) or [https://aka.ms/ge](https://aka.ms/ge)

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

### Retrieve users from the Microsoft Graph API using an Azure Service Principal

<img src="https://github.com/21bshwjt/MicrosoftGraph/blob/main/Screenshots/Consent.png?raw=true" width="800" height="320">

#### Above permissions are needed for that Application


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
$tokenEndpoint = "https://login.microsoftonline.com/$tenantId/oauth2/token"
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

### Retrieve users from the Microsoft Graph PowerShell using System Assigned Managed Identity & KeyVault

```powershell
Connect-AzAccount -Identity
$ApplicationId = "<AppID>"
$SecuredPassword = Get-AzKeyVaultSecret -VaultName "<KV_Name>" -Name "<Secret_Name>" -AsPlainText
$tenantID = "<Tenant_ID>"
$SecuredPasswordPassword = ConvertTo-SecureString -String $SecuredPassword -AsPlainText -Force
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $SecuredPasswordPassword
Connect-MgGraph -TenantId $tenantID -ClientSecretCredential $ClientSecretCredential
Get-MgUser
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

### Create an Application using Graph API

```powershell
# 'Application.ReadWrite.OwnedBy' - Permission is required
$client_id = "*****************"
$tenant_id = "********************"
$thumb_print = (Get-ChildItem "Cert:\LocalMachine\my" | Where-Object { $_.Subject -eq "CN=*******" }).Thumbprint
Connect-MgGraph -ClientId $client_id -TenantId $tenant_id -CertificateThumbprint $thumb_print
New-MgApplication -DisplayName <My_New_App1>
```
