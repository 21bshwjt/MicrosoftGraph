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
    CustomDomain               = $result.value.verifiedDomains.Name
    onPremisesSyncEnabled      = $result.value.onPremisesSyncEnabled
    onPremisesLastSyncDateTime = $result.value.onPremisesLastSyncDateTime  
    countryCode                = $result.value.countryLetterCode
}


```

