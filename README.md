# Microsoft Graph API
[Microsoft Graph](https://developer.microsoft.com/en-us/graph/graph-explorer)

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
