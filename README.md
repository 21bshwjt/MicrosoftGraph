# Microsoft Graph
[Microsoft Graph](https://developer.microsoft.com/en-us/graph/graph-explorer)

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
