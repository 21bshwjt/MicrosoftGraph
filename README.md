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


