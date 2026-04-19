### Enable/Disable SPN ###

# -------------------------------
# CONFIGURATION
# -------------------------------

$TenantId       = ""
$ClientId       = ""
$ClientSecret   = ""
$TargetSpnName  = ""

# -------------------------------
# GET ACCESS TOKEN
# -------------------------------

$TokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

$TokenBody = @{
    client_id     = $ClientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $ClientSecret
    grant_type    = "client_credentials"
}

$TokenResponse = Invoke-RestMethod `
    -Method POST `
    -Uri $TokenUrl `
    -Body $TokenBody `
    -ContentType "application/x-www-form-urlencoded"

$AccessToken = $TokenResponse.access_token

$Headers = @{
    Authorization = "Bearer $AccessToken"
    "Content-Type" = "application/json"
}

# -------------------------------
# FIND SERVICE PRINCIPAL
# -------------------------------

$SpnUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq '$TargetSpnName'"

$SpnResponse = Invoke-RestMethod `
    -Method GET `
    -Uri $SpnUri `
    -Headers $Headers

if ($SpnResponse.value.Count -eq 0) {
    Write-Host "Service Principal not found"
    exit
}

$ServicePrincipalId = $SpnResponse.value[0].id

Write-Host "Service Principal ID:" $ServicePrincipalId

# -------------------------------
# DISABLE SERVICE PRINCIPAL
# -------------------------------

$DisableBody = @{
    accountEnabled = $true
} | ConvertTo-Json

$DisableUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId"

Invoke-RestMethod `
    -Method PATCH `
    -Uri $DisableUri `
    -Headers $Headers `
    -Body $DisableBody

Write-Host "Service Principal has been disabled successfully"


### Validate SPN ###
# ------------------------------------------------
# CONFIGURATION
# ------------------------------------------------

$TenantId       = ""
$ClientId       = ""
$ClientSecret   = ""

# Recommended: use AppId (Application ID)
$AppId = ""

# ------------------------------------------------
# GET ACCESS TOKEN
# ------------------------------------------------

$TokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

$TokenBody = @{
    client_id     = $ClientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $ClientSecret
    grant_type    = "client_credentials"
}

try {
    $TokenResponse = Invoke-RestMethod `
        -Method POST `
        -Uri $TokenUrl `
        -Body $TokenBody `
        -ContentType "application/x-www-form-urlencoded"
}
catch {
    Write-Host "❌ Failed to acquire token" -ForegroundColor Red
    Write-Host $_
    return
}

$Headers = @{
    Authorization = "Bearer $($TokenResponse.access_token)"
}

# ------------------------------------------------
# RESOLVE SERVICE PRINCIPAL USING APP ID
# ------------------------------------------------

$UriSPN = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppId'"

Write-Host "Resolving Service Principal using AppId..."
Write-Host $UriSPN

try {
    $SPNResponse = Invoke-RestMethod `
        -Method GET `
        -Uri $UriSPN `
        -Headers $Headers
}
catch {
    Write-Host "❌ Failed to query Service Principals" -ForegroundColor Red
    Write-Host $_
    return
}

# Validate response
if (-not $SPNResponse.value -or $SPNResponse.value.Count -eq 0) {
    Write-Host "❌ No Service Principal found for AppId: $AppId" -ForegroundColor Red
    return
}

# Debug output (helps in troubleshooting)
Write-Host ""
Write-Host "Service Principal Found:"
$SPNResponse.value | Select-Object displayName, id, appId | Format-List

# Extract Object ID
$ServicePrincipalId = $SPNResponse.value[0].id

if (-not $ServicePrincipalId) {
    Write-Host "❌ Service Principal ID is empty" -ForegroundColor Red
    return
}

# ------------------------------------------------
# GET SERVICE PRINCIPAL DETAILS
# ------------------------------------------------

$UriDetails = "https://graph.microsoft.com/v1.0/servicePrincipals('$ServicePrincipalId')?`$select=displayName,appId,accountEnabled"

Write-Host ""
Write-Host "Fetching Service Principal details..."
Write-Host $UriDetails

try {
    $Response = Invoke-RestMethod `
        -Method GET `
        -Uri $UriDetails `
        -Headers $Headers
}
catch {
    Write-Host "❌ Failed to retrieve Service Principal details" -ForegroundColor Red
    Write-Host $_
    return
}

# ------------------------------------------------
# OUTPUT
# ------------------------------------------------

Write-Host ""
Write-Host "===== Service Principal Details ====="
Write-Host ("Display Name      : {0}" -f $Response.displayName)
Write-Host ("App ID            : {0}" -f $Response.appId)
Write-Host ("Object ID         : {0}" -f $ServicePrincipalId)
Write-Host ("Account Enabled   : {0}" -f $Response.accountEnabled)

### Enable/Disable User
# ------------------------------------------------
# CONFIGURATION
# ------------------------------------------------

$TenantId       = ""
$ClientId       = ""
$ClientSecret   = ""

# User (use UPN or Object ID)
$UserId = ""   # or GUID

# ------------------------------------------------
# GET ACCESS TOKEN
# ------------------------------------------------

$TokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

$TokenBody = @{
    client_id     = $ClientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $ClientSecret
    grant_type    = "client_credentials"
}

try {
    $TokenResponse = Invoke-RestMethod `
        -Method POST `
        -Uri $TokenUrl `
        -Body $TokenBody `
        -ContentType "application/x-www-form-urlencoded"
}
catch {
    Write-Host "❌ Failed to acquire token" -ForegroundColor Red
    Write-Host $_
    return
}

$Headers = @{
    Authorization = "Bearer $($TokenResponse.access_token)"
    "Content-Type" = "application/json"
}

# ------------------------------------------------
# DISABLE USER
# ------------------------------------------------

$Uri = "https://graph.microsoft.com/v1.0/users/$UserId"

$Body = @{
    accountEnabled = $true
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

### Remove From Global Admin ###
# ------------------------------------------------
# CONFIGURATION
# ------------------------------------------------

$TenantId       = ""
$ClientId       = ""
$ClientSecret   = ""

$UserUPN = ""

# Global Admin Role Template ID
$GlobalAdminRoleTemplateId = "62e90394-69f5-4237-9190-012177145e10"

# ------------------------------------------------
# GET TOKEN
# ------------------------------------------------

$TokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

$TokenBody = @{
    client_id     = $ClientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $ClientSecret
    grant_type    = "client_credentials"
}

$TokenResponse = Invoke-RestMethod -Method POST -Uri $TokenUrl -Body $TokenBody -ContentType "application/x-www-form-urlencoded"

$Headers = @{
    Authorization = "Bearer $($TokenResponse.access_token)"
    "Content-Type" = "application/json"
}

# ------------------------------------------------
# GET USER
# ------------------------------------------------

$User = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$UserUPN" -Headers $Headers
$UserId = $User.id

# ------------------------------------------------
# GET GLOBAL ADMIN ROLE (ACTIVATE IF NEEDED)
# ------------------------------------------------

$Roles = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -Headers $Headers

$GlobalAdminRole = $Roles.value | Where-Object { $_.roleTemplateId -eq $GlobalAdminRoleTemplateId }

# If role not found, activate it
if (-not $GlobalAdminRole) {
    Write-Host "Activating Global Administrator role..."

    $ActivateBody = @{
        roleTemplateId = $GlobalAdminRoleTemplateId
    } | ConvertTo-Json

    Invoke-RestMethod -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/directoryRoles" `
        -Headers $Headers `
        -Body $ActivateBody

    # Re-fetch roles
    $Roles = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -Headers $Headers
    $GlobalAdminRole = $Roles.value | Where-Object { $_.roleTemplateId -eq $GlobalAdminRoleTemplateId }
}

$RoleId = $GlobalAdminRole.id

# ------------------------------------------------
# CHECK MEMBERSHIP
# ------------------------------------------------

$Members = Invoke-RestMethod -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$RoleId/members" `
    -Headers $Headers

$UserMember = $Members.value | Where-Object { $_.id -eq $UserId }

if (-not $UserMember) {
    Write-Host "User is NOT a Global Administrator"
    return
}

# ------------------------------------------------
# REMOVE USER FROM ROLE
# ------------------------------------------------

$RemoveUri = "https://graph.microsoft.com/v1.0/directoryRoles/$RoleId/members/$UserId/`$ref"

Write-Host "Removing Global Admin role from user..."

Invoke-RestMethod -Method Delete -Uri $RemoveUri -Headers $Headers

Write-Host "✅ User removed from Global Administrator role"
