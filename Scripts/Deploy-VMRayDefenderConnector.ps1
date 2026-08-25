<#
.SYNOPSIS
  End-to-end deployment of the VMRay Microsoft Defender for Endpoint Azure connector.

.DESCRIPTION
  Single interactive script that automates the Azure-side deployment described in
  the README:

    Phase 1: Azure AD App Registration (create new OR reuse existing)
             - adds the WindowsDefenderATP + Microsoft Graph APPLICATION permissions
             - mints a client secret
             - grants admin consent (programmatically if you have rights,
               otherwise prints the consent URL to forward to an admin)

    Phase 2: Function App deployment via ARM template (Flex Consumption or Premium)
             - AFTER deploy, the script auto-populates AzureStorageConnectionString
               and AzureStorageAccountKey on the Function App and restarts it.
               (This is the manual "copy the storage key" step from the README,
               done for you. The ARM template itself is left unchanged.)

    Phase 3: Logic App deployment via ARM template (Consumption or Standard)
             - retrieves the VMRayDefender function key and the wdatp connection
               runtime URL and prints them so the remaining connection-authorization
               clicks are copy/paste.

  Two parts of the README CANNOT be automated through Azure APIs and remain manual.
  The script prints a checklist for each at the right moment:
    * Defender portal: Advanced Features (Live Response, Live Response for Servers,
      Live Response unsigned script execution) at https://security.microsoft.com
    * Intune: Quarantine remediation setting
    * The admin-consent click (if you can't grant it yourself)
    * Logic App connection authorization (service-principal auth on the wdatp
      connection + "Change connection" on the Get-single-alert action)

.PARAMETER DisplayName
  Display name for a NEW App Registration. Ignored if -AppId is supplied.

.PARAMETER AppId
  Application (Client) ID of an EXISTING App Registration to reuse.

.PARAMETER ClientSecret
  Existing client secret (SecureString). Only used with -AppId. If you pass -AppId
  without -ClientSecret the script offers to mint a fresh secret.

.PARAMETER ResourceGroup
  Resource group to deploy into. Created if it doesn't exist. The Function App and
  Logic App MUST share a resource group for the Logic App's function reference to
  resolve, so the script reuses this value for both.

.PARAMETER Region
  Azure region for a new resource group. Default: "Central US".

.PARAMETER FunctionPlan
  "Flex" (Flex Consumption) or "Premium". Prompted if omitted.

.PARAMETER FunctionName
  Base name for the Function App (the template appends a 3-char uniqueness hash).
  Default: "VMRayDefender".

.PARAMETER AppInsightsWorkspaceResourceID
  Full resource ID of a Log Analytics workspace. The script can list workspaces
  and let you pick one if you don't pass this.

.PARAMETER VmrayBaseURL
  https://eu.cloud.vmray.com or https://us.cloud.vmray.com (or your on-prem URL).

.PARAMETER VmrayAPIKey
  VMRay connector API key (SecureString).

.PARAMETER LogicAppPlan
  "Consumption" or "Standard". Prompted if omitted.

.PARAMETER PlaybookName
  Logic App name. Default: "SubmitDefenderAlertsToVMRay".

.PARAMETER SkipAppReg / SkipFunctionApp / SkipLogicApp
  Skip individual phases so you can test one at a time.

.EXAMPLE
  ./Deploy-VMRayDefenderConnector.ps1

.EXAMPLE
  # Re-run only the Function App phase, reusing an existing App Reg
  ./Deploy-VMRayDefenderConnector.ps1 -AppId "abc1234-..." -SkipLogicApp
#>

[CmdletBinding()]
param(
  # Phase 1 - App Registration
  [string]$DisplayName,
  [string]$AppId,
  [SecureString]$ClientSecret,
  [ValidateRange(1, 2)][int]$SecretLifetimeYears = 2,

  # Common
  [string]$ResourceGroup,
  [string]$Region = "Central US",

  # Phase 2 - Function App
  [ValidateSet("Flex", "Premium")][string]$FunctionPlan,
  [string]$FunctionName = "VMRayDefender",
  [string]$AppInsightsWorkspaceResourceID,
  [string]$VmrayBaseURL,
  [SecureString]$VmrayAPIKey,
  [int]$VmrayResubmitAfter = 7,

  # Phase 3 - Logic App
  [ValidateSet("Consumption", "Standard")][string]$LogicAppPlan,
  [string]$PlaybookName = "SubmitDefenderAlertsToVMRay",

  # ARM template sources (override for dev/offline)
  [string]$FlexTemplateUri            = "https://raw.githubusercontent.com/vmray/ms-defender-azure/refs/heads/main/FunctionApp/FlexConsumptionPlan/azuredeploy.json",
  [string]$PremiumTemplateUri         = "https://raw.githubusercontent.com/vmray/ms-defender-azure/refs/heads/main/FunctionApp/PremiumPlan/azuredeploy.json",
  [string]$LogicConsumptionTemplateUri= "https://raw.githubusercontent.com/vmray/ms-defender-azure/refs/heads/main/LogicApp/azuredeploy1.json",
  [string]$LogicStandardTemplateUri   = "https://raw.githubusercontent.com/vmray/ms-defender-azure/refs/heads/main/LogicApp/premiumazuredeploy.json",

  # Local template overrides (take precedence over the URIs above)
  [string]$FunctionTemplateFile,
  [string]$LogicTemplateFile,

  # Skip flags
  [switch]$SkipAppReg,
  [switch]$SkipFunctionApp,
  [switch]$SkipLogicApp
)

$ErrorActionPreference = "Stop"
$ProgressPreference     = "SilentlyContinue"

# Track whether the operator passed the names explicitly (so we know to prompt).
$FunctionNameWasPassed = $PSBoundParameters.ContainsKey('FunctionName')
$PlaybookNameWasPassed = $PSBoundParameters.ContainsKey('PlaybookName')
$script:FunctionNameResolved = $false

# ===========================================================================
#  Well-known constants
# ===========================================================================
$MICROSOFT_GRAPH_APP_ID   = "00000003-0000-0000-c000-000000000000"
$WINDOWS_DEFENDER_ATP_APP_ID = "fc780465-2017-40d4-a0c5-307022471b92"
# Storage Blob Data Owner - the role the Function App template assigns to its identity.
$STORAGE_ROLE_DEFINITION_ID = "b7e6dc6d-f1e8-4753-8033-0f276bb0955b"

# APPLICATION permissions (app roles) required on each resource API.
# Resolved to GUIDs at runtime from the resource service principal's AppRoles,
# so we never hard-code potentially-wrong IDs.
$REQUIRED_WDATP_ROLES = @(
  "Alert.ReadWrite.All",
  "Machine.LiveResponse",
  "Machine.Read.All",
  "Ti.ReadWrite",
  "Ti.ReadWrite.All",
  "Library.Manage"
)
$REQUIRED_GRAPH_ROLES = @(
  "SecurityAlert.ReadWrite.All",
  "SecurityIncident.ReadWrite.All"
)

# ===========================================================================
#  Display helpers
# ===========================================================================
function Write-Banner {
  param([string]$Title)
  Write-Host ""
  Write-Host "===========================================================================" -ForegroundColor Magenta
  Write-Host "  $Title" -ForegroundColor Magenta
  Write-Host "===========================================================================" -ForegroundColor Magenta
}

function Write-Phase {
  param([string]$Number, [string]$Title)
  Write-Host ""
  Write-Host ">>> Phase $Number - $Title" -ForegroundColor Cyan
  Write-Host ""
}

function Write-Step {
  param([string]$Index, [string]$Message)
  Write-Host ""
  Write-Host "[$Index] $Message" -ForegroundColor Cyan
}

# ===========================================================================
#  Interactive prompt helpers
# ===========================================================================
function Read-Choice {
  param([string]$Prompt, [string[]]$Options, [int]$Default = 1)
  Write-Host ""
  Write-Host $Prompt -ForegroundColor Yellow
  for ($i = 0; $i -lt $Options.Length; $i++) {
    $marker = if (($i + 1) -eq $Default) { " (default)" } else { "" }
    Write-Host "  [$($i + 1)] $($Options[$i])$marker"
  }
  do {
    $sel = Read-Host "  Choice"
    if ([string]::IsNullOrWhiteSpace($sel)) { return $Default }
    $num = 0
    if ([int]::TryParse($sel, [ref]$num) -and $num -ge 1 -and $num -le $Options.Length) { return $num }
    Write-Host "    Invalid. Enter a number between 1 and $($Options.Length)." -ForegroundColor Red
  } while ($true)
}

function Read-Text {
  param([string]$Prompt, [string]$Default = $null, [string]$ValidationPattern = $null,
        [string]$ValidationMessage = "Invalid input. Try again.")
  do {
    $defaultHint = if ($Default) { " [default: $Default]" } else { "" }
    Write-Host ""
    $value = Read-Host "  $Prompt$defaultHint"
    if ([string]::IsNullOrWhiteSpace($value) -and $Default) { return $Default }
    if ([string]::IsNullOrWhiteSpace($value)) { Write-Host "    Required. Please enter a value." -ForegroundColor Red; continue }
    if (-not $ValidationPattern -or $value -match $ValidationPattern) { return $value }
    Write-Host "    $ValidationMessage" -ForegroundColor Red
  } while ($true)
}

function Confirm-Action {
  param([string]$Prompt, [bool]$Default = $true)
  $defaultStr  = if ($Default) { "Y/n" } else { "y/N" }
  $defaultWord = if ($Default) { "Yes" } else { "No" }
  do {
    Write-Host ""
    $ans = (Read-Host "  $Prompt (default: $defaultWord) [$defaultStr]").Trim().ToLower()
    if ([string]::IsNullOrWhiteSpace($ans)) { return $Default }
    if ($ans -in @("y","yes")) { return $true }
    if ($ans -in @("n","no"))  { return $false }
    Write-Host "    Please answer y or n." -ForegroundColor Red
  } while ($true)
}

function Wait-ForEnter {
  param([string]$Message = "Press ENTER when ready to continue, or Ctrl+C to abort")
  Write-Host ""
  Write-Host "  $Message" -ForegroundColor Yellow
  Read-Host | Out-Null
}

function Read-RequiredSecret {
  # Reads a masked (SecureString) value, re-prompting until a non-empty value is
  # entered. Used for mandatory secrets so an accidental empty ENTER doesn't sail
  # through and fail deep in the deployment.
  param([string]$Prompt)
  do {
    $secure = Read-Host -AsSecureString $Prompt
    $plain  = [System.Net.NetworkCredential]::new("", $secure).Password
    if (-not [string]::IsNullOrWhiteSpace($plain)) { return $secure }
    Write-Host "    Required. Please paste a non-empty value." -ForegroundColor Red
  } while ($true)
}

# ===========================================================================
#  Auth helpers (mirror the Outlook deployment script patterns)
# ===========================================================================
function Connect-MgGraphSmart {
  param([string[]]$Scopes = @("Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All","Directory.Read.All"))

  $context = Get-MgContext -ErrorAction SilentlyContinue
  if ($context) {
    try {
      Get-MgApplication -Top 1 -ErrorAction Stop | Out-Null
      Write-Host "  Already connected to Microsoft Graph. Reusing session." -ForegroundColor Green
      return
    } catch {
      Write-Host "  Existing Graph session is stale. Re-authenticating..." -ForegroundColor Yellow
      Disconnect-MgGraph -ErrorAction SilentlyContinue
    }
  }

  $azContext = $null
  try { $azContext = Get-AzContext -ErrorAction Stop } catch { }
  if ($azContext) {
    try {
      Write-Host "  Using Az session to acquire Graph token..." -ForegroundColor Gray
      $tokenResult = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
      $secureToken = if ($tokenResult.Token -is [System.Security.SecureString]) { $tokenResult.Token }
                     else { ConvertTo-SecureString $tokenResult.Token -AsPlainText -Force }
      Connect-MgGraph -AccessToken $secureToken -NoWelcome -ErrorAction Stop | Out-Null
      Write-Host "  Connected via Az session." -ForegroundColor Green
      return
    } catch {
      Write-Host "  Az pass-through unavailable. Trying interactive browser..." -ForegroundColor Yellow
    }
  }

  try {
    Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop | Out-Null
    Write-Host "  Connected via interactive browser." -ForegroundColor Green
    return
  } catch {
    Write-Host "  Interactive browser failed. Falling back to device code..." -ForegroundColor Yellow
  }
  Connect-MgGraph -Scopes $Scopes -UseDeviceCode -NoWelcome -ErrorAction Stop | Out-Null
  Write-Host "  Connected via device code." -ForegroundColor Green
}

function Connect-AzSmart {
  $azContext = Get-AzContext -ErrorAction SilentlyContinue
  if ($azContext) {
    Write-Host "  Azure session: $($azContext.Account.Id) (tenant $($azContext.Tenant.Id))" -ForegroundColor Green
    return
  }
  Write-Host "  No Azure session. Starting sign-in..." -ForegroundColor Gray
  Connect-AzAccount -ErrorAction Stop | Out-Null
  $azContext = Get-AzContext
  Write-Host "  Connected as $($azContext.Account.Id)." -ForegroundColor Green
}

function Invoke-WithGraphRetry {
  param([Parameter(Mandatory=$true)][scriptblock]$Block, [string]$Description = "Graph operation")
  try { return & $Block }
  catch {
    $errText = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
    if ($errText -match "Authentication needed|InvalidAuthenticationToken|401|TokenExpired") {
      Write-Host "  Token expired during '$Description'. Refreshing..." -ForegroundColor Yellow
      Connect-MgGraphSmart
      return & $Block
    }
    throw
  }
}

function Ensure-Module {
  param([string]$Name)
  $module = Get-Module -ListAvailable -Name $Name | Select-Object -First 1
  if (-not $module) {
    Write-Host "  Installing $Name (current user, one-time)..." -ForegroundColor Yellow
    Install-Module $Name -Scope CurrentUser -Force -AllowClobber
  }
  Import-Module $Name -ErrorAction Stop
}

# ===========================================================================
#  Phase 1 helpers - App Registration & application-permission consent
# ===========================================================================
function Get-ResourceServicePrincipal {
  # Returns the service principal for a resource API (Graph / WindowsDefenderATP),
  # creating it in the tenant if it doesn't exist yet.
  param([string]$ResourceAppId, [string]$FriendlyName)
  $sp = Invoke-WithGraphRetry -Description "looking up $FriendlyName SP" -Block {
    Get-MgServicePrincipal -Filter "appId eq '$ResourceAppId'" -ErrorAction SilentlyContinue | Select-Object -First 1
  }
  if (-not $sp) {
    Write-Host "  $FriendlyName service principal not present in tenant. Creating it..." -ForegroundColor Yellow
    $sp = Invoke-WithGraphRetry -Description "creating $FriendlyName SP" -Block {
      New-MgServicePrincipal -AppId $ResourceAppId
    }
  }
  return $sp
}

function Resolve-AppRoles {
  # Maps required role VALUES (e.g. "Alert.ReadWrite.All") to their GUIDs using the
  # resource SP's published AppRoles. Warns (doesn't fail) on any value not found.
  param($ResourceSp, [string[]]$RoleValues, [string]$FriendlyName)
  $resolved = @()
  foreach ($val in $RoleValues) {
    $role = $ResourceSp.AppRoles | Where-Object { $_.Value -eq $val -and $_.IsEnabled } | Select-Object -First 1
    if ($role) {
      $resolved += [pscustomobject]@{ Value = $val; Id = $role.Id }
    } else {
      Write-Host "    WARNING: '$val' not found on $FriendlyName. It will be skipped." -ForegroundColor Yellow
    }
  }
  return $resolved
}

function Build-RequiredResourceAccess {
  param($GraphRoles, $WdatpRoles, $GraphSpId, $WdatpSpId)
  # GraphRoles/WdatpRoles are the resolved {Value,Id} objects. Type = "Role" (app perms).
  $entries = @()
  if ($GraphRoles.Count -gt 0) {
    $entries += @{
      ResourceAppId  = $MICROSOFT_GRAPH_APP_ID
      ResourceAccess = @($GraphRoles | ForEach-Object { @{ Id = $_.Id; Type = "Role" } })
    }
  }
  if ($WdatpRoles.Count -gt 0) {
    $entries += @{
      ResourceAppId  = $WINDOWS_DEFENDER_ATP_APP_ID
      ResourceAccess = @($WdatpRoles | ForEach-Object { @{ Id = $_.Id; Type = "Role" } })
    }
  }
  return $entries
}

function Test-AppRoleConsentGranted {
  # True only if EVERY required app-role assignment exists on the app's SP.
  param([string]$AppSpId, $AllRequiredRoleIds)
  try {
    $assignments = Invoke-WithGraphRetry -Description "listing app role assignments" -Block {
      Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $AppSpId -All -ErrorAction SilentlyContinue
    }
    $grantedIds = @($assignments | ForEach-Object { $_.AppRoleId })
    foreach ($rid in $AllRequiredRoleIds) {
      if ($grantedIds -notcontains $rid) { return $false }
    }
    return $true
  } catch {
    # Surface the real error (rare) instead of silently swallowing it, so a
    # genuine permission/API failure doesn't masquerade as "consent not granted".
    Write-Host "    (consent check couldn't complete: $($_.Exception.Message))" -ForegroundColor DarkGray
    return $false
  }
}

function Grant-AppRoleConsent {
  # Attempts to grant admin consent programmatically by creating app-role assignments.
  # Returns $true on full success, $false if anything could not be granted (caller
  # then falls back to the browser consent URL).
  param([string]$AppSpId, $GraphRoles, $WdatpRoles, [string]$GraphSpId, [string]$WdatpSpId)
  $ok = $true
  $work = @()
  $work += @($GraphRoles | ForEach-Object { @{ Id = $_.Id; Value = $_.Value; ResourceId = $GraphSpId } })
  $work += @($WdatpRoles | ForEach-Object { @{ Id = $_.Id; Value = $_.Value; ResourceId = $WdatpSpId } })

  $existing = @()
  try {
    $existing = @((Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $AppSpId -All -ErrorAction SilentlyContinue) | ForEach-Object { $_.AppRoleId })
  } catch { }

  foreach ($r in $work) {
    if ($existing -contains $r.Id) {
      Write-Host "    = $($r.Value) (already granted)" -ForegroundColor Gray
      continue
    }
    try {
      New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $AppSpId `
        -PrincipalId $AppSpId -ResourceId $r.ResourceId -AppRoleId $r.Id -ErrorAction Stop | Out-Null
      Write-Host "    + $($r.Value)" -ForegroundColor Green
    } catch {
      Write-Host "    ! $($r.Value) - could not grant ($($_.Exception.Message))" -ForegroundColor Yellow
      $ok = $false
    }
  }
  return $ok
}

function Wait-ForAppRoleConsent {
  # Retry the app-role consent check with an immediate first check, then delays,
  # to absorb the propagation lag (often 10-90s, occasionally longer) between
  # Microsoft granting consent and Graph's read-side reflecting the app-role
  # assignments. Returns $true once all required roles are seen; $false on timeout.
  param(
    [Parameter(Mandatory=$true)][string]$AppSpId,
    [Parameter(Mandatory=$true)]$AllRequiredRoleIds,
    [int]$MaxRetries = 6,
    [int]$RetryDelay = 15
  )
  Write-Host "  Verifying consent..." -ForegroundColor Gray

  # Check immediately first - if consent has already propagated, detect it instantly.
  if (Test-AppRoleConsentGranted -AppSpId $AppSpId -AllRequiredRoleIds $AllRequiredRoleIds) {
    Write-Host "  Consent confirmed for all required permissions." -ForegroundColor Green
    return $true
  }

  for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
    Start-Sleep -Seconds $RetryDelay
    if (Test-AppRoleConsentGranted -AppSpId $AppSpId -AllRequiredRoleIds $AllRequiredRoleIds) {
      Write-Host "  Consent confirmed for all required permissions." -ForegroundColor Green
      return $true
    }
    if ($attempt -lt $MaxRetries) {
      $elapsed = $attempt * $RetryDelay
      Write-Host "  Still propagating (${elapsed}s elapsed), retrying..." -ForegroundColor Gray
    }
  }
  return $false
}

# ===========================================================================
#  Generic Az deploy helper
# ===========================================================================
function Invoke-ArmDeploy {
  param(
    [string]$DeploymentName,
    [string]$ResourceGroup,
    [hashtable]$Parameters,
    [string]$TemplateUri,
    [string]$TemplateFile
  )
  $p = @{
    Name              = $DeploymentName
    ResourceGroupName = $ResourceGroup
    ErrorAction       = "Stop"
  }
  foreach ($k in $Parameters.Keys) { $p[$k] = $Parameters[$k] }
  if ($TemplateFile) { $p.TemplateFile = $TemplateFile } else { $p.TemplateUri = $TemplateUri }
  return New-AzResourceGroupDeployment @p
}

function Select-CreatedResource {
  # Finds resources in the RG matching a name prefix. If exactly one, returns it.
  # If several (RG reuse), lets the operator pick. Used to locate the name-mangled
  # storage account / function app the ARM template created.
  param([string]$ResourceGroup, [string]$NamePrefix, [string]$Kind = "Storage")
  $items = @()
  if ($Kind -eq "Storage") {
    $items = @(Get-AzStorageAccount -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue |
               Where-Object { $_.StorageAccountName -like "$NamePrefix*" })
    if ($items.Count -eq 1) { return $items[0].StorageAccountName }
    if ($items.Count -eq 0) { return $null }
    Write-Host ""
    Write-Host "  Multiple storage accounts match '$NamePrefix*':" -ForegroundColor Yellow
    for ($i=0;$i -lt $items.Count;$i++){ Write-Host "    [$($i+1)] $($items[$i].StorageAccountName)" }
    $pick = Read-Choice -Prompt "Which one did this deployment create?" -Options @($items | ForEach-Object { $_.StorageAccountName })
    return $items[$pick-1].StorageAccountName
  } else {
    $items = @(Get-AzWebApp -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -like "$NamePrefix*" })
    if ($items.Count -eq 1) { return $items[0].Name }
    if ($items.Count -eq 0) { return $null }
    Write-Host ""
    Write-Host "  Multiple apps match '$NamePrefix*':" -ForegroundColor Yellow
    for ($i=0;$i -lt $items.Count;$i++){ Write-Host "    [$($i+1)] $($items[$i].Name)" }
    $pick = Read-Choice -Prompt "Which one did this deployment create?" -Options @($items | ForEach-Object { $_.Name })
    return $items[$pick-1].Name
  }
}

function Remove-StaleStorageRoleAssignment {
  # SAFEGUARD for same-RG re-deploys. The Function App template names its storage
  # role assignment guid(storageAccount, roleDef) - deterministic per RG and WITHOUT
  # the principalId. On a re-deploy the Function App identity changes, so ARM tries to
  # rewrite that same-named assignment with a new principal and fails with
  # 'RoleAssignmentUpdateNotPermitted'. We pre-delete any existing assignment for that
  # role on the vmraystorage* account so the deploy recreates it cleanly. (Leaves the
  # GitHub template untouched.) No-op on a fresh RG where the storage account doesn't exist yet.
  param([string]$ResourceGroup)
  try {
    $accts = @(Get-AzStorageAccount -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue |
               Where-Object { $_.StorageAccountName -like 'vmraystorage*' })
    if ($accts.Count -eq 0) { return }   # fresh deploy - nothing to clean
    foreach ($a in $accts) {
      $scope = $a.Id
      $ras = @(Get-AzRoleAssignment -Scope $scope -ErrorAction SilentlyContinue |
               Where-Object { $_.Scope -eq $scope -and $_.RoleDefinitionId -like "*$STORAGE_ROLE_DEFINITION_ID" })
      foreach ($ra in $ras) {
        Write-Host "  Removing stale role assignment on $($a.StorageAccountName) (principal $($ra.ObjectId))..." -ForegroundColor Yellow
        Remove-AzRoleAssignment -ObjectId $ra.ObjectId -RoleDefinitionId $STORAGE_ROLE_DEFINITION_ID -Scope $scope -ErrorAction Stop | Out-Null
      }
    }
  } catch {
    Write-Host "  (Could not pre-clean role assignments: $($_.Exception.Message). Continuing - a fresh RG is unaffected.)" -ForegroundColor Gray
  }
}

function Remove-StaleDeploymentScript {
  # The Flex template includes a 'WaitSection' deploymentScripts resource (a 30s sleep).
  # deploymentScripts spin up a backing storage account + container instance; if a prior
  # deployment failed or was cancelled mid-run, the leftover resource can conflict on the
  # next deploy. Removing it first forces a clean re-run. No-op if it doesn't exist
  # (fresh RG, or Premium plan which has no WaitSection).
  param([string]$ResourceGroup, [string]$Name = "WaitSection")
  try {
    $existing = Get-AzResource -ResourceGroupName $ResourceGroup -ResourceType "Microsoft.Resources/deploymentScripts" -Name $Name -ErrorAction SilentlyContinue
    if ($existing) {
      Write-Host "  Removing leftover '$Name' deployment script from a previous run..." -ForegroundColor Yellow
      Remove-AzResource -ResourceId $existing.ResourceId -Force -ErrorAction Stop | Out-Null
    }
  } catch {
    Write-Host "  (Could not remove '$Name' deployment script: $($_.Exception.Message). Continuing.)" -ForegroundColor Gray
  }
}

function Get-FunctionDefaultKey {
  # Returns the 'default' key for the VMRayDefender function inside the given app.
  param([string]$ResourceGroup, [string]$FunctionAppName)
  try {
    $sub = (Get-AzContext).Subscription.Id
    $path = "/subscriptions/$sub/resourceGroups/$ResourceGroup/providers/Microsoft.Web/sites/$FunctionAppName/functions/VMRayDefender/listkeys?api-version=2022-03-01"
    $resp = Invoke-AzRestMethod -Path $path -Method POST -ErrorAction Stop
    if ($resp.StatusCode -eq 200) { return ($resp.Content | ConvertFrom-Json).default }
  } catch { }
  return $null
}

function Test-WebSiteNameAvailable {
  # A Standard Logic App is a Microsoft.Web/sites resource, so its name must be
  # globally unique (it becomes <name>.azurewebsites.net). Returns $true if free.
  # On any check failure returns $true so we never block - the deploy will surface
  # a genuine conflict itself.
  param([string]$Name)
  try {
    $sub  = (Get-AzContext).Subscription.Id
    $path = "/subscriptions/$sub/providers/Microsoft.Web/checkNameAvailability?api-version=2023-12-01"
    $body = @{ name = $Name; type = "Microsoft.Web/sites" } | ConvertTo-Json
    $resp = Invoke-AzRestMethod -Path $path -Method POST -Payload $body -ErrorAction Stop
    if ($resp.StatusCode -eq 200) { return [bool]($resp.Content | ConvertFrom-Json).nameAvailable }
  } catch { }
  return $true
}

function Set-AppSettingsMerged {
  # Merges $NewSettings into a site's existing app settings (any Microsoft.Web/sites,
  # including a Logic App Standard). Reads current settings, overlays the new ones,
  # writes them back - so we never wipe the settings the template already placed.
  param([string]$ResourceGroup, [string]$SiteName, [hashtable]$NewSettings)
  $sub  = (Get-AzContext).Subscription.Id
  $base = "/subscriptions/$sub/resourceGroups/$ResourceGroup/providers/Microsoft.Web/sites/$SiteName"
  $listResp = Invoke-AzRestMethod -Path "$base/config/appsettings/list?api-version=2022-03-01" -Method POST -ErrorAction Stop
  $merged = @{}
  if ($listResp.StatusCode -eq 200) {
    $current = ($listResp.Content | ConvertFrom-Json).properties
    if ($current) { $current.PSObject.Properties | ForEach-Object { $merged[$_.Name] = $_.Value } }
  }
  foreach ($k in $NewSettings.Keys) { $merged[$k] = $NewSettings[$k] }
  $body = @{ properties = $merged } | ConvertTo-Json -Depth 10
  $putResp = Invoke-AzRestMethod -Path "$base/config/appsettings?api-version=2022-03-01" -Method PUT -Payload $body -ErrorAction Stop
  if ($putResp.StatusCode -ge 400) { throw "App settings PUT returned HTTP $($putResp.StatusCode): $($putResp.Content)" }
}

# ===========================================================================
#                              SCRIPT START
# ===========================================================================
Write-Banner "VMRay Defender for Endpoint Connector - Azure Deployment"

Write-Host ""
Write-Host "  This script automates the Azure-side deployment:" -ForegroundColor Gray
Write-Host "    1. App Registration (permissions + secret + admin consent)" -ForegroundColor Gray
Write-Host "    2. Function App (ARM) + auto-fills the storage key settings + restart" -ForegroundColor Gray
Write-Host "    3. Logic App (ARM) + prints the values for the final connection wiring" -ForegroundColor Gray
Write-Host ""
Write-Host "  Two areas stay MANUAL (no Azure API): Defender Advanced Features + Intune," -ForegroundColor Gray
Write-Host "  and the Logic App connection authorization. The script tells you exactly" -ForegroundColor Gray
Write-Host "  what to click and when." -ForegroundColor Gray

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
Write-Phase "0" "Pre-flight"

Write-Step "1/2" "Loading PowerShell modules..."
Ensure-Module Microsoft.Graph.Applications
Ensure-Module Az.Resources
Ensure-Module Az.Websites
Ensure-Module Az.Storage
Ensure-Module Az.Functions
try { Ensure-Module Az.OperationalInsights } catch { Write-Host "  (Az.OperationalInsights optional - workspace picker disabled)" -ForegroundColor Gray }

Write-Step "2/2" "Connecting to Microsoft Graph and Azure..."
Connect-MgGraphSmart
Connect-AzSmart

$mgContext = Get-MgContext
$azContext = Get-AzContext
$tenantId  = $mgContext.TenantId

Write-Host ""
Write-Host "  Tenant       : $tenantId" -ForegroundColor White
Write-Host "  Subscription : $($azContext.Subscription.Name) ($($azContext.Subscription.Id))" -ForegroundColor White

# Subscription picker (same UX as the Outlook script)
$allSubs = @()
try { $allSubs = @(Get-AzSubscription -TenantId $tenantId -ErrorAction Stop | Sort-Object Name) }
catch { $allSubs = @($azContext.Subscription) }

if ($allSubs.Count -le 1) {
  if (-not (Confirm-Action "Continue with this tenant + subscription?")) {
    throw "Aborted by user. Switch context (Connect-AzAccount / Connect-MgGraph) and retry."
  }
} else {
  Write-Host "  $($allSubs.Count) subscriptions are accessible in this tenant." -ForegroundColor Gray
  $subChoice = Read-Choice -Prompt "How do you want to handle the subscription?" -Options @(
    "Use the current subscription shown above", "Switch to a different subscription") -Default 1
  if ($subChoice -eq 2) {
    $subOptions = @($allSubs | ForEach-Object { "$($_.Name) ($($_.Id))" })
    $picked = Read-Choice -Prompt "Pick a subscription:" -Options $subOptions -Default 1
    $chosenSub = $allSubs[$picked - 1]
    Set-AzContext -SubscriptionId $chosenSub.Id -TenantId $tenantId | Out-Null
    $azContext = Get-AzContext
    Write-Host "  Now using: $($azContext.Subscription.Name) ($($azContext.Subscription.Id))" -ForegroundColor Green
  }
}

# Resource group (shared by Function App + Logic App)
if (-not $ResourceGroup) {
  $ResourceGroup = Read-Text -Prompt "Resource group name (created if it doesn't exist; used for BOTH apps)"
}
$existingRg = Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue
if ($existingRg) {
  $Region = $existingRg.Location
  Write-Host ""
  Write-Host "  Using existing resource group '$ResourceGroup' in '$Region'." -ForegroundColor Green
} else {
  if (-not $PSBoundParameters.ContainsKey('Region')) {
    $Region = Read-Text -Prompt "Azure region for the new resource group" -Default $Region
  }
  Write-Host "  Creating resource group '$ResourceGroup' in '$Region'..." -ForegroundColor Yellow
  New-AzResourceGroup -Name $ResourceGroup -Location $Region | Out-Null
  Write-Host "  Created." -ForegroundColor Green
}

# ===========================================================================
# PHASE 1 - App Registration
# ===========================================================================
$appClientId      = $null
$appClientSecret  = $null
$consentDeferred  = $false
$deferredConsentUrl = $null
$allRequiredRoleIds = @()

if ($SkipAppReg.IsPresent) {
  Write-Phase "1" "App Registration - SKIPPED (-SkipAppReg)"
  if (-not $AppId)        { throw "-SkipAppReg requires -AppId" }
  if (-not $ClientSecret) { throw "-SkipAppReg requires -ClientSecret" }
  $appClientId     = $AppId
  $appClientSecret = $ClientSecret
} else {
  Write-Phase "1" "App Registration"

  # Resolve the resource service principals + required role GUIDs up front.
  Write-Step "1/5" "Resolving required API permissions..."
  $graphSp = Get-ResourceServicePrincipal -ResourceAppId $MICROSOFT_GRAPH_APP_ID -FriendlyName "Microsoft Graph"
  $wdatpSp = Get-ResourceServicePrincipal -ResourceAppId $WINDOWS_DEFENDER_ATP_APP_ID -FriendlyName "WindowsDefenderATP"
  $graphRoles = Resolve-AppRoles -ResourceSp $graphSp -RoleValues $REQUIRED_GRAPH_ROLES -FriendlyName "Microsoft Graph"
  $wdatpRoles = Resolve-AppRoles -ResourceSp $wdatpSp -RoleValues $REQUIRED_WDATP_ROLES -FriendlyName "WindowsDefenderATP"
  $allRequiredRoleIds = @(@($graphRoles | ForEach-Object { $_.Id }) + @($wdatpRoles | ForEach-Object { $_.Id }))
  Write-Host "  Resolved $($graphRoles.Count) Graph + $($wdatpRoles.Count) WindowsDefenderATP permissions." -ForegroundColor Green

  $appChoice = if ($AppId) { 2 }
               else { Read-Choice -Prompt "How do you want to handle the App Registration?" `
                        -Options @("Create a new App Registration","Use an existing App Registration") -Default 1 }

  if ($appChoice -eq 1) {
    # Loop until we have a name the user is happy to create. If duplicates exist
    # and the user declines to reuse the name, re-prompt for a different one
    # instead of exiting the whole script.
    while ($true) {
      if (-not $DisplayName) { $DisplayName = Read-Text -Prompt "Display name for the new App Registration" -Default "VMRay-Defender-Connector-App" }

      $existing = Invoke-WithGraphRetry -Description "checking for duplicates" -Block {
        $escName = $DisplayName.Replace("'", "''")
        @(Get-MgApplication -Filter "displayName eq '$escName'")
      }
      if ($existing.Count -eq 0) { break }

      Write-Host ""
      Write-Host "  WARNING: $($existing.Count) App Registration(s) named '$DisplayName' already exist." -ForegroundColor Yellow
      $existing | ForEach-Object { Write-Host "    - AppId: $($_.AppId)" -ForegroundColor Yellow }
      if (Confirm-Action "Create another with the same name?" -Default $false) { break }

      # User declined - clear the name so the loop re-prompts for a different one.
      Write-Host "  Please enter a different name for the new App Registration." -ForegroundColor Yellow
      $DisplayName = $null
    }

    Write-Step "2/5" "Creating App Registration '$DisplayName'..."
    $app = Invoke-WithGraphRetry -Description "creating App Reg" -Block {
      New-MgApplication -DisplayName $DisplayName -SignInAudience "AzureADMyOrg"
    }
    Write-Host "  Created (AppId: $($app.AppId))" -ForegroundColor Green

    Write-Step "3/5" "Adding API permissions..."
    $rra = Build-RequiredResourceAccess -GraphRoles $graphRoles -WdatpRoles $wdatpRoles -GraphSpId $graphSp.Id -WdatpSpId $wdatpSp.Id
    Invoke-WithGraphRetry -Description "setting permissions" -Block {
      Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $rra
    }
    Write-Host "  Permissions added." -ForegroundColor Green

    Write-Step "4/5" "Creating client secret (valid $SecretLifetimeYears year(s))..."
    $secretParams = @{ PasswordCredential = @{
      DisplayName = "VMRay Defender connector secret (created $(Get-Date -Format 'yyyy-MM-dd'))"
      EndDateTime = (Get-Date).AddYears($SecretLifetimeYears) } }
    $secret = Invoke-WithGraphRetry -Description "creating secret" -Block { Add-MgApplicationPassword -ApplicationId $app.Id -BodyParameter $secretParams }
    $appClientSecret = ConvertTo-SecureString $secret.SecretText -AsPlainText -Force
    Write-Host "  Secret created (expires $($secret.EndDateTime.ToString('yyyy-MM-dd')))." -ForegroundColor Green
    Write-Host ""
    Write-Host "  +----------------------------------------------------------------------+" -ForegroundColor Yellow
    Write-Host "  |  CLIENT SECRET (visible only once - save it now):                    |" -ForegroundColor Yellow
    Write-Host "  |  $($secret.SecretText)" -ForegroundColor White
    Write-Host "  +----------------------------------------------------------------------+" -ForegroundColor Yellow
  }
  else {
    # ----- Reuse existing -----
    # Loop until we locate the App Registration. A mistyped Client ID re-prompts
    # instead of exiting the whole script.
    $app = $null
    while ($true) {
      if (-not $AppId) { $AppId = Read-Text -Prompt "Existing Application (Client) ID" }
      $app = Invoke-WithGraphRetry -Description "loading App Reg" -Block {
        Get-MgApplication -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue | Select-Object -First 1
      }
      if ($app) { break }

      Write-Host "    No App Registration found with AppId '$AppId'. Check the value and try again." -ForegroundColor Red
      # Clear the parameter value so the loop prompts interactively next time.
      $AppId = $null
    }
    Write-Host "  Selected: $($app.DisplayName)  (AppId: $($app.AppId))" -ForegroundColor Green

    Write-Step "2/5" "Ensuring API permissions are present..."
    $rra = Build-RequiredResourceAccess -GraphRoles $graphRoles -WdatpRoles $wdatpRoles -GraphSpId $graphSp.Id -WdatpSpId $wdatpSp.Id
    Invoke-WithGraphRetry -Description "setting permissions" -Block {
      Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $rra
    }
    Write-Host "  Permissions ensured." -ForegroundColor Green

    Write-Step "3/5" "Resolving client secret..."
    if ($ClientSecret) {
      $appClientSecret = $ClientSecret
      Write-Host "  Using ClientSecret from parameter." -ForegroundColor Green
    } else {
      $secretChoice = Read-Choice -Prompt "Client secret for this App Registration?" `
                        -Options @("Paste an existing secret now","Generate a fresh secret") -Default 2
      if ($secretChoice -eq 1) {
        $appClientSecret = Read-RequiredSecret "  Client Secret"
      } else {
        $secretParams = @{ PasswordCredential = @{
          DisplayName = "VMRay Defender connector secret (created $(Get-Date -Format 'yyyy-MM-dd'))"
          EndDateTime = (Get-Date).AddYears($SecretLifetimeYears) } }
        $secret = Invoke-WithGraphRetry -Description "minting secret" -Block { Add-MgApplicationPassword -ApplicationId $app.Id -BodyParameter $secretParams }
        $appClientSecret = ConvertTo-SecureString $secret.SecretText -AsPlainText -Force
        Write-Host ""
        Write-Host "  +----------------------------------------------------------------------+" -ForegroundColor Yellow
        Write-Host "  |  NEW CLIENT SECRET (visible only once):                              |" -ForegroundColor Yellow
        Write-Host "  |  $($secret.SecretText)" -ForegroundColor White
        Write-Host "  +----------------------------------------------------------------------+" -ForegroundColor Yellow
      }
    }
  }

  $appClientId = $app.AppId

  # ----- Service principal + admin consent (application permissions) -----
  Write-Step "4/5" "Ensuring the app's service principal exists..."
  $appSp = Invoke-WithGraphRetry -Description "looking up app SP" -Block {
    Get-MgServicePrincipal -Filter "appId eq '$appClientId'" -ErrorAction SilentlyContinue | Select-Object -First 1
  }
  if (-not $appSp) {
    $appSp = Invoke-WithGraphRetry -Description "creating app SP" -Block { New-MgServicePrincipal -AppId $appClientId }
  }
  Write-Host "  Service principal ready (Id: $($appSp.Id))." -ForegroundColor Green

  Write-Step "5/5" "Granting admin consent (application permissions)..."
  if (Test-AppRoleConsentGranted -AppSpId $appSp.Id -AllRequiredRoleIds $allRequiredRoleIds) {
    Write-Host "  All required permissions already consented. Skipping." -ForegroundColor Green
  } else {
    $granted = Grant-AppRoleConsent -AppSpId $appSp.Id -GraphRoles $graphRoles -WdatpRoles $wdatpRoles -GraphSpId $graphSp.Id -WdatpSpId $wdatpSp.Id
    if ($granted) {
      Write-Host "  Admin consent granted programmatically." -ForegroundColor Green
    } else {
      $deferredConsentUrl = "https://login.microsoftonline.com/$tenantId/adminconsent?client_id=$appClientId"
      Write-Host ""
      Write-Host "  Couldn't grant every permission automatically (you may lack the directory role)." -ForegroundColor Yellow
      Write-Host "  A Global Administrator must open this URL once and click Accept:" -ForegroundColor Yellow
      Write-Host ""
      Write-Host "    $deferredConsentUrl" -ForegroundColor Cyan
      try { Start-Process $deferredConsentUrl -ErrorAction Stop | Out-Null } catch { }

      $consentChoice = Read-Choice -Prompt "Consent step:" -Options @(
        "I (or an admin) just clicked Accept - verify now (waits up to 90s)",
        "Skip - forward the URL to an admin later") -Default 1

      if ($consentChoice -eq 2) {
        $consentDeferred = $true
      } else {
        $consentVerified = Wait-ForAppRoleConsent -AppSpId $appSp.Id -AllRequiredRoleIds $allRequiredRoleIds

        # If not seen after 90s, offer a recovery loop instead of just giving up:
        # consent propagation is often just slow, so let the user wait longer,
        # re-open the URL, trust a portal confirmation, or defer to an admin.
        while (-not $consentVerified -and -not $consentDeferred) {
          Write-Host ""
          Write-Host "  WARNING: Consent verification didn't see all permissions granted after 90 seconds." -ForegroundColor Yellow
          Write-Host "  Either propagation is unusually slow, OR the Accept click didn't actually register." -ForegroundColor Yellow
          Write-Host "  Verify in Portal: Entra ID -> App registrations -> your app -> API permissions -> Status column." -ForegroundColor Gray

          $recoveryChoice = Read-Choice -Prompt "What would you like to do?" -Options @(
            "Wait another 90s and re-check (consent often just needs more time to propagate)",
            "Re-open the consent URL and try again (if the Accept click may not have registered)",
            "I've confirmed consent IS granted in the Portal - continue as granted",
            "Skip - forward the URL to an admin later"
          ) -Default 1

          switch ($recoveryChoice) {
            1 {
              Write-Host ""
              $consentVerified = Wait-ForAppRoleConsent -AppSpId $appSp.Id -AllRequiredRoleIds $allRequiredRoleIds
            }
            2 {
              Write-Host ""
              Write-Host "  Re-opening consent URL:" -ForegroundColor Cyan
              Write-Host "    $deferredConsentUrl" -ForegroundColor Gray
              Write-Host "  Tip: try an InPrivate / Incognito window, or sign out of other Microsoft accounts first." -ForegroundColor Gray
              try { Start-Process $deferredConsentUrl -ErrorAction Stop | Out-Null } catch { }
              Wait-ForEnter "After clicking Accept again, press ENTER"
              $consentVerified = Wait-ForAppRoleConsent -AppSpId $appSp.Id -AllRequiredRoleIds $allRequiredRoleIds
            }
            3 {
              # Manual override: the user can see consent granted in the Portal even
              # though Graph's read-side hasn't caught up. Trust it and proceed as
              # granted (NOT deferred), so the final summary won't flag consent.
              Write-Host "  Trusting Portal confirmation - continuing as granted." -ForegroundColor Green
              $consentVerified = $true
            }
            4 {
              $consentDeferred = $true
            }
          }
        }
      }
    }
  }

  # ----- Manual checkpoint: Defender Advanced Features + Intune -----
  Write-Host ""
  Write-Host "  ----------------------------------------------------------------------" -ForegroundColor Yellow
  Write-Host "  MANUAL STEPS (cannot be automated via Azure APIs):" -ForegroundColor Yellow
  Write-Host "  ----------------------------------------------------------------------" -ForegroundColor Yellow
  Write-Host "  A) Defender portal -> https://security.microsoft.com" -ForegroundColor Yellow
  Write-Host "     Settings > Endpoints > Advanced features, enable:" -ForegroundColor Yellow
  Write-Host "       - Live Response" -ForegroundColor Yellow
  Write-Host "       - Live Response for Servers" -ForegroundColor Yellow
  Write-Host "       - Live Response unsigned script execution" -ForegroundColor Yellow
  Write-Host "  B) Intune Antivirus policy:" -ForegroundColor Yellow
  Write-Host "       - Set remediation to 'Quarantine' for all threat levels" -ForegroundColor Yellow
  Write-Host "  (You can do these any time before going live - they don't block deploy.)" -ForegroundColor Gray
}

# ===========================================================================
# PHASE 2 - Function App
# ===========================================================================
$functionAppName = $null
if ($SkipFunctionApp.IsPresent) {
  Write-Phase "2" "Function App - SKIPPED (-SkipFunctionApp)"
} else {
  Write-Phase "2" "Deploy Function App"

  if (-not $appClientId)     { throw "Phase 2 needs an App Client ID. Don't skip Phase 1, or pass -AppId." }
  if (-not $appClientSecret) { throw "Phase 2 needs the client secret. Pass -ClientSecret or run Phase 1." }

  if (-not $FunctionPlan) {
    $planChoice = Read-Choice -Prompt "Which Function App hosting plan?" -Options @(
      "Flex Consumption (check region support)","Premium") -Default 1
    $FunctionPlan = if ($planChoice -eq 2) { "Premium" } else { "Flex" }
  }
  $funcTemplateUri = if ($FunctionPlan -eq "Premium") { $PremiumTemplateUri } else { $FlexTemplateUri }

  if (-not $FunctionNameWasPassed -and -not $script:FunctionNameResolved) {
    $FunctionName = Read-Text -Prompt "Function App base name (< 20 chars, letters/numbers/hyphens)" -Default $FunctionName `
                              -ValidationPattern '^[a-zA-Z0-9-]{1,19}$' `
                              -ValidationMessage "Must be fewer than 20 characters; letters, numbers and hyphens only."
  }
  $script:FunctionNameResolved = $true

  # Log Analytics workspace resource ID (required by the template)
  if (-not $AppInsightsWorkspaceResourceID) {
    $wsPicked = $false
    try {
      $workspaces = @(Get-AzOperationalInsightsWorkspace -ErrorAction Stop | Sort-Object Name)
      if ($workspaces.Count -gt 0) {
        $useList = Read-Choice -Prompt "Log Analytics workspace (for App Insights):" -Options @(
          "Pick from the $($workspaces.Count) workspace(s) in this subscription","Paste a Resource ID manually") -Default 1
        if ($useList -eq 1) {
          $wsOpts = @($workspaces | ForEach-Object { "$($_.Name)  ($($_.ResourceGroupName))" })
          $wp = Read-Choice -Prompt "Pick a workspace:" -Options $wsOpts -Default 1
          $AppInsightsWorkspaceResourceID = $workspaces[$wp-1].ResourceId
          $wsPicked = $true
        }
      }
    } catch { }
    if (-not $wsPicked) {
      $AppInsightsWorkspaceResourceID = Read-Text -Prompt "Log Analytics workspace Resource ID" `
        -ValidationPattern '^/subscriptions/.+/workspaces/.+' `
        -ValidationMessage "Must be a full /subscriptions/.../workspaces/... resource ID."
    }
  }

  if (-not $VmrayBaseURL) {
    $urlChoice = Read-Choice -Prompt "VMRay Base URL:" -Options @(
      "https://eu.cloud.vmray.com","https://us.cloud.vmray.com","Other (enter manually)") -Default 1
    $VmrayBaseURL = switch ($urlChoice) {
      1 { "https://eu.cloud.vmray.com" }
      2 { "https://us.cloud.vmray.com" }
      3 { Read-Text -Prompt "VMRay Base URL" -ValidationPattern '^https?://' }
    }
  }
  if (-not $VmrayAPIKey) {
    Write-Host ""
    Write-Host "  Paste the VMRay connector API key (input hidden):" -ForegroundColor Yellow
    $VmrayAPIKey = Read-RequiredSecret "  VMRay API Key"
  }

  # Advanced connector settings - everything here has a sensible template default,
  # so this whole block is opt-in. Only the values the operator changes get passed;
  # the rest fall through to the ARM template defaults.
  $advancedFaParams = @{}
  if (Confirm-Action "Configure advanced connector settings? (otherwise sensible defaults are used)" -Default $false) {
    $advancedFaParams['VmrayResubmitAfter']         = [int](Read-Text -Prompt "Resubmit if previous analysis older than (days, 0-100)" -Default "$VmrayResubmitAfter" `
                                                              -ValidationPattern '^(0|[1-9][0-9]?|100)$' `
                                                              -ValidationMessage "Enter a whole number from 0 to 100.")
    $advancedFaParams['CreateIndicatorsInDefender'] = Confirm-Action "Create indicators in Microsoft Defender?" -Default $true
    $advancedFaParams['AddTagsToIncident']          = Confirm-Action "Add VMRay verdict/threat-name tags to incidents?" -Default $true
    $advancedFaParams['AddCommentsToIncident']      = Confirm-Action "Append VMRay enrichment comments to incidents?" -Default $false
    $advancedFaParams['FetchQuarantinedFiles']      = Confirm-Action "Fetch quarantined files from host machines?" -Default $true
    $vChoice = Read-Choice -Prompt "Which VMRay verdicts should create indicators?" -Options @(
      "Malicious","Suspicious","Malicious & Suspicious") -Default 1
    $advancedFaParams['VmraySampleVerdict'] = @("Malicious","Suspicious","Malicious & Suspicious")[$vChoice-1]
    Write-Host ""
    $flt = Read-Host "  Filter - only process alerts whose title contains (comma-separated; blank = all alerts)"
    if (-not [string]::IsNullOrWhiteSpace($flt)) { $advancedFaParams['FilterAlertTitleWith'] = $flt }
  }

  Write-Host ""
  Write-Host "  About to deploy the Function App:" -ForegroundColor Yellow
  Write-Host "    Plan          : $FunctionPlan" -ForegroundColor White
  Write-Host "    Base name     : $FunctionName  (a 3-char hash is appended)" -ForegroundColor White
  Write-Host "    Resource group: $ResourceGroup" -ForegroundColor White
  Write-Host "    Region        : $Region" -ForegroundColor White
  Write-Host "    VMRay URL     : $VmrayBaseURL" -ForegroundColor White
  if (-not (Confirm-Action "Proceed with Function App deployment?")) { throw "Aborted by user." }

  # Safeguards for same-RG re-deploys (both no-ops on a fresh RG):
  #  - clear any stale storage role assignment that would collide
  #  - clear a leftover 'WaitSection' deployment script that can conflict
  Remove-StaleStorageRoleAssignment -ResourceGroup $ResourceGroup
  Remove-StaleDeploymentScript -ResourceGroup $ResourceGroup

  Write-Step "1/3" "Deploying ARM template (this can take several minutes)..."
  # Storage settings intentionally left blank here - the storage account is created
  # by THIS deployment, so its keys don't exist yet. We fill them in step 2/3.
  $faParams = @{
    AzureClientID                  = $appClientId
    AzureClientSecret              = $appClientSecret
    AzureTenantID                  = $tenantId
    AppInsightsWorkspaceResourceID = $AppInsightsWorkspaceResourceID
    VmrayBaseURL                   = $VmrayBaseURL
    VmrayAPIKey                    = $VmrayAPIKey
    VmrayResubmitAfter             = $VmrayResubmitAfter
  }
  # The Flex template's function-name parameter is 'FunctionName'; the Premium
  # template calls the same thing 'functionAppName'. Use the right key per plan.
  if ($FunctionPlan -eq "Premium") { $faParams['functionAppName'] = $FunctionName }
  else                             { $faParams['FunctionName']     = $FunctionName }
  # Overlay any advanced settings the operator chose.
  foreach ($k in $advancedFaParams.Keys) { $faParams[$k] = $advancedFaParams[$k] }
  # The template's storage role assignment references the Function App's freshly
  # created managed identity. On a re-deploy (resources already exist) ARM reaches the
  # role-assignment resource almost immediately, before the identity has replicated to
  # Entra ID, and fails with 'PrincipalNotFound / replication delay'. On a fresh RG the
  # minutes spent creating storage+plan+site give replication time, so it doesn't show.
  # We can't add principalType to the GitHub template, so we retry: by the next attempt
  # the identity has replicated and the assignment succeeds.
  $faDeployBase = "vmray-defender-func-$(Get-Date -Format 'yyyyMMddHHmmss')"
  $maxAttempts  = 3
  $faDeploy     = $null
  for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    try {
      $faDeploy = Invoke-ArmDeploy -DeploymentName "$faDeployBase-$attempt" -ResourceGroup $ResourceGroup `
                    -Parameters $faParams -TemplateUri $funcTemplateUri -TemplateFile $FunctionTemplateFile
      break
    } catch {
      $msg = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
      if ($msg -match "PrincipalNotFound|does not exist in the directory|replication delay" -and $attempt -lt $maxAttempts) {
        Write-Host "  Managed identity not yet replicated to Entra ID (attempt $attempt/$maxAttempts)." -ForegroundColor Yellow
        Write-Host "  Waiting 60s for replication, then retrying..." -ForegroundColor Yellow
        Start-Sleep -Seconds 60
        continue
      }
      throw
    }
  }
  if (-not $faDeploy -or $faDeploy.ProvisioningState -ne "Succeeded") {
    throw "Function App deployment finished with state '$($faDeploy.ProvisioningState)'."
  }
  Write-Host "  Function App deployment succeeded." -ForegroundColor Green

  Write-Step "2/3" "Auto-filling storage key settings (the README's manual step)..."
  $storageName = Select-CreatedResource -ResourceGroup $ResourceGroup -NamePrefix "vmraystorage" -Kind "Storage"
  $functionAppName = Select-CreatedResource -ResourceGroup $ResourceGroup -NamePrefix ($FunctionName.ToLower()) -Kind "Web"
  if (-not $storageName)     { throw "Could not locate the 'vmraystorage*' account created by the deployment." }
  if (-not $functionAppName) { throw "Could not locate the Function App created by the deployment." }
  Write-Host "  Storage account : $storageName" -ForegroundColor Gray
  Write-Host "  Function App    : $functionAppName" -ForegroundColor Gray

  $keys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroup -Name $storageName -ErrorAction Stop
  $primaryKey = $keys[0].Value
  $suffix = (Get-AzContext).Environment.StorageEndpointSuffix
  if ([string]::IsNullOrWhiteSpace($suffix)) { $suffix = "core.windows.net" }
  $connString = "DefaultEndpointsProtocol=https;AccountName=$storageName;AccountKey=$primaryKey;EndpointSuffix=$suffix"

  Update-AzFunctionAppSetting -Name $functionAppName -ResourceGroupName $ResourceGroup -AppSetting @{
    AzureStorageConnectionString = $connString
    AzureStorageAccountKey       = $primaryKey
  } -Force -ErrorAction Stop | Out-Null
  Write-Host "  AzureStorageConnectionString + AzureStorageAccountKey set." -ForegroundColor Green

  Write-Step "3/3" "Restarting the Function App..."
  Restart-AzFunctionApp -Name $functionAppName -ResourceGroupName $ResourceGroup -Force -ErrorAction Stop | Out-Null
  Write-Host "  Restarted." -ForegroundColor Green
}

# ===========================================================================
# PHASE 3 - Logic App
# ===========================================================================
$logicAppName = $null
$functionKey  = $null
if ($SkipLogicApp.IsPresent) {
  Write-Phase "3" "Logic App - SKIPPED (-SkipLogicApp)"
} else {
  Write-Phase "3" "Deploy Logic App"

  if (-not $LogicAppPlan) {
    $lpChoice = Read-Choice -Prompt "Which Logic App plan?" -Options @(
      "Consumption","Standard") -Default 1
    $LogicAppPlan = if ($lpChoice -eq 2) { "Standard" } else { "Consumption" }
  }

  if (-not $PlaybookNameWasPassed) {
    $PlaybookName = Read-Text -Prompt "Logic App name" -Default $PlaybookName
  }
  # Standard Logic Apps are Microsoft.Web/sites -> the name must be GLOBALLY unique.
  # Check up front and re-prompt so we fail fast instead of deep in the ARM deploy.
  if ($LogicAppPlan -eq "Standard") {
    while (-not (Test-WebSiteNameAvailable -Name $PlaybookName)) {
      Write-Host ""
      Write-Host "  '$PlaybookName' is already taken globally (must be unique across all of azurewebsites.net)." -ForegroundColor Yellow
      $PlaybookName = Read-Text -Prompt "Enter a different, globally-unique Logic App name"
    }
  }
  # If Phase 2 was skipped, FunctionName hasn't been resolved yet - prompt now so the
  # Logic App's function reference points at the right Function App.
  if (-not $FunctionNameWasPassed -and -not $script:FunctionNameResolved) {
    $FunctionName = Read-Text -Prompt "Function App base name (must match the deployed Function App)" -Default $FunctionName
    $script:FunctionNameResolved = $true
  }

  Write-Host ""
  Write-Host "  Logic App name  : $PlaybookName" -ForegroundColor White
  Write-Host "  Plan            : $LogicAppPlan" -ForegroundColor White
  Write-Host "  Resource group  : $ResourceGroup  (same as Function App)" -ForegroundColor White
  Write-Host "  Function base   : $FunctionName" -ForegroundColor White
  if (-not (Confirm-Action "Proceed with Logic App deployment?")) { throw "Aborted by user." }

  Write-Step "1/2" "Deploying ARM template..."
  $laDeployName = "vmray-defender-logic-$(Get-Date -Format 'yyyyMMddHHmmss')"
  if ($LogicAppPlan -eq "Standard") {
    if (-not $appClientId -or -not $appClientSecret) {
      throw "Standard Logic App needs the App Client ID + secret. Run Phase 1 or pass -AppId/-ClientSecret."
    }
    # The Standard template builds the function URL from this value WITHOUT adding a
    # uniqueness hash, so it must be the ACTUAL deployed Function App name (with hash),
    # not the base name. Prefer the name resolved in Phase 2; otherwise discover it.
    $actualFuncName = $functionAppName
    if (-not $actualFuncName) {
      $actualFuncName = Select-CreatedResource -ResourceGroup $ResourceGroup -NamePrefix ($FunctionName.ToLower()) -Kind "Web"
    }
    if (-not $actualFuncName) {
      Write-Host "  WARNING: couldn't determine the deployed Function App name - using base '$FunctionName'." -ForegroundColor Yellow
      Write-Host "  If the real name has a hash suffix, the Standard Logic App will point at the wrong URL." -ForegroundColor Yellow
      $actualFuncName = $FunctionName
    } else {
      Write-Host "  Wiring Standard Logic App to Function App: $actualFuncName" -ForegroundColor Gray
      # Carry the discovered name forward so the key fetch in step 2/2 works even when
      # Phase 2 was skipped in this run.
      if (-not $functionAppName) { $functionAppName = $actualFuncName }
    }
    $laParams = @{
      logicAppName      = $PlaybookName
      AzureClientID     = $appClientId
      AzureClientSecret = $appClientSecret
      AzureTenantID     = $tenantId
      FunctionName      = $actualFuncName
    }
    $laTemplateUri = $LogicStandardTemplateUri
  } else {
    $laParams = @{
      PlaybookName    = $PlaybookName
      FunctionAppName = $FunctionName
    }
    $laTemplateUri = $LogicConsumptionTemplateUri
  }
  $laDeploy = Invoke-ArmDeploy -DeploymentName $laDeployName -ResourceGroup $ResourceGroup `
                -Parameters $laParams -TemplateUri $laTemplateUri -TemplateFile $LogicTemplateFile
  if ($laDeploy.ProvisioningState -ne "Succeeded") {
    throw "Logic App deployment finished with state '$($laDeploy.ProvisioningState)'."
  }
  $logicAppName = $PlaybookName
  Write-Host "  Logic App deployment succeeded." -ForegroundColor Green

  Write-Step "2/2" "Wiring up connection values..."
  # Function key for the VMRayDefender function (Standard plan needs it baked into
  # app settings; Consumption resolves the function by ARM resource id and doesn't).
  if ($functionAppName) {
    $functionKey = Get-FunctionDefaultKey -ResourceGroup $ResourceGroup -FunctionAppName $functionAppName
    if ($functionKey) { Write-Host "  Retrieved VMRayDefender function key." -ForegroundColor Green }
    else { Write-Host "  Could not auto-retrieve the function key. Get it from the portal." -ForegroundColor Yellow }
  } else {
    Write-Host "  Function App name unknown in this run (Phase 2 skipped). Run all phases together," -ForegroundColor Yellow
    Write-Host "  or get the key from the portal (Function App > Functions > VMRayDefender > Function Keys)." -ForegroundColor Yellow
  }

  # Standard plan: the wdatp credentials in connections.json are @appsetting() refs, so
  # filling these app settings satisfies them. The OTHER connections.json values are
  # literal placeholders (not app-setting refs) - those still need a JSON-View edit,
  # which we can't do from the management plane. We set the credentials here and print
  # the exact values to paste for the remaining placeholders.
  if ($LogicAppPlan -eq "Standard") {
    Write-Host "  Populating Standard Logic App credential settings..." -ForegroundColor Gray
    try {
      $plainSecret = [System.Net.NetworkCredential]::new("", $appClientSecret).Password
      $stdSettings = @{
        AzureClientID     = $appClientId
        AzureClientSecret = $plainSecret
        AzureTenantID     = $tenantId
      }
      if ($functionKey) { $stdSettings['azureFunctionOperation_functionKey'] = $functionKey }
      try {
        $conn = Get-AzResource -ResourceGroupName $ResourceGroup -ResourceType "Microsoft.Web/connections" `
                  -ResourceName "wdatp" -ApiVersion "2016-06-01" -ExpandProperties -ErrorAction Stop
        if ($conn.Properties.connectionRuntimeUrl) { $stdSettings['wdatp_connectionRuntimeUrl'] = $conn.Properties.connectionRuntimeUrl }
      } catch { }
      Set-AppSettingsMerged -ResourceGroup $ResourceGroup -SiteName $PlaybookName -NewSettings $stdSettings
      Write-Host "  Credential app settings set (AzureClientID / AzureClientSecret / AzureTenantID)." -ForegroundColor Green
      try { Restart-AzWebApp -Name $PlaybookName -ResourceGroupName $ResourceGroup -ErrorAction Stop | Out-Null } catch { }
    } catch {
      Write-Host "  Could not set credential app settings: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # connections.json (Workflow > Connections > JSON View) still has literal placeholders.
    $rgLocation = try { (Get-AzResourceGroup -Name $ResourceGroup -ErrorAction Stop).Location } catch { $Region }
    $keyDisplay = if ($functionKey) { $functionKey } else { "(get from Function App > Functions > VMRayDefender > Function Keys)" }
    Write-Host ""
    Write-Host "  ACTION - open the Logic App > Workflow > Connections > JSON View and replace" -ForegroundColor Yellow
    Write-Host "  these literal placeholders (credentials already come from app settings):" -ForegroundColor Yellow
    Write-Host "    <sub_id>            = $((Get-AzContext).Subscription.Id)" -ForegroundColor White
    Write-Host "    <resourceGroupName> = $ResourceGroup" -ForegroundColor White
    Write-Host "    <location>          = $rgLocation" -ForegroundColor White
    Write-Host "    <function_name>     = $functionAppName" -ForegroundColor White
    Write-Host "    <Function Key>      = $keyDisplay" -ForegroundColor White
  }
}

# ===========================================================================
# FINAL SUMMARY
# ===========================================================================
Write-Banner "Deployment summary"

Write-Host ""
Write-Host "  Tenant ID       : $tenantId" -ForegroundColor White
if ($appClientId)     { Write-Host "  App Client ID   : $appClientId" -ForegroundColor White }
if ($functionAppName) { Write-Host "  Function App    : $functionAppName" -ForegroundColor White }
if ($logicAppName)    { Write-Host "  Logic App       : $logicAppName ($LogicAppPlan)" -ForegroundColor White }
if ($functionKey)     { Write-Host "  Function key    : $functionKey" -ForegroundColor White }

if ($consentDeferred -and $deferredConsentUrl) {
  Write-Host ""
  Write-Host "  !! ADMIN CONSENT NOT FULLY GRANTED !!" -ForegroundColor Red
  Write-Host "  Forward this URL to a Global Administrator:" -ForegroundColor Yellow
  Write-Host "    $deferredConsentUrl" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "  REMAINING MANUAL STEPS:" -ForegroundColor Yellow
Write-Host "  ----------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "  1. Defender Advanced Features + Intune settings (see Phase 1 checklist)." -ForegroundColor Yellow
if ($logicAppName) {
  if ($LogicAppPlan -eq "Consumption") {
    Write-Host "  2. Logic App connection authorization (Consumption):" -ForegroundColor Yellow
    Write-Host "     - Open Logic App '$logicAppName' > Edit (designer)." -ForegroundColor Yellow
    Write-Host "     - On the WDATP connection, set Authentication = Service principal" -ForegroundColor Yellow
    Write-Host "       Client ID = $appClientId" -ForegroundColor Yellow
    Write-Host "       Tenant ID = $tenantId" -ForegroundColor Yellow
    Write-Host "       Client secret = (the secret printed in Phase 1)" -ForegroundColor Yellow
    Write-Host "     - On 'Alerts - Get single alert', click Change connection -> select it." -ForegroundColor Yellow
    Write-Host "     - Save." -ForegroundColor Yellow
  } else {
    Write-Host "  2. Logic App connection wiring (Standard):" -ForegroundColor Yellow
    Write-Host "     - Credentials (Client ID/secret/tenant) were set via app settings." -ForegroundColor Yellow
    Write-Host "     - Edit Workflow > Connections > JSON View and replace the literal" -ForegroundColor Yellow
    Write-Host "       placeholders with the values printed in Phase 3 (<sub_id>," -ForegroundColor Yellow
    Write-Host "       <resourceGroupName>, <location>, <function_name>, <Function Key>). Save." -ForegroundColor Yellow
    Write-Host "     - Authorize the wdatp API connection" -ForegroundColor Yellow
    Write-Host "       (wdatp connection > General > Edit API Connection > Authorize > Save)." -ForegroundColor Yellow
  }
}
Write-Host ""
Write-Host "===========================================================================" -ForegroundColor Magenta
