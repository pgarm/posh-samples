<# LIST OUT ALL THE SERVICE PRINCIPALS WITH AAD GRAPH PERMISSIONS
    This script will list out all the service principals with AAD Graph permissions in the tenant.
    The script will also list out the permissions as Delegated or Application permissions, and optionally sign-in activity from LogAnalytics workspace.
    The output will be exported to a CSV file.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)][string]$TenantId, # Tenant ID as GUID or starter domain name
    [string]$WorkspaceName, # Log Analytics Workspace name to retrieve activity logs from. If not specified, the script will not attempt to retrieve activity logs. You can get the workspace name from https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/DiagnosticSettings
    [string]$SubscriptionId, # Subscription ID to use for Log Analytics workspace. If not specified, the script will use iterate through subscriptions available to the user and attempt to find the workspace.
    [string[]]$InHouse = @() # Add your own tenant IDs here if you use additional tenants to host application objects
)

if ($Verbose.IsPresent) {
    $VerboseStashed = $VerbosePreference
    $VerbosePreference = 'Continue'
}

# Helper function to expand nested objects
function Expand-ObjectProperties {
    param
    (
        [Parameter(
            Mandatory = $true, 
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )][psobject]$InputObject
        , [Parameter(
            ValueFromPipelineByPropertyName = $true
        )][string[]]$Properties
        , [Parameter(
            ValueFromPipelineByPropertyName = $true
        )][string]$ExpandProperty
    )
    process {
        foreach ($item in $InputObject) {
            foreach ($prop in ($item | Select-Object -ExpandProperty $ExpandProperty)) {
                if ($prop -is [PSCustomObject]) {
                    $work = $item | Select-Object $Properties
                    foreach ($subprop in $prop.psobject.properties) {
                        $work | Add-Member -MemberType NoteProperty -Name $subprop.Name -Value $subprop.Value
                    }
                    $work
                }
                else {
                    $item | Select-Object $Properties | Select-Object *, @{Name = "$ExpandProperty"; Expression = { $prop } }
                }
            }
        }
    }
}

# Define first-party owner tenantIDs
$firstparty = @(
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a',
    '72f988bf-86f1-41af-91ab-2d7cd011db47'
)

# List of permissions to ignore
$trash = @('openid', 'profile', 'offline_access', '')

# Define Log Analytics query to pull sign-in activity for apps
$Query = @"
SigninLogs
| where TimeGenerated > ago (30d) and ResourceIdentity == '00000002-0000-0000-c000-000000000000'
| summarize count() by AppDisplayName,AppId,UserId
| summarize ActiveUsers = count(UserId), TotalSignIns = sum (count_) by AppDisplayName,AppId
"@

# Connect to MGGraph with Application.Read.All, Directory.Read.All scope
Connect-MgGraph -Scopes Application.Read.All, Directory.Read.All -ContextScope Process -TenantId $TenantId
Select-MgProfile beta
$inhouse += (Get-MgContext).TenantId # Add the current tenant ID to the list of tenants to consider in-house

# Connect to AzAccount if a workspace name is specified and module is available, and get the workspace object if it exists
if ($WorkspaceName -and (Get-Module -ListAvailable Az.Accounts).Count -gt 0) {
    try {
        Write-Progress -Activity "Initializing" -Status "Connecting to Azure RM" -PercentComplete 0 -Id 1
        Write-Verbose "Connecting to Azure RM $((Get-MgContext).Account) $((Get-MgContext).TenantId)"
        Connect-AzAccount -AccountId (Get-MgContext).Account -TenantId $TenantId | Out-Null
        $Subscriptions = Get-AzSubscription
    }
    catch {
        Write-Warning "Unable to connect to Azure RM. Activity logs will not be retrieved."
    }
}

# Try to find the Log Analytics workspace in the subscription specified, or in any of the subscriptions available to the user
Write-Progress -Activity "Initializing" -Status "Retrieving Log Analytics workspace" -PercentComplete 0 -Id 1
if ($SubscriptionId -in $Subscriptions.Id) {
    Write-Progress -Activity "Retrieving Log Analytics configuration" -Status "Trying subscription $SubscriptionId" -PercentComplete 0 -Id 2 -ParentId 1
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    $Workspace = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $WorkspaceName }
}
if (!$Workspace) {
    $s=0
    foreach ($sub in $Subscriptions) {
        Write-Progress -Activity "Retrieving Log Analytics configuration" -Status "Trying subscription $SubscriptionId" -PercentComplete (($s++)*100/$Subscriptions.Count) -Id 2 -ParentId 1
        Set-AzContext -SubscriptionId $sub.Id | Out-Null
        $Workspace = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $WorkspaceName }
        if ($Workspace) {
            Write-Verbose "Found workspace $($Workspace.Name) in subscription $($sub.Name)"
            break
        }
    }
}
Write-Progress -Activity "Retrieving Log Analytics configuration" -Completed -Id 2 -ParentId 1

# If the workspace is found, try to retrieve the activity logs
if ($Workspace) {
    try {
        Write-Progress -Activity "Retrieving activity logs" -Status "Retrieving activity logs from LogAnalytics" -PercentComplete 0 -Id 3 -ParentId 1
        $ActivityLogs = (Invoke-AzOperationalInsightsQuery -Workspace $Workspace -Query $Query).Results
    }
    catch {
        Write-Warning "Unable to retrieve activity logs from LogAnalytics. Activity logs will be omitted on the report."
    }
    Write-Progress -Activity "Retrieving activity logs" -Completed -Id 3 -ParentId 1
}
else {
    Write-Warning "Unable to find workspace $WorkspaceName in any of the subscriptions in the tenant, or you don't have access to it. Activity logs will not be retrieved."
}

# Get the SP objects for AAD Graph amd Microsoft Graph from the tenant
$ApiObjects = @{
    AadGraph = Get-MgServicePrincipal -Filter "appid eq '00000002-0000-0000-c000-000000000000'"
    MsGraph  = Get-MgServicePrincipal -Filter "appid eq '00000003-0000-0000-c000-000000000000'"
}

# The following two calls are long-running on large tenants
# Get list of all App Registrations in the tenant that have AAD Graph permissions (can't filter on the OData query efficiently)
Write-Progress -Activity "Initializing" -Status "Getting App Registrations" -PercentComplete 0 -Id 1
$Applications = Get-MgApplication -All -Property Id, DisplayName, AppId, RequiredResourceAccess | Where-Object { $_.RequiredResourceAccess.ResourceAppId -contains $APIobjects.AadGraph.AppId } | Select-Object Id, DisplayName, AppId, RequiredResourceAccess
# Get the list of all the service principals (as we can't pull permissions from graph directly in one call)
Write-Progress -Activity "Initializing" -Status "Getting Service Principals" -PercentComplete 0 -Id 1
$ServicePrincipals = Get-MgServicePrincipal -All

$Output = @(); $i = 0; $StartTime = Get-Date

if ($ActivityLogs.AppId -contains '1b730954-1685-4b74-9bfd-dac224a7b894') {
    $Output += [PsCustomObject]@{
        DisplayName = 'Azure Active Directory PowerShell'
        ServicePrincipalId = ''
        AppId = '1b730954-1685-4b74-9bfd-dac224a7b894'
        Owner = 'First-party'
        AppRegistration = $false
        AppProxy = ''
        RequestedAadRoles = ''
        ApplicationAadRoles = ''
        RequestedAadScopes = ''
        DelegatedAadScopes = ''
        RequestedMsgRoles = ''
        ApplicationMsgRoles = ''
        RequestedMsgScopes = ''
        DelegatedMsgScopes = ''
        ActiveAadUsers = ($ActivityLogs | Where-Object { $_.AppId -eq '1b730954-1685-4b74-9bfd-dac224a7b894'}).ActiveUsers
        TotalAadSignIns = ($ActivityLogs | Where-Object { $_.AppId -eq '1b730954-1685-4b74-9bfd-dac224a7b894'}).TotalSignIns
    }
}

# Loop through all the applications to find which ones have AAD Graph permissions
foreach ($sp in $serviceprincipals) {
    $i++
    Write-Progress -Activity "Getting Service Principal consented permissions..." -Status "$i/$($servicePrincipals.Count) - $($sp.DisplayName)" -percentComplete (($i / $servicePrincipals.Count) * 100) -Id 1 -SecondsRemaining (((Get-Date) - $StartTime).TotalSeconds*($servicePrincipals.Count-$i)/$i)

    $obj = @{
        DisplayName        = $sp.DisplayName
        ServicePrincipalId = $sp.Id
        AppId              = $sp.AppId
    }

    switch ($sp.AppOwnerOrganizationId) {
        # Deterine if the app is first-party, in-house, or third-party
        { $firstparty -contains $_ } { $obj.Owner = 'First-party' }
        { $inhouse -contains $_ } { $obj.Owner = 'In-house' }
        Default { $obj.Owner = 'Third-party' }
    }

    if ($sp.appid -in $applications.appid) {
        # Determine if the SP has an App Registration in the tenant and get permissions from the manifest
        $obj.AppRegistration = $true
        $ManifestPermissions = ($applications | Where-Object { $_.AppId -eq $sp.AppId }).RequiredResourceAccess | 
        Where-Object { $_.ResourceAppId -in $ApiObjects.Values.AppId } | 
        Expand-ObjectProperties -Properties ResourceAppId -ExpandProperty ResourceAccess | 
        Select-Object ResourceAppId, Id, Type
        foreach ($perm in $ManifestPermissions) {
            # Add-Member -InputObject $perm -NotePropertyName ResourceDisplayName -NotePropertyValue ($ApiObjects.Values | Where-Object { $_.AppId -eq $perm.ResourceAppId }).DisplayName
            switch ($perm.Type) {
                'Scope' { Add-Member -InputObject $perm -NotePropertyName PermissionName -NotePropertyValue ($ApiObjects.Values.PublishedPermissionScopes | Where-Object { $_.Id -eq $perm.Id }).Value }
                'Role' { Add-Member -InputObject $perm -NotePropertyName PermissionName -NotePropertyValue ($ApiObjects.Values.AppRoles | Where-Object { $_.Id -eq $perm.Id }).Value }
            }
        }
        $obj.RequestedAadRoles = ($ManifestPermissions | Where-Object { $_.ResourceAppId -eq $ApiObjects.AadGraph.AppId -and $_.Type -eq 'Role' } | Select-Object -ExpandProperty PermissionName -Unique) -join ','
        $obj.RequestedAadScopes = ($ManifestPermissions | Where-Object { $_.ResourceAppId -eq $ApiObjects.AadGraph.AppId -and $_.Type -eq 'Scope' } | Select-Object -ExpandProperty PermissionName -Unique) -join ','
        $obj.RequestedMsgRoles = ($ManifestPermissions | Where-Object { $_.ResourceAppId -eq $ApiObjects.MsGraph.AppId -and $_.Type -eq 'Role' } | Select-Object -ExpandProperty PermissionName -Unique) -join ','
        $obj.RequestedMsgScopes = ($ManifestPermissions | Where-Object { $_.ResourceAppId -eq $ApiObjects.MsGraph.AppId -and $_.Type -eq 'Scope' } | Select-Object -ExpandProperty PermissionName -Unique) -join ','
        try {
            $obj.AppProxy = (Get-MgApplication -ApplicationId ($Applications | Where-Object { $_.AppId -eq $sp.AppId }).Id -Property OnPremisesPublishing).OnPremisesPublishing.ExternalUrl
        }
        catch { $obj.AppProxy = '' }
        Remove-Variable ManifestPermissions -ErrorAction SilentlyContinue
    }
    else {
        $obj.AppRegistration = $false
        $obj.RequestedAadRoles = ''
        $obj.RequestedAadScopes = ''
        $obj.RequestedMsgRoles = ''
        $obj.RequestedMsgScopes = ''
        $obj.AppProxy = ''
    }

    # Get the list of delegated permissions granted to the SP
    $DelegatedPermissions = Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $sp.Id | 
    Where-Object { $_.ResourceId -in $ApiObjects.Values.Id } | 
    Select-Object ResourceId, Scope
    if ($DelegatedPermissions) {
        if ($DelegatedPermissions.ResourceId -contains $ApiObjects.AadGraph.Id) {
            $obj.DelegatedAadScopes = (($DelegatedPermissions | Where-Object { $_.ResourceId -eq $ApiObjects.AadGraph.Id }).Scope.Split(' ') | Where-Object { $_ -notin $trash } | Select-Object -Unique) -join ','
        }
        else {
            $obj.DelegatedAadScopes = ''
        }
        if ($DelegatedPermissions.ResourceId -contains $ApiObjects.MsGraph.Id) {
            $obj.DelegatedMsgScopes = (($DelegatedPermissions | Where-Object { $_.ResourceId -eq $ApiObjects.MsGraph.Id }).Scope.Split(' ') | Where-Object { $_ -notin $trash } | Select-Object -Unique) -join ','
        }
        else {
            $obj.DelegatedMsgScopes = ''
        }
    }
    else {
        $obj.DelegatedAadScopes = ''
        $obj.DelegatedMsgScopes = ''
    }
    Remove-Variable DelegatedPermissions -ErrorAction SilentlyContinue

    # Get the list of application permissions granted to the SP
    $ApplicationPermissions = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.id | 
    Where-Object { $_.ResourceId -in $ApiObjects.Values.Id } | 
    Select-Object ResourceId, AppRoleId
    if ($ApplicationPermissions) {
        foreach ($perm in $ApplicationPermissions) {
            switch ($perm.ResourceId) {
                $ApiObjects.AadGraph.Id { Add-Member -InputObject $perm -NotePropertyName PermissionName -NotePropertyValue ($ApiObjects.AadGraph.AppRoles | Where-Object { $_.Id -eq $perm.AppRoleId }).Value }
                $ApiObjects.MsGraph.Id { Add-Member -InputObject $perm -NotePropertyName PermissionName -NotePropertyValue ($ApiObjects.MsGraph.AppRoles | Where-Object { $_.Id -eq $perm.AppRoleId }).Value }
            }
        }
        if ($ApplicationPermissions.ResourceId -contains $ApiObjects.AadGraph.Id) {
            $obj.ApplicationAadRoles = ($ApplicationPermissions | Where-Object { $_.ResourceId -eq $ApiObjects.AadGraph.Id } | Select-Object -ExpandProperty PermissionName -Unique) -join ','
        }
        else {
            $obj.ApplicationAadRoles = ''
        }
        if ($ApplicationPermissions.ResourceId -contains $ApiObjects.MsGraph.Id) {
            $obj.ApplicationMsgRoles = ($ApplicationPermissions | Where-Object { $_.ResourceId -eq $ApiObjects.MsGraph.Id } | Select-Object -ExpandProperty PermissionName -Unique) -join ','
        }
        else {
            $obj.ApplicationMsgRoles = ''
        }
    }
    else {
        $obj.ApplicationAadRoles = ''
        $obj.ApplicationMsgRoles = ''
    }
    Remove-Variable ApplicationPermissions -ErrorAction SilentlyContinue

    # Add ativity data to the object
    if ($obj.AppId -in $ActivityLogs.AppId) {
        $obj.ActiveAadUsers = ($ActivityLogs | Where-Object { $_.AppId -eq $obj.AppId}).ActiveUsers
        $obj.TotalAadSignIns = ($ActivityLogs | Where-Object { $_.AppId -eq $obj.AppId}).TotalSignIns
    }
    elseif ($ActivityLogs) {
        $obj.ActiveAadUsers = ''
        $obj.TotalAadSignIns = ''
    }

    # Add the object to the output array if it has any permissions
    if ($obj.ApplicationAadRoles -or $obj.DelegatedAadScopes -or $obj.RequestedAadRoles -or $obj.RequestedAadScopes) {
        $Output += [PsCustomObject]$obj | Select-Object DisplayName, ServicePrincipalId, AppId, Owner, AppRegistration, AppProxy, `
            RequestedAadRoles, ApplicationAadRoles, RequestedAadScopes, DelegatedAadScopes, `
            RequestedMsgRoles, ApplicationMsgRoles, RequestedMsgScopes, DelegatedMsgScopes
    }
}

try {
    $Output | Export-Csv -Path ".\AADGraphPermissions.csv" -NoTypeInformation
    Write-Host "Exported the CSV to .\AADGraphPermissions.csv"
}
catch {
    Write-Host "Failed to export file"
}

$VerbosePreference = $VerboseStashed