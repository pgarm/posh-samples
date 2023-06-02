<# LIST OUT ALL THE SERVICE PRINCIPALS WITH AAD GRAPH PERMISSIONS
    This script will list out all the service principals with AAD Graph permissions in the tenant.
    The script will also list out the permissions as Delegated or Application permissions.
    The output will be exported to a CSV file.
#>

[CmdletBinding()]
param (
    [string]$TenantId = 'pgarmcdx.onmicrosoft.com' # Tenant ID as GUID or starter domain name
)

#Helper function to expand nested objects
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

$inhouse = @( # Add your own tenant IDs here if you use additional tenants to host application objects

)

$trash = @('openid', 'profile', 'offline_access', '') # List of permissions to ignore

# Connect to MGGraph with Application.Read.All, Directory.Read.All scope
Connect-MgGraph -Scopes Application.Read.All, Directory.Read.All -ContextScope Process -TenantId $TenantId
Select-MgProfile beta
$inhouse += (Get-MgContext).TenantId # Add the current tenant ID to the list of tenants to consider in-house

# Get the SP objects for AAD Graph amd Microsoft Graph from the tenant
$ApiObjects = @{
    AadGraph = Get-MgServicePrincipal -Filter "appid eq '00000002-0000-0000-c000-000000000000'"
    MsGraph  = Get-MgServicePrincipal -Filter "appid eq '00000003-0000-0000-c000-000000000000'"
}

# The following two calls are long-running on large tenants
# Get list of all App Registrations in the tenant that have AAD Graph permissions (can't filter on the OData query efficiently)
$Applications = Get-MgApplication -All -Property Id, DisplayName,AppId,RequiredResourceAccess | Where-Object { $_.RequiredResourceAccess.ResourceAppId -contains $APIobjects.AadGraph.AppId } | Select-Object Id, DisplayName, AppId, RequiredResourceAccess
# Get the list of all the service principals (as we can't pull permissions from graph directly in one call)
$ServicePrincipals = Get-MgServicePrincipal -All

$Output = @(); $i = 0
foreach ($sp in $serviceprincipals) {
    $i++
    Write-Progress -Activity "Getting Service Principal consented permissions..." -Status "$i/$($servicePrincipals.Count) - $($sp.DisplayName)" -percentComplete (($i / $servicePrincipals.Count) * 100)

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
        $obj.AppProxy = (Get-MgApplication -ApplicationId ($Applications | Where-Object {$_.AppId -eq $sp.AppId}).Id -Property OnPremisesPublishing).OnPremisesPublishing.ExternalUrl
        Remove-Variable ManifestPermissions -ErrorAction SilentlyContinue
    }
    else {
        $obj.AppRegistration = $false
        $obj.RequestedAadRoles = ''
        $obj.RequestedAadScopes = ''
        $obj.RequestedMsgRoles = ''
        $obj.RequestedMsgScopes = ''
        $obj.AppProxy = $false
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
    if ($obj.ApplicationAadRoles -or $obj.DelegatedAadScopes -or $obj.RequestedAadRoles -or $obj.RequestedAadScopes) {
        $Output += [PsCustomObject]$obj | Select-Object DisplayName,ServicePrincipalId,AppId,Owner,AppRegistration,AppProxy,`
            RequestedAadRoles,ApplicationAadRoles,RequestedAadScopes,DelegatedAadScopes,`
            RequestedMsgRoles,ApplicationMsgRoles,RequestedMsgScopes,DelegatedMsgScopes
    }
}

$Output | Export-Csv -Path ".\AADGraphPermissions.csv" -NoTypeInformation
