#Requires -Version 7.0
param (
    [Parameter(Mandatory=$true,ParameterSetName='byFile')][ValidateScript({ Test-Path $_ -PathType Leaf <# Saves some time for later #>})][string]$Path,
    [Parameter(Mandatory=$true,ParameterSetName='byList')][string[]]$TenantIds
)

# Connect to MsGraph - requires consent if not previously granted
Connect-MgGraph -Scopes CrossTenantInformation.ReadBasic.All -ContextScope Process

# Import the list of tenants if a file is specified (no processing if a list is provided)
switch ($parameterSetName) {
    'byFile' {
        try {
            $TenantIds = Import-Csv -Path $Path | Select-Object -ExpandProperty TenantId
        }
        catch {
            $TenantIds = Get-Content -Path $Path
        }
    }
    Default {}
}
$out = @()

# Get the tenant details
foreach ($tenantId in $TenantIds) {
    $out += Invoke-MgGraphRequest -Method Get -Uri "beta/tenantRelationships/findTenantInformationByTenantId(tenantId='$tenantId')" -OutputType PSObject | 
            Select-Object tenantId,displayName,defaultDomainName
}

# Output the results
$out | Export-Csv -Path "$PSScriptRoot\tenants_result.csv" -NoTypeInformation