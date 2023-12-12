#Requires -Version 7.0
param (
    [Parameter(Mandatory = $true)][ValidateScript({ Test-Path $_ -PathType Leaf })][string]$Path
)

# Connect to MsGraph - requires consent if not previously granted
Connect-MgGraph -Scopes CrossTenantInformation.ReadBasic.All -ContextScope Process

# Import the list of tenants if a file is specified (no processing if a list is provided)
$TenantIds = Get-Content -Path $Path
$out = @()

# Get the tenant details
foreach ($tenantId in $TenantIds) {
    $out += Invoke-MgGraphRequest -Method Get -Uri "beta/tenantRelationships/findTenantInformationByTenantId(tenantId='$tenantId')" -OutputType PSObject | 
    Select-Object tenantId, displayName, defaultDomainName
}

# Output the results
$out | Export-Csv -Path "$PSScriptRoot\tenants_result.csv" -NoTypeInformation