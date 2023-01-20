[CmdletBinding()]
param (
    # Use to update UPNs for members of selected group only. If not specified, will go for all synced accounts
    [String]$Group,
    [String]$Tenant = '',
    [String]$newUPNSuffix = ''
)

function Remove-Diacritics {
    param ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
}

# Connect to Azure AD (Tenant ID as GUID or .onmicrosoft.com domain)
Connect-AzureAD -TenantId $Tenant

# Get all members of the group if needed
if ($Group) {
    try {
        $groupobj = Get-AzureADGroup -SearchString $Group
    }
    catch {
        Write-Host -ForegroundColor Red "Couldn't retrieve the group specified:`n$_"
        exit 1
    }
    $members = Get-AzureADGroupMember -ObjectId $groupobj.ObjectId -All:$true
}
else {
    $members = Get-AzureADUser -Filter 'dirsyncEnabled eq true' -All
}

# Create an empty array to store the UPN change information
$UPNChanges = @()
$UPNfails = @()

# Iterate through each member
foreach ($member in $members) {
    # Create the new UPN
    $newUPN = "$((Remove-Diacritics $member.GivenName).toLower() -replace "[\W_ ']+", '').$((Remove-Diacritics $member.Surname).toLower() -replace "[\W_ ']+", '')@$newUPNSuffix"

    try {
        # Update the user's UPN
        Set-AzureADUser -ObjectId $member.ObjectId -UserPrincipalName $newUPN -ErrorAction Stop

        # Log the UPN change in the array
        $UPNChanges += [PSCustomObject]@{
            'CurrentUPN' = $member.UserPrincipalName
            'NewUPN'     = $newUPN
        }
    }
    catch {
        # If it fails, write it on the screen
        Write-Host -ForegroundColor Red "Could not set UPN for user $($member.ObjectId) to $newUPN`:`n$_"
        $UPNfails += [PSCustomObject]@{
            'CurrentUPN' = $member.UserPrincipalName
            'NewUPN'     = $newUPN
        }
    }
    finally {
        #garbage collect
        Remove-Variable newUPN, member
    }
}

# Export the UPN changes to a CSV file
$UPNChanges | Export-Csv -Path ".\UPNChanges_$(Get-Date -Format 'yyMMdd-HHmmss').csv" -NoTypeInformation
$UPNfails | Export-Csv -Path ".\UPNFails_$(Get-Date -Format 'yyMMdd-HHmmss').csv" -NoTypeInformation
