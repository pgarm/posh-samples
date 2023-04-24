#################################################################################
#DISCLAIMER: This is not an official PowerShell Script. We designed it specifically for the situation you have encountered right now.
#Please do not modify or change any preset parameters. 
#Please note that we will not be able to support the script if it is changed or altered in any way or used in a different situation for other means.

#This code-sample is provided "AS IT IS" without warranty of any kind, either expressed or implied, including but not limited to the implied warranties of merchantability and/or fitness for a particular purpose.
#This sample is not supported under any Microsoft standard support program or service.. 
#Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. 
#The entire risk arising out of the use or performance of the sample and documentation remains with you. 
#In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the script be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of  the use of or inability to use the sample or documentation, even if Microsoft has been advised of the possibility of such damages.
#################################################################################

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)][String]$TenantId, # Can be GUID or .onmicrosoft.com domain name
    [Parameter(Mandatory = $true)][String]$Server     # Can be on-prem server name or connector object GUID
)

# Connect to MsGraph
$ConnectionProfile = @{
    TenantId = $TenantId
    Scopes   = @('Application.Read.All')
}
Connect-MgGraph @ConnectionProfile
Select-MgProfile -Name beta

#Determine if the server was supplied as name or GUID and retrieve Connector object, associated Connector Group object
try {
    if ($server -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$') {
        $ConnectorObject = Get-MgOnPremisePublishingProfileConnector -ConnectorId ([GUID]$Server).Guid -OnPremisesPublishingProfileId applicationProxy -ExpandProperty MemberOf
    }
    else {
        $ConnectorObject = Get-MgOnPremisePublishingProfileConnector -OnPremisesPublishingProfileId applicationProxy -ExpandProperty MemberOf -Filter "machineName eq '$Server'"
        switch ($ConnectorObject.Count) {
            0 {
                Write-Host -ForegroundColor Red "No connector object found with name $Server, terminating"
                exit 404
            }
            1 { 
                Write-Host "Found connector object $Server ($($ConnectorObject.Id)),`n       member of group $($ConnectorObject.MemberOf.Name) ($($ConnectorObject.MemberOf.Id))"
            }
            Default {
                Write-Host -ForegroundColor Yellow "$($ConnectorObject.Count) connector objects found with name $Server"
                switch (($ConnectorObject | Where-Object { $_.Status -eq 'active' }).count) {
                    1 {
                        $ConnectorObject = $ConnectorObject | Where-Object { $_.Status -eq 'active' }
                        Write-Host "Selected only active object $($ConnectorObject.Id), member of group $($ConnectorObject.MemberOf.Id) named $($ConnectorObject.MemberOf.Name)"
                    }
                    Default {
                        Write-Host "Couldn't select single instance of connector object from the available ones.`nPlease re-run specifying GUID form the list below instead of server name:"
                        $ConnectorObject | Format-Table Id, Status
                        exit 300
                    }
                }
            }
        }
    }
}
catch {
    Write-Host -ForegroundColor "Error retrieving connector object from Graph:`n$_.Message"
    Exit 400
}

# Retrieve connector group object
$ConnectorGroup = Get-MgOnPremisePublishingProfileConnectorgroup -OnPremisesPublishingProfileId applicationProxy -ExpandProperty Applications, Members -Filter "id eq '$($ConnectorObject.MemberOf.Id)'"
Write-Host "Connector group $($ConnectorObject.MemberOf.Name) ($($ConnectorObject.MemberOf.Id)) has $($ConnectorGroup.Members.Count) connectors in it:"
$ConnectorGroup.Members | Format-Table
Write-Host ""

# Retrieve Applications that have Kerberos SingleSignOn configured, then filter locally (as expand+filter isn't supported yet), and enrich the ConnectorGroup with extra properties
<#
    > Get-MgApplication -Property id, AppId, DisplayName, onPremisesPublishing -ExpandProperty connectorGroup -Filter "connectorGroup/id eq '$ConnectorObject.MemberOf.Id'"
    Get-MgApplication_List: $select across multiple workloads along with $expand acoss multiple workloads isn't supported yet.
#>
$ConnectorGroup.Applications = Get-MgApplication -Property id, AppId, DisplayName, onPremisesPublishing -Filter "onPremisesPublishing/singleSignOnSettings/singleSignOnMode eq 'onPremisesKerberos'" -All | 
Where-Object { $_.Id -in $ConnectorGroup.Applications.Id }
$outApplications = $ConnectorGroup.Applications | Select-Object AppId, DisplayName, `
    @{l = 'InternalUrl'; e = { $_.OnPremisesPublishing.InternalUrl } }, `
    @{l = 'KerberosServicePrincipalName'; e = { $_.OnPremisesPublishing.SingleSignOnSettings.KerberosSignOnSettings.KerberosServicePrincipalName } }

# Format output and export to file
Write-Host "Connector group has $($ConnectorGroup.Applications.Count) applications published with Kerberos authentication:"
$Path = ".\$(($ConnectorGroup.Id -split '-')[0])_$(Get-Date -Format 'yyyyMMdd')_applist.csv"
Write-Host "Exporting Kerberos settings to $Path"
$outApplications | Export-Csv -Path $Path -NoTypeInformation


# Source / credit:
# https://social.technet.microsoft.com/wiki/contents/articles/18996.active-directory-powershell-script-to-list-all-spns-used.aspx
# You can use the block below as separate script and populate this with the SPNs found in output from the exported file above
# This will list all objects that have the SPN configured, and their type (user, group, computer, etc.)
$spnlist = $outApplications.KerberosServicePrincipalName | Select-Object -Unique
$OutList = @()
try {
    $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $SearcherObject = $ForestObject.FindGlobalCatalog().GetDirectorySearcher()
}
# catch ActiveDirectoryOperationException
catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException] {
    Write-Host -ForegroundColor Red "Error connecting to Active Directory: `n$($_.Exception.Message)"
    exit 500
}
if ($spnlist.Count -eq 0) {
    Write-Host "No SPNs found in the list, terminating"
    exit 0
}
foreach ($spn in $spnlist) {
    $SearcherObject.filter = "(servicePrincipalName=$spn)"
    $SearchResult = $SearcherObject.Findall()
    Write-Host "Found $($SearchResult.count) principal(s) with SPN '$spn': $($SearchResult.Properties.name -join ',')"
    foreach ($obj in $SearchResult) {
        $OutList += $obj | Select-Object `
            @{l = 'SPN'; e = { $spn } }, `
            @{l = 'Type'; e = { $_.Properties.objectcategory -replace '^CN=([a-zA-Z\-]+),.*$', '$1' } }, `
            @{l = "Name"; e = { $_.Properties.name } }, `
            @{l = "DistinguishedName"; e = { $_.Properties.distinguishedname } }
    }
    Remove-Variable SearchResult
}
$SearcherObject.Dispose()
if ($OutList.Count -gt 0) {
    $Path = ".\$(($ConnectorGroup.Id -split '-')[0])_$(Get-Date -Format 'yyyyMMdd')_ownlist.csv"
    Write-Host "Exporting SPN owners to $Path"
    $OutList | Export-Csv -Path $Path -NoTypeInformation
}
else {
    Write-Host "No SPN owners found"
}
