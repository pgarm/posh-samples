# Better use the param() block with initial assignment instead of direct
# Also, any sensitive data should generally not be stored in the script directly - remove the SubscriptionID value assignment for production use
[CmdletBinding()]
param (
    [string]$SubscriptionID = "",
    [int]$DaysNearExpiration = 90,
    [string]$VaultName,
    [switch]$ExcludeCertificates
)


# Select-AzSubscription is an alias for Set-AzContext, better to use the primary cmdlet name
Set-AzContext -Subscription $SubscriptionID

# The rest of the script can be replaced by this one-liner (broken out to several lines for readability)
$now = Get-Date
$threshold = $now.AddDays($DaysNearExpiration)

if ($VaultName) {$Vaults = Get-AzKeyVault -VaultName $VaultName} else {$Vaults = Get-AzKeyVault}

$ExpSecrets =  $Vaults | 
    Get-AzKeyVaultSecret | Select-Object Name, ContentType, Expires, @{l = "Status"; e = {
            if ($_.Expires -lt $now) { "Expired" }
            elseif ($_.Expires -lt $threshold) { "Expiring" }
        }
    } | Where-Object { $_.Status } | Sort-Object Expired

if ($ExcludeCertificates.IsPresent) {
    $ExpSecrets = $ExpSecrets | Where-Object {$_.ContentType -ne 'application/x-pkcs12'}
}

Write-Host "Total number of expired secretsv in $($Vaults.count) vaults: $(($ExpSecrets | Where-Object {$_.Status -eq "Expired"}).Count)"
$ExpSecrets | Where-Object { $_.Status -eq "Expired" } | Format-Table -AutoSize

Write-Host "Total number of secrets expiring soon in $($Vaults.count) vaults: $(($ExpSecrets | Where-Object {$_.Status -eq "Expiring"}).Count)"
$ExpSecrets | Where-Object { $_.Status -eq "Expiring" } | Format-Table -AutoSize
