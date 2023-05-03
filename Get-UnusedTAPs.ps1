param (
    [Parameter(Mandatory=$true)][String]$TenantId
)

Connect-MgGraph -Scopes User.Read.All, UserAuthenticationMethod.Read.All -TenantId $TenantId
$users = Get-MgUser -All | Select-Object Id, DisplayName, userPrincipalName
foreach ($user in $users) {
    $tap = Get-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.Id | Where-Object {$_.MethodUsabilityReason -in @('EnabledByPolicy','Expired')}
    if ($tap) {
        [array]$unused += $user | Select-Object *, @{l="Status";e={$tap.MethodUsabilityReason}}, @{l="Expires";e={$tap.StartDateTime.addhours($tap.LifetimeInMinutes / 60)}}
    }
    Remove-Variable tap
}
Write-Host "Found $($unused.Count) unsused TAPs, exporting to .\UnusedTAPs_$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$unused | Export-Csv -Path ".\UnusedTAPs_$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"