#Reqiures -Version 7.0

[CmdletBinding()]
param (
    [String]$TenantId = '' # Prefill TenantId as GUID of any verified domain name, or supply as parameter
)

#Helper class for stopwatch used in progress reporting
class OperationTracker {
    
    OperationTracker([int]$TotalCount) {
        $this | Add-Member -MemberType ScriptProperty -Name 'TotalCount' -Value { return $TotalCount }.GetNewClosure() -Force
        $this.Reset()
    }

    [timespan] Elapsed() {
        if (!$this.TimeStopped) { return [System.DateTime]::Now - $this.TimeStarted } else { return ($this.TimeStopped - $this.TimeStarted) }
    }

    [float] PercentComplete() {
        if ($this.TotalCount -eq 0) { return 0 }
        return $this.CurrentItem / $this.TotalCount * 100
    }

    [timespan] Remaining() {
        if ($this.TimeStopped) { return [timespan]::Zero }
        if ($this.CurrentItem -eq 0) { return [timespan]::Zero }
        $secondsPerItem = $this.Elapsed().TotalSeconds / $this.CurrentItem
        $secondsRemaining = $secondsPerItem * ($this.TotalCount - $this.CurrentItem)
        return [timespan]::FromSeconds($secondsRemaining)
    }

    [void] Next() {
        $i = $this.CurrentItem + 1
        $this | Add-Member -MemberType ScriptProperty -Name 'CurrentItem' -Value { return $i}.GetNewClosure() -Force
    }

    [string] Status() {
        return "$($this.CurrentItem)/$($this.TotalCount)"
    }

    [void] Stop() {
        $ts = [System.DateTime]::Now
        $this | Add-Member -MemberType ScriptProperty -Name 'TimeStopped' -Value { return $ts }.GetNewClosure() -Force
    }

    [void] Reset() {
        $ts = [System.DateTime]::Now
        $this | Add-Member -MemberType ScriptProperty -Name 'TimeStarted' -Value { return $ts }.GetNewClosure() -Force
        $this | Add-Member -MemberType ScriptProperty -Name 'TimeStopped' -Value { return $null }.GetNewClosure() -Force
        $this | Add-Member -MemberType ScriptProperty -Name 'CurrentItem' -Value { return 0 }.GetNewClosure() -Force
    }
}

#Helper function to get all pages of a Graph request
function Get-MgGraphRequestAll {
    param (
        [Parameter(Mandatory = $true)][uri]$Uri, # The URI to query
        [Parameter(Mandatory = $false)][string]$Method = 'GET' # The HTTP method to use
    )

    $out = [psobject]@{
         value = @()
    }

    do {
        if ($req.'@odata.nextLink') { $uri = $req.'@odata.nextLink' }
        $req = Invoke-MgGraphRequest -Method $Method -Uri $uri -OutputType PSObject
        [array]$out.value += $req.value
        Write-Progress -Activity "Getting data from $uri" -Status "Count: $($out.value.count)" -id 1
    } while ($req.'@odata.nextLink')
    Write-Progress -id 1 -Completed

    $out.add('count', $out.value.count)
    $out.add('@odata.context', $req.'@odata.context')
    if ($req.'@odata.deltaLink') { $out.add('@odata.deltaLink', $req.'@odata.deltaLink') }

    return $out
}

# Connect to MS Graph, with scopes to read registration report and user authentication methods
Connect-MgGraph -Scopes AuditLog.Read.All,UserAuthenticationMethod.Read.All -TenantId $TenantId -ContextScope Process -NoWelcome

$reportUri = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?`$filter=methodsRegistered/any(x:x eq 'microsoftAuthenticatorPush')&`$select=id,userPrincipalName,userDisplayName"
$reportResult = Get-MgGraphRequestAll -Uri $reportUri

$out = @()
$t = [OperationTracker]::new($reportResult['Count'])
foreach ($user in $reportResult.value) {
    $t.Next()
    Write-Progress -Activity "Getting app registration data for users" -Status "$($t.Status): ($($user.id)) $($user.userPrincipalName)" -id 2 `
                   -PercentComplete $t.PercentComplete() -SecondsRemaining $t.Remaining().TotalSeconds
    $userUri = "https://graph.microsoft.com/beta/users/$($user.id)/authentication/microsoftAuthenticatorMethods"
    $userResult = Invoke-MgGraphRequest -Method GET -Uri $userUri -OutputType PSObject
    $appGroup = $userResult.value.clientappName | Group-Object -AsHashTable
    [array]$out += $user | Select-Object *, @{l='FullCount';e={$appGroup['microsoftAuthenticator'].count}}, @{l='LiteCount';e={$appGroup['outlookMobile'].count}}
}
$t.Stop()
Write-Progress -id 2 -Activity "Getting app registration data for users" -PercentComplete 100 -Status "Done in $($t.Elapsed().ToString()), press any key to continue"
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Write-Progress -id 2 -Completed

$out | Export-Csv -Path .\AuthenticatorAppTypeReport.csv -NoTypeInformation