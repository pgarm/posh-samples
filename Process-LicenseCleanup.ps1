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
## Start-Log and Write-Log functions are courtesy of Adam Bertram (https://adamtheautomator.com/sccm-client-logs)
#################################################################################


[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)][String]$TenantId, # Use starting domain or GUID
    [Parameter(Mandatory = $true)][String[]]$TargetSKUs, # List SKUs youwant to be stripped from users. Note this is an array when invoking the script with parameters
    [Parameter(Mandatory = $true, ParameterSetName = 'List')][String[]]$UserIdList, # Users can be defined as UPN or ObjectId. Note this is an array when invoking the script with parameters
    [Parameter(Mandatory = $true, ParameterSetName = 'File')][String]$UserListFile,
    [String]$LogPath = ".\" # Use a plaintext file with user list, one per line, UPN or ObjectId.
)

function Start-Log {
    [CmdletBinding()]
    param (
        [ValidateScript({ Split-Path $_ -Parent | Test-Path })]
        [string]$FilePath
    )
    try {
        if (!(Test-Path $FilePath)) {
            ## Create the log file
            New-Item $FilePath -Type File | Out-Null
        }
        ## Set the global variable to be used as the FilePath for all subsequent Write-Log calls in this session
        $global:ScriptLogFilePath = $FilePath
    }
    catch {
        Write-Error $_.Exception.Message
    }
}

function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
    
        [Parameter()]
        [ValidateSet(1, 2, 3)]
        [int]$LogLevel = 1
    )
    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
    $Line = $Line -f $LineFormat
    Add-Content -Value $Line -Path $ScriptLogFilePath
}

function Remove-UserLicenses {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][String]$UserId
    )

    # Get user info from MSGraph, including license assignments
    try {
        $userObj = Get-MgUser -UserId $UserId -Property Id, displayName, userPrincipalName, licenseAssignmentStates
        Write-Log -Message "Retrieved license information for user $($userObj.DisplayName) <$($userObj.UserPrincipalName)> ($($userObj.Id)), total $(($userObj.LicenseAssignmentStates.SkuId | Select-String -Pattern $SKUs.Values).Count) assignments to remove"
    }
    catch {
        Write-Log -Message "Couldn't retrieve the license info for user $($userObj.DisplayName) <$($userObj.UserPrincipalName)> ($($userObj.Id))" -LogLevel 2
    }

    # Select direct assignments and remove those
    $dir = ($userObj.licenseAssignmentStates | Where-Object { !$_.assignedByGroup -and ($_.SkuId -in $SKUs.Keys) }) | Select-Object *, @{l = "SkuPartNumber"; e = { $SKUs[$_.SkuId] } }
    if ($dir.Count -gt 0) {
        try {
            Set-MgUserLicense -UserId $userObj.Id -RemoveLicenses $dir.SkuId -AddLicenses @()
            Write-Log "Removed $($dir.Count) directly assigned licenses for user $($userObj.Id): $($dir.SkuPartNumber -join ', ')"
        }
        catch {
            Write-Log "Failed to remove $($dir.Count) directly assigned licenses for user $($userObj.Id): $($dir.SkuPartNumber -join ', ')" -LogLevel 2
        }
    }
    else {
        Write-Log "No directly assigned targeted licenses found for user $($userObj.Id)"
    }

    # Select group-assigned licenses and remove user from respective groups
    $grp = ($userObj.licenseAssignmentStates | Where-Object { $_.assignedByGroup -and ($_.SkuId -in $SKUs.Keys) }) | Select-Object *, @{l = "SkuPartNumber"; e = { $SKUs[$_.SkuId] } }
    if ($grp.Count) {
        foreach ($GroupId in ($grp.assignedByGroup | Select-Object -Unique)) {
            try {
                Remove-MgGroupMemberByRef -GroupId $GroupId -DirectoryObjectId $userObj.Id
                Write-Log "Removed user $($userObj.Id) from group $GroupId that was granting licenses: $(($userObj.LicenseAssignmentStates | Where-Object {$_.assignedByGroup -eq $GroupId}).SkuPartNumber -join ', ')"
            }
            catch {
                if ($_.ToString() -eq "Insufficient privileges to complete the operation.") {
                    Write-Log "Can't remove user $($userObj.Id) from dynamic group $GroupId that was granting licenses: $(($userObj.LicenseAssignmentStates | Where-Object {$_.assignedByGroup -eq $GroupId}).SkuPartNumber -join ', ')" -LogLevel 2
                }
                else {
                    Write-Log "Failed to remove user $($userObj.Id) from group $GroupId that was granting licenses: $(($userObj.LicenseAssignmentStates | Where-Object {$_.assignedByGroup -eq $GroupId}).SkuPartNumber -join ', ')" -LogLevel 2
                }
            }
        }
    }
    else {
        Write-Log "No group assigned targeted licenses found for user $($userObj.Id)"
    }

    $lft = ($userObj.LicenseAssignmentStates | Where-Object { ($_.SkuId -notin $SKUs.Keys) -and ($_.AssignedByGroup -notin $grp.assignedByGroup) }).SkuId | Select-Object -Unique | Select-Object *, @{l = "SkuPartNumber"; e = { $SKUs[$_.SkuId] } }
    if ($lft.count -gt 0) {
        Write-Log "User $($userObj.Id) has $($lft.Count) licenses not targeted: $($lft.SkuPartNumber -join ', ')"
    }
}

# Initialize the log file (if you need path checking, implement it here)
try {
    Start-Log -FilePath "$($LogPath.Trim('\'))\LicenseCleanup_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    Write-Log "Starting license cleanup run"
}
catch {
    Write-Host -ForegroundColor Red "Couldn't initialize the log file, terminating"
    Exit 1
}

# If the file source is supplied, load it
if ( $PsCmdlet.ParameterSetName -eq “File”) {
    try {
        $UserIdList = Get-Content -Path $UserListFile
        Write-Log -Message "Retrieved user list to process from $UserListFile`: total $($UserIdList.Count)"
    }
    catch {
        Write-Log -Message "Couldn't retrieve user list to process from $UserListFile`: $_)" -LogLevel 3
        Exit 1
    }
}

# Note the scopes are needed to perform license lookup, user lookup and management, group lookup and membership management, respectively
try {
    Connect-MgGraph -Scopes Organization.Read.All, User.ReadWrite.All, Group.Read.All, GroupMember.ReadWrite.All -TenantId $TenantId
    Write-Log -Message "Connected to MgGraph"
}
catch {
    Write-Log -Message "Couldn't connect to MgGraph: $_" -LogLevel 3
    Exit 1
}

# Get targeted SKUs from tenant
try {
    $global:SKUs = @{}
    Get-MgSubscribedSku -Property SkuId, SkuPartNumber | Select-Object SkuId, SkuPartNumber | Where-Object { $_.SkuPartNumber -in $TargetSKUs } | ForEach-Object {
        $SKUs.Add($_.SkuId, $_.SkuPartNumber)
    }
}
catch {
    Write-Log "Fouldn't retrieve SKUs from the tenant" -LogLevel 3
    Exit 1
}

foreach ($UserId in $UserIdList) {
    Remove-UserLicenses -UserId $UserId
}

Write-Log "Completed the run"
