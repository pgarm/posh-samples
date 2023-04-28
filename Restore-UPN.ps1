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
    [Parameter(Mandatory = $true)][String]$UserListFile,
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

# Initialize the log file (if you need path checking, implement it here)
try {
    Start-Log -FilePath "$($LogPath.Trim('\'))\UpnRestore_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    Write-Log "Starting UPN cleanup run"
}
catch {
    Write-Host -ForegroundColor Red "Couldn't initialize the log file, terminating"
    Exit 1
}

# If the file source is supplied, load it
try {
    $UserList = Import-Csv -Path $UserListFile
    Write-Log -Message "Retrieved user list to process from $UserListFile`: total $($UserList.Count)"
}
catch {
    Write-Log -Message "Couldn't retrieve user list to process from $UserListFile`: $_)" -LogLevel 3
    Exit 1
}

# Connect to Graph
try {
    Connect-MgGraph -TenantId $TenantId -Scopes User.ReadWrite.All -ContextScope Process
}
catch {
    Write-Log -Message "Couldn't connect to Graph: $_" -LogLevel 3
    Exit 1
}

# Process each user
$i = $s = $f = 0; $StartTime = Get-Date
foreach ($user in $userlist) {
    $i++
    Write-Progress -Activity "Updating user UPNs" -Status "$i/$($userlist.count): Setting $($user.Id) to $($user.UserPrincipalName)" -PercentComplete ($i / $userlist.count * 100) -SecondsRemaining (($userlist.count - $i) * ((Get-Date).Second - $StartTime.second) / $i)
    try {
        Update-MgUser -UserId $user.Id -UserPrincipalName $user.UserPrincipalName
        Write-Log -Message "Set UPN $($user.UserPrincipalName) on UserID $($user.id)"
        $s++
    }
    catch {
        Write-Log -Message "Couldn't process user $($user.UserPrincipalName) (ID $($user.id)): $_" -LogLevel 2
        $f++
    }
}
Write-Log -Message "Finished updating user UPNs`nTotal: $i`nSuccessful: $s`nFailed: $f`nElapsed time: $((Get-Date) - $StartTime)"
