#Requires -Version 6.0
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
# This is a sample script, produced to illustrate a possible way to determine if certain Named Locations in Azure AD,and their respective CIDR IP ranges, are actually used by clients to sign in.
# This only processes IPv4 ranges, and excludes country Named Locations.
# Partially inspired by works of David Kittell (https://www.kittell.net/code/powershell-ipv4-range/) and Dr. Tobias Weltner, MVP PowerShell. No actuall code was reused.
#################################################################################

function ConvertTo-IPv4Object {
    param (
        [Parameter(Mandatory = $true)]
        [ValidatePattern(
            '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$',
            ErrorMessage = "'{0}' is not a valid IPv4 address")
        ][String]$Address
    )
    
    [System.Net.IPAddress]($Address.Split('.')[-1..-4] -join '.')
}

function ConvertTo-IPv4String {
    param (
        [System.Net.IPAddress]$Address
    )
    
    $Address.GetAddressBytes()[-1..-4] -join '.'
}

function Expand-CIDR {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidatePattern(
            '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$',
            ErrorMessage = "'{0}' is not a valid CIDR notation")
        ][String]$CIDR,
        [Switch]$AsArray,
        [Switch]$AsObject,
        [ValidateSet("Base", "Mask")][String]$OverridePreference = "Base"
    )
        
    $cidrsplit = $CIDR -split '/'
    $base = ConvertTo-IPv4Object $cidrsplit[0]
    $mask = [system.math]::Pow(2,32 - $cidrsplit[1]) - 1
    $tops = [system.net.ipaddress][int32]($base.Address -bor $mask)
    if ([int32]($base.Address -band $mask) -ge 0) {
        switch ($OverridePreference) {
            "Base" {
                $base = [system.net.ipaddress][int32]($tops.Address -bxor $mask)
                $cidrsplit[0] = ConvertTo-IPv4String $base
                Write-Warning "CIDR mask is longer than possible with the base address.`nModifying the request to $($cidrsplit -join '/')."
                Write-Verbose "If you want to override mask instead (to limit the return to maximum possible with the given base address), run the command with '-OverridePreference Mask'"
            }
            "Mask" {
                $zeroes = [int]([math]::Floor([math]::log($base.Address -bxor ($base.Address - 1),2)))
                $cidrsplit[1] = 32 - $zeroes
                $mask = [system.math]::Pow(2,32 - $cidrsplit[1]) - 1
                $tops = [system.net.ipaddress][int32]($base.Address -bor $mask)
                            Write-Warning "CIDR mask is longer than possible with the base address.`nModifying the request to $($cidrsplit -join '/')."
                Write-Verbose "If you want to override base address instead (to include all addresses while keeping the mask), run the command with '-OverridePreference Base' (default)"
            }
        }
    }

    if ($AsArray.IsPresent) {
        $out = @()
        $base.Address..$tops.Address | ForEach-Object {
            if ($AsObject.IsPresent) {
                $out += [System.Net.IPAddress]$_    
            }
            else {
                $out += ConvertTo-IPv4String $_
            }
        }
    }
    else {
        if ($AsObject.IsPresent) {
            $out = [PSCustomObject]@{
                First = [System.Net.IPAddress]$base
                Last  = [System.Net.IPAddress]$tops
            }
        }
        else {
            $out = [PSCustomObject]@{
                First = ConvertTo-IPv4String $base
                Last  = ConvertTo-IPv4String $tops
            }
        }
    }
    return $out
}

function Get-SignInActivityByCIDRv4 {
    param (
        [Parameter(Mandatory = $true)]
        [ValidatePattern(
            '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$',
            ErrorMessage = "'{0}' is not a valid CIDR notation")
        ][String]$CIDR
    )
    
    $activity = @()
    $i = 0
    $range = Expand-CIDR -CIDR $CIDR -AsArray
    foreach ($ipAddress in $range) {
        # As currently $count query parameter is not supported for /auditLogs/signIns, we can't reliably get sign-in count per IP.
        # Also, as the cap for any query result is 1000 sign-ins, we can't retrieve them all and count locally (it's also resource- and latency-prohibiting)
        # Instead, we're checking if there's at least one sign-in from specific IP
        Write-Progress -Id 3 -ParentId 2 -Activity "Retrieving Sign-in activity by IP" -Status "$($i+1)/$($range.Count): $ipAddress" -PercentComplete ($i * 100 / $range.Count)
        $activity += [PSCustomObject]@{
            Address = $ipAddress
            Active  = [bool](Get-MgAuditLogSignIn -Filter "ipAddress eq '$ipAddress'" -Top 1)
        }
        $i++
    }

    $metrics = $activity | Measure-Object -Sum -Property Active
    $rangeresult = [PSCustomObject]@{
        Range       = $CIDR
        Active      = [int]($metrics.Sum)
        Total       = [int]($metrics.Count)
        # Percentage = [int]($metrics.Sum * 100 / $metrics.Count)
        IPAddresses = $activity
    }

    Write-Progress -Id 3 -ParentId 2 -Activity "Retrieving Sign-in activity by IP" -Status "Done" -PercentComplete 100 -Completed
    return $rangeresult
}

function Get-SignInActivityByNamedLocation {
    param (
        [String]$LocationId
    )
    $ranges = @()
    $Location = Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $LocationId
    $r = 0
    foreach ($range in ($Location.AdditionalProperties['ipRanges'])) {
        switch ($range['@odata.type']) {
            '#microsoft.graph.iPv4CidrRange' { 
                Write-Progress -Id 2 -ParentId 1 -Activity "Retrieving sign-in activity by CIDR range" -Status "$($r+1)/$(($Location.AdditionalProperties['ipRanges']).Count): $($range['cidrAddress'])" -PercentComplete ($r * 100 / ($Location.AdditionalProperties['ipRanges']).Count)
                $ranges += Get-SignInActivityByCIDRv4 -CIDR $range['cidrAddress']
            }
            '#microsoft.graph.iPv6CidrRange' {
                Write-Warning "Skipping $($range['cidrAddress']), as IPv6 is not yet fully supported in AAD, as there are no public endpoints."
            }
        }        
        $r++
    }

    $metrics = $ranges | Measure-Object -Sum -Property Active
    $LocationResult = [PSCustomObject]@{
        DisplayName = $Location.DisplayName
        Id          = $location.Id
        Active      = [bool]($metrics.Sum)
        CIDRs       = $ranges
    }

    Write-Progress -Id 2 -ParentId 1 -Activity "Retrieving sign-in activity by CIDR range" -Status "Done" -PercentComplete 100 -Completed
    return $LocationResult
}

function Get-IPNamedLocationsActivity {
    param (
        [String]$TenantId
    )
    
    Connect-MgGraph -Scopes AuditLog.Read.All, Policy.Read.All -TenantId $TenantId | Out-Null

    [Array]$Locations = Get-MgIdentityConditionalAccessNamedLocation -Filter "isof('microsoft.graph.ipNamedLocation')" -All
    $out = @()
    $l = 0

    foreach ($loc in $Locations) {
        Write-Progress -Id 1 -Activity "Retrieving Named Locations" -Status "$($l+1)/$($Locations.Count): $($loc.DisplayName) ($($loc.Id))" -PercentComplete ($l * 100 / $Locations.Count)
        $out += Get-SignInActivityByNamedLocation -Location $loc.Id
        $l++
    }
    Write-Progress -Id 1 -Activity "Retrieving Named Locations" -Status "Done" -PercentComplete 100 -Completed
    return $out
}
