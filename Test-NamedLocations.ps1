#Requires -Version 6.0

##
# 
##

function Expand-CIDR {
    param (
        [Parameter(Mandatory = $true)]
        [ValidatePattern(
            '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$',
            ErrorMessage = "'{0}' is not a valid CIDR notation")
        ][String]$CIDR,
        [Switch]$AsArray,
        [ValidateSet("Base","Mask")][Switch]$OverridePreference = "Mask"
    )
        
    $cidrsplit = $CIDR -split '/'
    $base = [System.Net.IPAddress]($cidrsplit[0].Split('.')[-1..-4] -join '.')
    $check = ([System.Convert]::ToString($base.Address, 2).PadLeft(32, '0').SubString($cidrsplit[1],32-$cidrsplit[1])).LastIndexOf(1)
    if ($check -ge 0) {
        Write-Warning "CIDR mask is longer than possible with the base address."
        switch ($OverridePreference) {
            "Base" {

            }
            "Mask" {
                $cidrsplit[1] = [int]($cidrsplit[1]) + $check + 1
            }
        }
    }
    $tops = [System.Net.IPAddress]([System.Convert]::ToInt32([System.Convert]::ToString($base.Address, 2).PadLeft(32, '0').SubString(0, $cidrsplit[1]).PadRight(32, '1'), 2))

    if ($AsArray.IsPresent) {
        $out = @()
        $base.Address..$tops.Address | ForEach-Object {
            [array]$out += [string]((([System.Net.IPAddress]$_).IPAddressToString.Split('.'))[-1..-4] -join '.')
        }
    }
    else {
        $out = [PSCustomObject]@{
            First = $cidrsplit[0]
            Last  = ($tops.IPAddressToString.Split('.'))[-1..-4] -join '.'
        }
    }
    return $out
}