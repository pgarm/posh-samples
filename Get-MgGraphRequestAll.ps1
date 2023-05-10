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
        $req = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
        [array]$out.value += $req.value
    } while ($req.'@odata.nextLink')

    $out.add('count', $out.value.count)
    $out.add('@odata.context', $req.'@odata.context')
    if ($req.'@odata.deltaLink') { $out.add('@odata.deltaLink', $req.'@odata.deltaLink') }

    return $out
}