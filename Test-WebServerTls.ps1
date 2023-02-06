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
    [Parameter(Mandatory = $true)]
    [uri]
    $Uri
)

function Get-WebServerTlsConfig {
    param (
        # Server FQDN or IP address
        [Parameter(Mandatory = $true)]
        [String]
        $Server,
        
        # Port to connect to. If not specified, defaults to 443
        [String]
        $Port = 443
    )

    $Protocols = @()

    foreach ($v in @("ssl2", "ssl3", "tls", "tls11", "tls12")) {
        $TcpClient = [System.Net.Sockets.TcpClient]::new($Server, $Port)
        $SslStream = [System.Net.Security.SslStream]::new($TcpClient.GetStream(), $true, ([System.Net.Security.RemoteCertificateValidationCallback] { $true }))
        $SslStream.ReadTimeout = 15000
        $SslStream.WriteTimeout = 15000
        try {
            #Write-Host "using $v"
            $SslStream.AuthenticateAsClient($Server, $null, $v, $false)
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate = $sslStream.RemoteCertificate
            [array]$Protocols += $v 
        }
        catch { <#Write-Host $_ #> }
        finally {
            if ($sslStream) { $SslStream.Close(); $SslStream.Dispose() }
            if ($client) { $TcpClient.Close(); $TcpClient.Dispose() }
        }
    }

    if ($Certificate) {
        return [PSCustomObject]@{
            Protocols   = $Protocols
            Certificate = $Certificate
        }
    }
    else {
        Write-Host "Could not negotiate TLS with $Server`:$Port" -ForegroundColor Red
    }
}

function Get-WebServerIpAddresses {
    param (
        [Parameter(Mandatory = $true)][String]$Fqdn
    )
    
    try {
        [array]$ServerIpAddress = Resolve-DnsName $uri.Host -Type A_AAAA | Where-Object { $_.Type -in @('A', 'AAAA') }
        if ($ServerIpAddress.Count -gt 0) {
            Write-Host "Resolved $($ServerIpAddress.Count) IP addresses for $($uri.Host)" -ForegroundColor Green
        }
        else {
            Write-Host "No IP addresses resolved for $($uri.Host) - check name resolution" -ForegroundColor Red
            exit 404
        }
    }
    catch {
        switch ($_.CategoryInfo.Category) {
            'ResourceUnavailable' {
                Write-Host 'Hostname could not be resolved to IP address' -ForegroundColor Red;
                exit 404
            }
            'OperationTimeout' {
                Write-Host 'Name resolution timed out' -ForegroundColor Red;
                exit 408
            }
            Default {
                Write-Host 'Error occurred during name resolution:`n$_' -ForegroundColor Red;
                exit 400
            }
        }
    }
}

Start-Transcript -Path ".\PsTranscript_$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

#Verify that the hostname in Uri maps to actual IP address
Get-WebServerIpAddresses -Fqdn $Uri.Host

#Verify own public IP address
try {
    $EgressIp = (Invoke-WebRequest "https://ifconfig.me/ip").Content
    Write-Host "Egress IP address is $EgressIp"
}
catch {
    Write-Host "Couldn't determine egress point public IP, check for possible internet connectivity issue" -ForegroundColor Yellow
}

#Retrieve TLS versions and certificate
$RemoteTlsConfig = Get-WebServerTlsConfig -Server $Uri.Host -Port $Uri.Port
if ($RemoteTlsConfig) {
    Write-Host "Available TLS versions: $($RemoteTlsConfig.Protocols -join ', ')"
    if ($RemoteTlsConfig.Certificate.Verify()) {
        Write-Host "Certificate presented by server is trusted" -ForegroundColor Green
    }
    else {
        Write-Host "Certificate presented by server is not trusted" -ForegroundColor Red
    }
    if ($Uri.Host -in $RemoteTlsConfig.Certificate.DnsNameList.Unicode) {
        Write-Host "Host name $($Uri.Host) present in certificate SAN extension" -ForegroundColor Green
    }
    else {
        Write-Host "Host name $($Uri.Host) not present in certificate SAN extension" -ForegroundColor Red
    }

    Export-Certificate -Cert $RemoteTlsConfig.Certificate -filepath ".\$($Uri.Host).cer" 
}

Stop-Transcript