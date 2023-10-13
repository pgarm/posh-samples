#Reqires -Version 7 -Modules MSAL.PS

[CmdletBinding()]
param (
    [string]$LogPath = ".\$(Get-Date -Format 'yyyyMMddTHHmmss')_testrun_$("{0:x8}" -f (new-guid).GetHashCode()).log",
    [pscredential]$Credentials
)

<# In production use, never store credentials in the code. Also, avoid using ROPC flow in production whenever possible.
$username = 'username@domain.com'
$password = ConvertTo-SecureString 'plaintextpassword' -AsPlainText -Force
$ropcCredential = [System.Management.Automation.PSCredential]::new($username, $password)
#>

# Create a hashtable with connection parameters - modify to your application/tenant details
$clientParameters = @{
    ClientId       = 'affa6b58-2b16-48de-90c9-b683201a1169' # registered app ID (clientID)
    TenantId       = '441ff24f-4d10-4329-bffd-2579322b75bb' # tenant ID
    RedirectUri    = 'msalaffa6b58-2b16-48de-90c9-b683201a1169://auth' # registered reply URL
    Scopes         = @(
        'https://graph.microsoft.com/.default'
    )
    UserCredential = $ropcCredential ?? (Get-Credential -Message 'Please enter your credentials for service account')
}

class backoff {
    hidden [int]$current = 4
    hidden [int]$max = 9
    hidden [int]$base = 2
    hidden [int]$factor = 10

    [int]Next() {
        if ($this.current -lt $this.max) {
            $this.current++
        }
        return [math]::Pow($this.base, $this.current) * $this.factor
    }

    [void]Reset() {
        $this.current = 4
    }
}

enum cmLogType {
    Information = 1
    Warning = 2
    Error = 3
}

class pslEntry {
    [ValidateNotNullOrEmpty()][string]$Content
    [cmLogType]$Type
    [string]$Context
    [string]$File
    [int]$Thread

    hidden init() {
        $ts = [System.DateTime]::UtcNow
        $this | Add-Member -MemberType ScriptProperty -Name 'TimeGenerated' -Value { return $ts }.GetNewClosure()
        $this | Add-Member -MemberType ScriptProperty -Name 'Date' -Value { return $ts.ToString('MM-dd-yyyy') }.GetNewClosure()
        $this | Add-Member -MemberType ScriptProperty -Name 'Time' -Value { return $ts.ToString('HH:mm:ss.fff'), '000' -join '+' }.GetNewClosure()
        if ($MyInvocation.ScriptName) {
            $this | Add-Member -MemberType ScriptProperty -Name 'Component' -Value { return "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)" }.GetNewClosure()
        }
        else {
            $this | Add-Member -MemberType ScriptProperty -Name 'Component' -Value { return "Console" }.GetNewClosure()
        }        
    }

    pslEntry([hashtable]$props) {
        $this.init()
        $this.Content = $props.Content
        $this.Type = $props.Type ?? [cmLogType]::Information
        $this.Context = $props.Context
        $this.Thread = $props.Thread ?? [System.Threading.Thread]::CurrentThread.ManagedThreadId
        $this.File = $props.File
    }

    pslEntry([string]$Content, [cmLogType]$Type, [int]$Thread, [string]$File, [string]$Context) {
        $this.init()
        $this.Content = $Content
        $this.Type = $Type
        $this.Context = $Context
        $this.Thread = $Thread
        $this.File = $File
    }

    pslEntry([string]$Content, [cmLogType]$Type, [int]$Thread, [string]$File) {
        $this.init()
        $this.Content = $Content
        $this.Type = $Type
        $this.Context = ''
        $this.Thread = $Thread
        $this.File = $File
    }

    pslEntry([string]$Content, [cmLogType]$Type, [int]$Thread) {
        $this.init()
        $this.Content = $Content
        $this.Type = $Type
        $this.Context = ''
        $this.Thread = $Thread
        $this.File = ''
    }

    pslEntry([string]$Content, [cmLogType]$Type) {
        $this.init()
        $this.Content = $Content
        $this.Type = $Type
        $this.Context = ''
        $this.Thread = [System.Threading.Thread]::CurrentThread.ManagedThreadId
        $this.File = ''
    }

    pslEntry([string]$Content) {
        $this.init()
        $this.Content = $Content
        $this.Type = [cmLogType]::Information
        $this.Context = ''
        $this.Thread = [System.Threading.Thread]::CurrentThread.ManagedThreadId
        $this.File = ''
    }

    [string]GetCmLine() {
        $f = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="{4}" type="{5}" thread="{6}" file="{7}">'
        $l = $this.Content, $this.Time, $this.Date, $this.Component, $this.Context, $this.Type.value__, $this.Thread, $this.File
        return $f -f $l
    }
}


class psl {
    hidden [System.IO.StreamWriter]$Writer
    
    psl ([System.IO.FileInfo]$Path) {
        # Set current directory to $pwd if Path is relative
        if (![System.IO.Path]::IsPathRooted($Path)) {
            $t = [System.IO.Directory]::GetCurrentDirectory()
            [System.IO.Directory]::SetCurrentDirectory($pwd)
            $Path = [System.IO.FileInfo]::new($Path.ToString())
        }
        else { $t = $null } # must define $t to avoid error in the check below

        $this | Add-Member -MemberType ScriptProperty -Name 'Path' -Value { return $Path }.GetNewClosure() -SecondValue { Write-Warning "Path is a ReadOnly property" }
        # Create the log file if it doesn't exist, or open existing for append
        if (!($this.Path.Exists)) {
            $this.Writer = $this.Path.CreateText()
        } 
        else {
            $this.Writer = $this.Path.AppendText()
        }
        $this.Writer.AutoFlush = $true

        # Restore the current directory if it was changed
        if ($t) { [System.IO.Directory]::SetCurrentDirectory($t) }
        Remove-Variable t -ErrorAction SilentlyContinue
    }

    [void]Write ([pslEntry]$Message) {
        $this.Writer.WriteLine($Message.GetCmLine())
    }

    [void]Close () {
        $this.Writer.Close()
        $this.Writer.Dispose()
        $this.Writer = $null
    }

    [void]Close ([string]$CloseMessage) {
        $this.Write([pslEntry]$CloseMessage)
        $this.Close()
    }

    [void]Close ([string]$CloseMessage, [cmLogType]$Type) {
        $this.Write([pslEntry]@{Content = $CloseMessage; Type = $Type })
        $this.Close()
    }
}

#Start the test run, setting null token and base URL
$token = $null
$uri = 'https://graph.microsoft.com/beta/users/delta?$select=id,displayname,accountEnabled'

# Initialize logging
try {
    $logFile = [psl]::new($LogPath)
    $logFile.Write([pslEntry]"Starting test run")
    Write-Host "Starting test run `nLogging to $($logFile.Path.FullName)"
}
catch {
    Write-Error "Failed to initialize logging to $LogPath, terminating"
    exit 1
}

# Main processing loop
$runStart = Get-Date
$blankRetrieved = 0; $totalRetrieved = 0; $requestCount = 0
$backoff = [backoff]::new()
do {
    # Get a token if we don't have one or if it's about to expire
    if (!($token) -or ((New-TimeSpan -Start (Get-Date).ToUniversalTime() -End $token.ExpiresOn.UtcDateTime).TotalMinutes -lt 5)) {
        try {
            $token = Get-MsalToken @clientParameters
            $authHeader = @{
                'Authorization' = $token.CreateAuthorizationHeader()
            }
            $logFile.Write([pslEntry]@{Content = "Retrieved new token as $($token.Account.Username)`n for tenant $($token.TenantId)`n expiring $($token.ExpiresOn) UTC.`n Scopes: $($token.Scopes -join ',')`n CorrelationId $($token.CorrelationId)"; File = 'Token' })
        }
        catch {
            $logFile.Close([pslEntry]@{Content = "Failed to retrieve token, terminating`n$_"; Type = [cmLogType]::Error })
            Write-Error "Failed to retrieve token, terminating"
            exit 1
        }
    }

    # Invoke the Graph API call and get the measurements
    try {
        $latency = Measure-Command {
            $rawResponse = Invoke-WebRequest -Uri $uri -Headers $authHeader
        }
        $RequestCount ++
        
        if ($rawResponse.StatusCode -ne 200) {
            $logFile.Write([pslEntry]@{Content = "HTTP/$($response.StatusCode): GET $uri`n CorrelationId: $($response.Headers.'client-request-id')`n Timestamp: $([System.DateTime]::Parse($response.Headers.Date).ToUniversalTime().ToString('o'))"; File = 'Graph' })
        }
        else {
            $Response = $rawResponse.Content | ConvertFrom-Json
            $c = $Response.value.Count
            $logLine = @(
                "HTTP/$($rawResponse.StatusCode): GET $uri",
                " Retrieved $c object(s) in $($latency.TotalMilliseconds)ms",
                " CorrelationId: $($rawResponse.Headers.'client-request-id')",
                " Timestamp: $([System.DateTime]::Parse($rawResponse.Headers.Date).ToUniversalTime().ToString('o'))",
                "Diag: $($rawResponse.Headers.'x-ms-ags-diagnostic')"
            )

            if ($response.'@odata.deltaLink') {
                $logFile.Write([pslEntry]@{Content = "DeltaLink found, end of run"; File = 'Graph' })
            }
            elseif ($response.'@odata.nextLink') {
                $uri = $response.'@odata.nextLink'   
                if ($c -gt 0) {
                    $totalRetrieved += $c
                    $logFile.Write([pslEntry]@{Content = ($logLine -join "`n"); File = 'Graph' })
                    $backoff.Reset()
                }
                else {
                    $blankRetrieved++
                    $logFile.Write([pslEntry]@{Content = ($logLine -join "`n"); File = 'Graph'; Type = [cmLogType]::Warning })
                    $b = $backoff.Next()
                    $logFile.Write([pslEntry]@{Content = "Retrying request after $b`ms"; File = 'Graph' })
                    Start-Sleep -MilliSeconds $b
                    Remove-Variable b
                }
         
            }
            else {
                Write-Host "No nextLink or deltaLink found, terminating"
                break            
            }

            Remove-Variable c,logLine -ErrorAction SilentlyContinue
        }
    }
    catch {
        $logFile.Write([pslEntry]@{Content = "Error in Graph call:`n$_"; File = 'Graph'; Type = [cmLogType]::Error })
    }
} until (
    $response.'@odata.deltaLink'
)

# Wrap up
$logFile.Close("Test run completed with $requestcount requests in $((New-TimeSpan -Start $runStart -End (Get-Date)).ToString())`n Total objects retrieved: $totalRetrieved`n Blank responses: $blankRetrieved")
Write-Host "Test run completed successfully`nLog file: $($logFile.Path.FullName)"

