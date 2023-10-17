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
    
    hidden [void]open() {
        #Check if the log file exists abd create it if it doesn't
        if (!($this.Path.Exists)) {
            $this.Writer = $this.Path.CreateText()
            $this.Writer.AutoFlush = $true
        } 
        else {
            # Try to open existing for append
            if ($this.Writer) {
                return
            }
            try {
                #$t = $this.Path.Open('Open','ReadWrite','None')
                #if ($t) { $t.Close(); $t.Dispose(); Remove-Variable t -ErrorAction SilentlyContinue }
                $this.Writer = $this.Path.AppendText()
                $this.Writer.AutoFlush = $true
            }
            catch [System.IO.IOException] {
                Write-Error -CategoryActivity 'OpenLogFile' -CategoryReason 'FileInUse' -Message ($_.Exception.Message) -ErrorAction Stop
            }
            catch {
                Write-Error -CategoryActivity 'OpenLogFile' -Message ($_.Exception.Message)  -ErrorAction Stop
            }
        }
    }

    psl ([System.IO.FileInfo]$Path) {
        # Set current directory to $pwd if Path is relative
        if (![System.IO.Path]::IsPathRooted($Path)) {
            $t = [System.IO.Directory]::GetCurrentDirectory()
            [System.IO.Directory]::SetCurrentDirectory($pwd)
            $Path = [System.IO.FileInfo]::new($Path.ToString())
        }
        else { $t = $null } # must define $t to avoid error in the check below

        $this | Add-Member -MemberType ScriptProperty -Name 'Path' -Value { return $Path }.GetNewClosure() -SecondValue { Write-Warning "Path is a ReadOnly property" }
        $this.Open()

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

function Open-Log {
    #Function to create a new log file or open an existing one for append
    [Alias('New-Log', 'Start-Log')]
    param (
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$Path = ".\$($Name)_$([System.DateTime]::Now.ToString('yyyyMMddTHHmmss'))_$("{0:x8}" -f [System.Guid]::NewGuid().GetHashCode()).log",
        [string]$Message,
        [switch]$PassThru
    )
    try {
        $log = Get-Log -Name $Name
    }
    catch {
        $log = New-Variable -Name $Name -Value ([psl]::new($Path)) -Option ReadOnly -Scope Script
    }
    
    if ($Message) {
        $log.Write($Message)
    }

    if ($PassThru) {
        return $log
    }
}

function Get-Log {
    # Function to get logfile object by name
    param (
        [Parameter(Mandatory = $true)][string]$Name
    )

    $log = Get-Variable -Name $Name -Scope Script -ValueOnly -ErrorAction SilentlyContinue | Where-Object { $_ -is [psl] }

    if ($log) {
        return $log
    }
    else {
        Write-Error -CategoryActivity 'OpenLogFile' -Message "Log `"$Name`" not open or does not exist" -ErrorAction Stop
    }
}

function Close-Log {
    # Function to close a log file
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'byName')][string]$Name,
        [Parameter(Mandatory = $true, ParameterSetName = 'byObject', ValueFromPipeline = $true)][psl]$Log,
        [string]$Message
    )

    if ($PSCmdlet.ParameterSetName -eq 'byName') {
        try {
            $Log = Get-Log -Name $Name

            if ($Message) {
                $log.Close($Message)
            }
            else {
                $log.Close()
            }
        }
        catch {
            Write-Warning "Log `"$Name`" not open or does not exist"
        }
        finally {
            Remove-Variable -Name $Name -Scope Script -Force -ErrorAction SilentlyContinue
        }
    }
}

function Write-Log {
    # Function to write a log entry to a log file
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'byName')][string]$Name,
        [Parameter(Mandatory = $true, ParameterSetName = 'byObject', ValueFromPipeline = $true)][psl]$Log,
        [Parameter(Mandatory = $true)][string]$Content,
        [cmLogType]$Type = [cmLogType]::Information,
        [string]$Context = '',
        [int]$Thread = [System.Threading.Thread]::CurrentThread.ManagedThreadId,
        [string]$File = ''
    )

    if ($PSCmdlet.ParameterSetName -eq 'byName') {
        $Log = Get-Log -Name $Name
    }

    $Log.Write([pslEntry]@{
            Content = $Content
            Type    = $Type
            Context = $Context
            Thread  = $Thread
            File    = $File
        })
}