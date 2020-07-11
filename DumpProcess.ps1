#This script reads the Sysmon event logs, gets process IDs from the event and dumps its memory. 
#Since task scheduler cannot provide the process id as an input for the script, we have to read Sysmon logs to get the process Id.
#this can be implemented in other ways as well. Since we monitor only the honeyfolder, any Sysmon file create event is enough for us to trigger the script. 
#An alternative way would be monitoring file creation events in general and searching only for the honey folder related Sysmon events.

$events=Get-WinEvent -FilterHashtable @{ProviderName="Microsoft-Windows-Sysmon"; Id = 11; StartTime = [datetime]::Now.AddMinutes(-20)} -ErrorAction Stop

#the below function was copied from PowerSploit.
#It dumps the full memory of a given process Id into a specified folder.
function Out-Minidump
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [System.Diagnostics.Process]
        $Process,

        [Parameter(Position = 1)]
        [ValidateScript({ Test-Path $_ })]
        [String]

        #Specify Save location for the dump files.
        #you just need to change this part of the function.
        $DumpFilePath = "C:\AntiRansom"
    )

    BEGIN
    {
        $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
        $WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic')
        $Flags = [Reflection.BindingFlags] 'NonPublic, Static'
        $MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags)
        $MiniDumpWithFullMemory = [UInt32] 2
    }

    PROCESS
    {
        $ProcessId = $Process.Id
        $ProcessName = $Process.Name
        $ProcessHandle = $Process.Handle
        $ProcessFileName = "$($ProcessId).dmp"
        #$ProcessFileName = "$($ProcessName)_$($ProcessId).dmp"

        $ProcessDumpPath = Join-Path $DumpFilePath $ProcessFileName

        $FileStream = New-Object IO.FileStream($ProcessDumpPath, [IO.FileMode]::Create)

        $Result = $MiniDumpWriteDump.Invoke($null, @($ProcessHandle,
                                                     $ProcessId,
                                                     $FileStream.SafeFileHandle,
                                                     $MiniDumpWithFullMemory,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero))

        $FileStream.Close()

        if (-not $Result)
        {
            $Exception = New-Object ComponentModel.Win32Exception
            $ExceptionMessage = "$($Exception.Message) ($($ProcessName):$($ProcessId))"

            # Remove any partially written dump files. For example, a partial dump will be written
            # in the case when 32-bit PowerShell tries to dump a 64-bit process.
            Remove-Item $ProcessDumpPath -ErrorAction SilentlyContinue

            throw $ExceptionMessage
        }
        else
        {
            Get-ChildItem $ProcessDumpPath
        }
    }

    END {}
}

#Check if the evet log query returns at least one event.
#If there is no event, exit.Since we already used -ErrorAction Stop, this is not necessary.
#if you change it to SilentlyContinue, you need to make sure the query returns at least one event.

if (!$events[0].message) {  

    Exit
   
}

else {
    
    $processes = @()

    #for each event, get process Id and dump it. 
    #this is because the ransomware process can spawn multiple process for encryption.

    foreach ($event in $events) {

    #parse the process Id.
    [int]$processId=[regex]::Match($event.message,'ProcessId\:\s(.+)').captures.groups[1].Value
        
    $processes += $processId
    }
    
    $processes = $processes | Select -Unique
    
    foreach ($process in $processes) {

    #define the dump name based on the Process Id.
    $dumpFileName = $process.ToString()+".dmp"
    
    #check if the process has already been dumped.

    if (Test-Path '"C:\AntiRansom\$dumpFileName"') {
       
       Exit
    }

    else {

       #dump the process.
       Out-Minidump -Process (Get-Process -Id $process)
    
    }
    }  
}
Exit
