<#	

.SYNOPSIS
Version 2.7.0

.DESCRIPTION
Version 2.7.0

.PARAMETER

.EXAMPLE

.INPUTS

.OUTPUTS

.LINK

.NOTES
#########################################################################
Author:		Brad W. Beckwith
Date:		December 4, 2019
Version:    2.5.0
Updated:    January 29, 2021 - Changed bbtouch to touch and modified Function

#########################################################################

#>


function Get-BBHeader([string]$Text, [int]$Width, [int]$LineNumber)
{
	
	<#
	.SYNOPSIS
		Creates a one or three line header (commented) for the user.
	
	.DESCRIPTION
		Creates a one or three line header (commented) for the user.
		The user and set the text, width of the header and how many
		lines the header will be. User choices are only 1 and 3.
	
	.PARAMETER Text
		User text that will be shown in the header line(s).
	
	.PARAMETER Width
		The width of the header in characters.
	
	.PARAMETER LineNumber
		How many lines the header is. Either 1 or 3 are the only
		choices.
	
	.EXAMPLE
		PS C:\> Get-BBHeader "Enter text" 70 3
	
	.NOTES
		
		Author:		Brad Beckwith
		Date:		
		Purpose:	See SYNOPSIS above
		Version:	1.5.0

		
#>
	
	function CreateText ($Text)
	{
		if ($Text) { $Text = " " + $Text + " " }
		$padLeft = [int]($Width / 2) + ($Text.Length / 2)
		$Text.PadLeft($padLeft, "#").PadRight($Width, "#")
	}
	
	if (($LineNumber -ne 1) -and ($LineNumber -ne 3))
	{
		Write-Host "`nLine No. is: $LineNumber"
		Write-Host "Line number should be 1 or 3 only"
		Write-Host "`nUsage: Get-BBHeader <what to print> <line width> <No. of Lines>`n"
		break
	}
	
	if ($LineNumber -eq 1)
	{
		CreateText $Text
	}
	
	if ($LineNumber -eq 3)
	{
		Get-BBHeader '' $Width 1
		CreateText $Text
		Get-BBHeader '' $Width 1
	}
	
}

Function New-BBFabricConfigName
{
<#	

    .SYNOPSIS
    Creates an empty file for the named server as an ISE CR Name. You
    must copy or create the required fabric switch config text with the
    file.

    .DESCRIPTION
    Creates an empty file for the named server as an ISE CR Name. You
    must copy or create the required fabric switch config text with the
    file.

    .PARAMETER ComputerName

    .EXAMPLE
    . .\Create-BBFabricConfigName
    Create-BBFabricConfigName

    .INPUTS
    Computername

    .OUTPUTS
    Test file with the proper ISE CR name

    .LINK
    N/A

    .NOTES
    ###################################################################
    Author:		Brad W. Beckwith
    Updated:	December 4, 2019

    Version:	v1.1.4
    Purpose:	Changed name from New--BBFabricConfigNamer to
                Create-BBFabricConfigName

    Version:	v1.1.3
    Purpose:	Added the ability to create a new blank file.
    
    Author:		Brad W. Beckwith
    Date:	    February 2017
    Version:    1.0.0
    ###################################################################

#>
    
    [CmdletBinding(ConfirmImpact = "Low")]
    Param
    (
        [parameter(Mandatory = $false,
                   ValueFromPipeline = $true,
                   Position = 0,
                   HelpMessage = "Enter one or more computer names separated by commas.")]
        [alias("CN", "MachineName", "Host")]
        [ValidateCount(1, 200)]
        [ValidateLength(1, 16)]
        [String]$ComputerName
    )
    
    Write-Output "`nEnter Server or descriptive name for the fabric config. file."
    $rtn = Read-Host -Prompt "File Name "
    $rtn = ($rtn).ToUpper().Trim()
    $date = (get-date).tostring("yyyyMMddmm_")
    $FileName = "ISE_CR_" + $date + $rtn + "_Fabric_Config.txt"
    Write-Host "$FileName" -ForegroundColor Green
    New-Item -Path $FileName -ItemType file
    
} #End Function Create-BBFabricConfigName

Function Write-ErrorLog
{
<#
.Synopsis
   Write-ErrorLog writes a message to a specified log file with the current time stamp.
.DESCRIPTION
   The Write-ErrorLog Function is designed to add logging capability to other scripts.
   In addition to writing output and/or verbose you can write to a log file for
   later debugging.
.NOTES
   
    Modified by: Brad Beckwith @bradbeckwith: Aug. 1, 2018
    Changed the output log file name for use with the scheduled task
    script this is currently part of.
.PARAMETER Message
   Message is the content that you wish to add to the log file. 
.PARAMETER Path
   The path to the log file to which you would like to write. By default the Function will 
   create the path and file if it does not exist. 
.PARAMETER Level
   Specify the criticality of the log information being written to the log (i.e. Error, Warning, Informational)
.PARAMETER NoClobber
   Use NoClobber if you do not wish to overwrite an existing file.
.EXAMPLE
   Write-ErrorLog -Message 'Log message' 
   Writes the message to c:\Logs\PowerShellErrorLog.log.
.EXAMPLE
   Write-ErrorLog -Message 'Restarting Server.' -Path c:\Logs\Scriptoutput.log
   Writes the content to the specified log file and creates the path and file specified. 
.EXAMPLE
   Write-ErrorLog -Message 'Folder does not exist.' -Path c:\Logs\Script.log -Level Error
   Writes the message to the specified log file as an error message, and writes the message to the error pipeline.
.LINK
   https://gallery.technet.microsoft.com/scriptcenter/Write-ErrorLog-PowerShell-999c32d0
#>    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [Alias('LogPath')]
        [string]$Path = 'C:\Logs\Test.log',
        [Parameter(Mandatory = $false)]
        [string]$Level = "Error",
        [Parameter(Mandatory = $false)]
        [switch]$NoClobber
    )
    
    Begin
    {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'
    }
    Process
    {
        
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Path) -AND $NoClobber)
        {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
        }
        
        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path))
        {
            Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
        }
        
        else
        {
            # Nothing to see here yet.
        }
        
        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyyMMddTHHmmss"
        
        
        # Write message to error, warning, or verbose pipeline and specify $Level
        If ($Level)
        {
            switch ($Level)
            {
                'Error' {
                    $Message = $Level + ": " + $Message
                }
                
                'Warning' {
                    $Message = $Level + ": " + $Message
                }
                'Info' {
                    $Message = $Level + ": " + $Message
                }
                Default { Write-Output "Unknown Level"; Exit }
            }
        }
        else
        {
            Write-Output "No level given"
            Exit
        }
        
        
        Write-Debug "Vars: Level,LevelText,FormattedDate,NewLogFile"
        Write-Verbose $Level
        
        # Write log entry to $Path
        Write-Output "$FormattedDate $Message" | Out-File -FilePath $Path -Append
    }
    End
    {
        # Set VerbosePreference back to default setting.
        $VerbosePreference = 'SilentlyContinue'
    }
} #End: Function Write-ErrorLog

Function Show-Colors()
{
    $colors = [Enum]::GetValues([ConsoleColor])
    $max = ($colors | foreach { "$_ ".Length } | Measure-Object -Maximum).Maximum
    foreach ($color in $colors)
    {
        Write-Host (" {0,2} {1,$max} " -f [int]$color, $color) -NoNewline
        Write-Host "$color" -Foreground $color
    }
} #End: Function Show-Colors

Function Get-BBLastBootTime
{
<#	

.SYNOPSIS
    Gets the latest boot time of the local computer. 
.DESCRIPTION
    Gets the latest boot time of the local computer.
.PARAMETER
    None
.EXAMPLE
    Get-BBLastBootTime
.INPUTS
    None
.OUTPUTS
    Latest boot time of the local computer system
.LINK
    None

.NOTES
########################################################################
Author:		Brad W. Beckwith
Date:		
Version:	v1.0.0
Purpose:	
########################################################################
	
#>
    
    SystemInfo | Select-String "^System Boot"    
} #End: Function Get-BBLastBootTime

Function Get-BBUptime
{
<#
.SYNOPSIS
	This Function returns the system uptime to the user.

.DESCRIPTION
	This Function returns the system uptime to the user.

.PARAMETER  ComputerName
	ComputerName is an array of strings, which can be passed
    or entered on the command line.

.EXAMPLE
	Get-BBUpTime -ComputerName 'localhost'

.EXAMPLE
	Get-BBUpTime -ComputerName 'localhost','com1','com2','com3'

.EXAMPLE
    Get-BBUpTime -ComputerName (Get-Content .\Servers.txt)

.EXAMPLE
	'localhost' | Get-BBUptime

.INPUTS
	ComputerName as a single string or an array of strings. This
    can be input as a text file with one system (computer) name
    on each line.

.OUTPUTS
	UpTime of the computer(s) passed to the Function each on
    a single line.

.LINK
	None
    
.NOTES
#########################################################################
Author:		Brad W. Beckwith
Date:		
Version:	v1.0.0
Purpose:	To output the length of time the system has been running.
#########################################################################

#>
    
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $false, ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string[]]$ComputerName = $Env:COMPUTERNAME
    )
    
    If ($ComputerName)
    {
        Write-Output "`n"
        ForEach ($Comp in $ComputerName) {
            $time = Get-WmiObject -class Win32_OperatingSystem -computer $Comp
            $t = $time.ConvertToDateTime($time.Lastbootuptime)
            [TimeSpan]$uptime = New-TimeSpan $t $(get-date)
            $upt = "$($uptime.days)d $($uptime.hours)h $($uptime.minutes)m $($uptime.seconds)S"
            Write-Output "$Comp uptime: $upt"
        }
    }
    else
    {
        $Mess = @()
        $Mess = "ComputerName was not entered or passed to",
        "the Function: Get-BBUptime."
        $Mess | ft | Out-String | Write-Error
    }
    
    Write-Output "`n"
} #End: Function Get-BBUptime

Function Set-BBFileTimeStamps
{
<#

.SYNOPSIS
    The purpose of this Function is to allow the user to change
    the CreationTime, LastWriteTime and LastAccessTime of one or
    more files and directories. The user can specify the directory
    to change or the name of a file in the directory.

.DESCRIPTION
    Changes File and/or Directory timestamps

.PARAMETER <path>
    [string] $path, default "Current directory of script."

.PARAMETER <date>
    [datetime] $ndays, default -35 days.

.PARAMETER <recurse>
    Default is False, not recursive

.EXAMPLE
    Set-BBFileTimeStamps -path C:\tmp\Errorlog.txt -ndays 30

    Output:

        Mode                LastWriteTime     Length Name                                                                                                                                              
    ----                -------------     ------ ----                                                                                                                                              
    d----         3/17/2016  12:21 PM            Audit                                                                                                                                             
    d----         3/17/2016  12:21 PM            Image                                                                                                                                             
    d----         3/17/2016  12:21 PM            PowerShell                                                                                                                                        
    -a---         3/17/2016  12:21 PM       1282 bios.html                                                                                                                                         
    -a---         3/17/2016  12:21 PM      24904 DevServerList.log                                                                                                                                 
    -a---         4/16/2016  12:32 PM          2 Errorlog.txt                                                                                                                                      
    -a---         3/17/2016  12:21 PM       4096 git_Directories.txt                                                                                                                               
    -a---         3/17/2016  12:21 PM       2676 JFServerList.log                                                                                                                                  
    -a---         3/17/2016  12:21 PM         82 LocalMACAddresses.html                                                                                                                            
    -a---         3/17/2016  12:21 PM       6040 xx.html

.EXAMPLE
    Set-BBFileTimeStamps -path C:\tmp -ndays -10
    This command will change the entire directory, but it's not recursive

    Output:
    Mode                LastWriteTime     Length Name                                                                                                                                              
    ----                -------------     ------ ----                                                                                                                                              
    d----          3/7/2016  12:41 PM            Audit                                                                                                                                             
    d----          3/7/2016  12:41 PM            Image                                                                                                                                             
    d----          3/7/2016  12:41 PM            PowerShell                                                                                                                                        
    -a---          3/7/2016  12:41 PM       1282 bios.html                                                                                                                                         
    -a---          3/7/2016  12:41 PM      24904 DevServerList.log                                                                                                                                 
    -a---          3/7/2016  12:41 PM          2 Errorlog.txt                                                                                                                                      
    -a---          3/7/2016  12:41 PM       4096 git_Directories.txt                                                                                                                               
    -a---          3/7/2016  12:41 PM       2676 JFServerList.log                                                                                                                                  
    -a---          3/7/2016  12:41 PM         82 LocalMACAddresses.html                                                                                                                            
    -a---          3/7/2016  12:41 PM       6040 xx.html

.EXAMPLE
    Set-BBFileTimeStamps -path C:\tmp -ndays -10 -recurse
    
.NOTES

    v1.0.0--Author:Brad Beckwith--Updated:Nov. 1, 2017
    
    Written By:    Brad Beckwith
    Date:          March 17, 2016
    Email:         brad.beckwith@gmail.com
    Version:       0.9.2

#>    
    
    [CmdletBinding()]
    Param (
        [Parameter(mandatory = $true, HelpMessage = "Default Path is C:\temp")]
        [string[]]$path = "C:\Temp",
        [Parameter(mandatory = $false, HelpMessage = "Default days back are 40")]
        [int]$ndays = -40,
        [Parameter(mandatory = $false, HelpMessage = "Recurse - Default: Off")]
        $m_recurse = $false
    ) # End: Param
    
    [datetime]$date = (Get-Date)
    $date = $date.AddDays($ndays)
    $mcmd = $null
    Write-Host "`nNew date is: $date" -ForegroundColor Yellow
    
    if ($m_recurse -eq $True -or $m_recurse -eq 1)
    {
        $mcmd = Get-ChildItem -Path $path -Recurse
    }
    else
    {
        $mcmd = Get-ChildItem -Path $path
    }
    
    $mcmd |
    ForEach-Object `
    {
        $_.CreationTime = $date
        $_.LastAccessTime = $date
        $_.LastWriteTime = $date
    } # End: ForEach
    
    
    Write-Host "`nDates have been changed. Exiting script..." -ForegroundColor Green
    
} #end Function Set-FileTimeStamps

Function Get-BBHardDriveSize
{
<#
.SYNOPSYS
    Gets local computer system hard drive sizes.
.DESCRIPTION
    Gets local computer system hard drive sizes and returns the
    information back to the users screen
.PARAMETER None

.EXAMPLE
    . .\Get-HardDriveSize 
    This example gets the hard drive information for the locally attached
    drive.

.INPUTS
    None

.OUTPUTS
    Hard Drive information

.NOTES
    
########################################################################
Author:		Brad W. Beckwith
Date:		January 2017
Version:	v1.0.0
Purpose:	Prints out the local hard drive information
########################################################################    
    
#>

[cmdletbinding(SupportsShouldProcess)]
param
(
    
)

BEGIN
{
    Write-Verbose "`nGathering information`n"
}

PROCESS
{
    Write-Verbose "Processing"
    
    if ($PSCmdlet.ShouldProcess)
    {
        
        # get calculated properties:
        $prop1 = @{
            Name        = 'DriveLetter'
            Expression  = { $_.DeviceID }
        }
        
        $prop2 = @{
            Name        = 'Free(GB)'
            Expression  = { [Math]::Round(($_.FreeSpace / 1GB), 1) }
        }
        
        $prop3 = @{
            Name        = 'Size(GB)'
            Expression  = { [Math]::Round(($_.Size / 1GB), 1) }
        }
        
        $prop4 = @{
            Name        = 'Percent'
            Expression  = { [Math]::Round(($_.Freespace * 100 / $_.Size), 1) }
        }
        
        # get all hard drives
        # $info = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $ComputerName | where { $_.DriveType -eq 3 } |`
        $info = Get-CimInstance -ClassName Win32_LogicalDisk |
            where { $_.DriveType -eq 3 } |`
            Select-Object -Property $prop1, $prop2, $prop3, $prop4
        
        Write-Verbose "Writing info to screen"
        $info
    }
    
    Write-Verbose "End Processing"
}

END
{
    Write-Verbose "`nComplete`n"
}
    
} #End Function: Get-HardDriveSize

Function Get-BBIKGFADUserACC
{
<#
.SYNOPSIS
    Searches for one or more Groups and lists the owner of the group.

.DESCRIPTION
    The default groups that are checked include:

    If you need to check another USER use the "-Search" parameter on the command line followed by an array
    of strings like this -Search ("[USER]","[USER]") 

.PARAMETER Search
    The Search parameter is used when a group that is not currently listed as default needs
    to be searched.

.EXAMPLE
    PS>Get-BBIKGFADUserACC
    
    This example searches the groups already included in the script. The following groups will
    be checked by default.
    "*IKGF*"
    "SQL_CCAM*"
    "SQL_IKGF*"
    "SYS_CCAM*"
    "SYS_CTAP*"
    "SYS_IKGF*"
    
.EXAMPLE
    PS>Get-BBIKGFADUserACC -Search "*IKGF*"
    
    This example shows the use of one group to search.

.EXAMPLE
    PS>Get-BBIKGFADUserACC -Search "*IKGF*","SQL_CCAM*"
    
    This example shows the use of one or more groups to search.
    
.EXAMPLE
    PS>Get-BBIKGFADUserACC -Search (Get-Content .\Users2Check.txt)
    
    This example shows the use of a text file containing one or more 
    groups each on it's own line, to search.

.NOTES
	Updated:    October 19, 2017
    V1.0.1:     Updated the help, adjusted the $Search VAR and created a Function.
    
    Author:     Brad Beckwith
	Group:      IKGF ISE
	V1.0.0:     Get Active Directory information to help with finding "User" account information.
	Date:       September 6, 2017
#>
    
    [cmdletBinding(SupportsShouldProcess = $True)]
    param (
        [parameter(
           mandatory = $false,
           ValueFromPipeline = $True,
           ValueFromPipelineByPropertyName = $True)
        ]
        [string[]]$Search = @("*IKGF*",
            "SQL_CCAM*",
            "SQL_IKGF*",
            "SYS_CCAM*",
            "SYS_CTAP*",
            "SYS_IKGF*"
        ) #End: Search Array
    ) #End: Param
    
    BEGIN
    {
        
    }
    PROCESS
    {
        If ($PSCmdlet.ShouldProcess)
        {
            try
            {
                $Search | % {
                    Get-AdUser -Filter 'Name -like $_' -Properties * |`
                    select DisplayName, SamAccountName, Created, LastLogonDate, Modified, PasswordLastSet,`
                           EmployeeID, PasswordExpired, Enabled
                } #End: Search
            }
            catch
            {
                Write-Host "Could not get information for $Search."
            }
        }
        Else
        {
            Write-Error "Nothing to search or 'SupportsShouldProcess' is False"
        }
    }
    END
    {
        
    }
    
} #End: Function Get-BBIKGFADUserACC

Function Get-BBIKGFADGrpMbrACC
{
<#	

.SYNOPSIS
    Return a listing of all Users belonging to the AD group requested
    by the user.
.DESCRIPTION
    Return a listing of all Users belonging to the AD group requested
    by the user.
.PARAMETER Search
    Search is the variable that contains the requested Active Directory
    group in which the user is looking for group members.
.EXAMPLE
    Get-BBIKGFADGrpMbrACC "IKGF ISE Staff"
.INPUTS
    Active Directory Group to search for users
.OUTPUTS
    Listing of all users currently listed within the Active Directory
    group.
.LINK
    None
.NOTES
########################################################################
Author:		Brad W. Beckwith
Date:		
Version:	v1.1.0
Purpose:	Return a listing of all Users belonging to the AD 
            group requested by the user.
########################################################################
	
#>
    
    [cmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Low')]
    param (
        [parameter(
           mandatory = $false,
           ValueFromPipeline = $True,
           ValueFromPipelineByPropertyName = $True)
        ]
        $Search = "IKGF Staff US"
    )
    
    $Search | % {
        Get-ADGroupMember $Search |`
        select Name, SamAccountName, SID, objectGUID | Sort Name
    }
    
} #End: Function Get-BBIKGFADGrpMbrACC

Function Get-BBPSVersion
{
<#	

.SYNOPSIS
    Returns the current PowerShell Version number on the local
    computer.
.DESCRIPTION
    Returns the current PowerShell Version number on the local
    computer.
.PARAMETER
    None
.EXAMPLE
    Get-BBPSVersion
.INPUTS
    None
.OUTPUTS
    Returns the current PowerShell Version information to the screen.
.LINK
    None

.NOTES
#########################################################################
Author:		Brad W. Beckwith
Date:	    2017	
Version:	v1.0.0
Purpose:	Returns the current PowerShell Version number to the
            screen for the local computer.
#########################################################################
	
#>
    
    $PSVersionTable.PSVersion
    
} #End: Function Get-BBPSVersion

Function Get-BBSN
{
<#	

.SYNOPSIS
    Returns the local systems serial number to the users screen.
.DESCRIPTION
    Returns the local systems serial number to the users screen.
.PARAMETER
    None
.EXAMPLE
Get-BBSN
.INPUTS
    None
.OUTPUTS
    None
.LINK
    None
.NOTES
#########################################################################
Author:		Brad W. Beckwith
Date:		
Version:	v1.0.0
Purpose:	Returns the local systems serial number to the users 
            screen.
#########################################################################
	
#>
    

    $serial = Get-WmiObject -Class Win32_ComputerSystemProduct |
    Select-Object -ExpandProperty IdentifyingNumber
    Write-Host "`n"
    "Local Systems Serial Number: $serial"
    Write-Host "`n"

} #End: Function Get-BBSN

Function Get-BBOSInfo
{
<#
.SYNOPSIS
    This Function will work with one or more computer names. The
    computer name must be at least three characters in length and no
    more than 20 characters long.
    The script will work on up to 150 computers at a time, but must
    have at least one. This also requires the Computer Name be at least
    one character, but no more than 20 characters long.
.DESCRIPTION
    Gets information on one or more computers.
.PARAMETER <ComputerName>
    localhost
.PARAMETER <NameLog>
    Creates a Log file with a number starting at zero and
    incrementing by one each time and outputs the results to
    the logfile.
.PARAMETER <Verbose>
    This outputs information to the screen as it runs and it
    does not need any parameters.
.PARAMETER <Debug>
    This outputs debug information to the screen and allows
    user interaction. If suspened, type 'exit' to return to
    the previous screen.
.EXAMPLE
    Get-BBOSInfo -ComputerName localhost -Verbose -NameLog
.EXAMPLE
    Get-BBOSInfo -ComputerName bwbeckwi-mobl2,localhost
.EXAMPLE
    Get-Content C:\computers.txt | Get-BBOSInfo -NameLog
.EXAMPLE
    Get-BBOSInfo -host bwbeckwi-mobl2
.EXAMPLE
    Import-Module ActiveDirectory
    Get-ADComputer -filter * | Select @{n='ComputerName';e={$_.Name}} |
    	Get-BBOSInfo
    Get-ADComputer -Filter 'Name -like "AZSKGF*"' |
    	Select @{n='ComputerName';e={$_.Name}} | Get-BBOSInfo
    Remove-Module ActiveDirectory
.NOTES
Written By: Brad Beckwith
Date:       Sunday, March 20, 2016
Purpose:    Use PowerShell script I have already written and
            place them somewhere I can use them quickly.

#>
    
    [cmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Low')]
    param (
        [parameter(mandatory = $True,
                   ValueFromPipeline = $True,
                   ValueFromPipelineByPropertyName = $True)
        ]
        [alias('hostname')]
        [ValidateLength(1, 20)]
        [ValidateCount(1, 150)]
        [string[]]$ComputerName,
        [switch]$NameLog
        
    ) #End: Param
    
    BEGIN
    {
        Set-Location -Path "C:\"
        If ($NameLog)
        {
            Write-Verbose "Finding name log file"
            
            $i = 0
            Do
            {
                #$LogFile = "Names-$i.txt"
                $LogFile = "$ComputerName-$i.txt"
                $i++
            }
            While (Test-Path $LogFile)
            
            Write-Verbose "Log file name will be $LogFile"
        }
        else
        {
            Write-Verbose "Name logging off"
        } #End: If $NameLog
        
        Write-Debug "Completed BEGIN block"
    } #End: BEGIN Block
    
    PROCESS
    {
        Write-Debug "Starting Process block"
        
        ForEach ($Computer in $ComputerName)
        {
            If ($PSCmdlet.ShouldProcess($Computer))
            {
                $Computer = $Computer.ToUpper()
                Write-Verbose "Now connecting to $Computer"
                
                If ($NameLog)
                {
                    $Computer | Out-File $LogFile -Append
                } #End: If $NameLog
                
                try
                {
                    $Continue = $True
                    #EV (ErrorVariable), EA (ErrorAction)
                    $os = Get-WmiObject -ErrorVariable myErr `
                                        -ErrorAction 'Stop' -ComputerName $ComputerName `
                                        -Class Win32_OperatingSystem |
                    Select Caption, BuildNumber, OSArchitecture,
                           ServicePackMajorVersion -First 1
                }
                catch
                {
                    Write-Verbose "Should be creating Error file now;Connection to $Computer failed"
                    $Continue = $false
                    $Computer | Out-File C:\Errors.txt
                    $myErr | Out-File C:\ErrorMessages.txt
                } #End: Catch
                
                If ($Continue)
                {
                    Write-Verbose "Connection to $Computer succeeded"
                    $bios = Get-WmiObject -ComputerName $ComputerName `
                                          -Class Win32_BIOS |
                    Select SerialNumber -First 1
                    $processor = Get-WmiObject -ComputerName $ComputerName `
                                               -Class Win32_Processor |
                    Select AddressWidth -First 1
                    $osarchitecture = $os.osarchitecture -replace '-bit', ''
                    
                    $mPSVersion = ($host).Version
                    
                    Write-Debug "Creating properties"
                    $properties = @{
                        'ComputerName'  = $Computer;
                        'OSVersion'     = $os.Caption;
                        'OSBuild'       = $os.BuildNumber;
                        'OSArchitecture' = $osarchitecture;
                        'OSSPVersion'   = $os.ServicePackMajorVersion;
                        'BIOSSerialNumber' = $bios.SerialNumber;
                        'ProcArchitecture' = $processor.addresswidth;
                        'PSVersion'     = $mPSVersion
                    } #End: $Properties
                    
                    Write-Debug "Creating output Object; ready to write to pipeline"
                    $obj = New-Object -TypeName PSObject -Property $properties #Creates new Object for output
                    Write-Output $obj |
                    Select ComputerName, BIOSSerialNumber, OSArchitecture, OSBuild,
                           OSSPVersion, OSVersion, PSVersion, ProcArchitecture
                    
                    $obj |
                    Select ComputerName, BIOSSerialNumber, OSArchitecture, OSBuild,
                           OSSPVersion, OSVersion, PSVersion, ProcArchitecture |
                            Out-File $LogFile
                    
                } #End: If $continue
                
            } #End: If $PSCmdlet
        } #End: ForEach
        
        Write-Debug "Completing Process block"
    } #End: Process Block
    
    END
    {
        Write-Verbose "Completed"
        Write-Debug "Completed END block"
    } #End: END Block
    
    
} #End: Function Get-BBOSInfo

Function Get-BBServicesToShutDn
{
<#	

.SYNOPSIS
    Returns a list of services that are running and can be shutdown.
.DESCRIPTION
    Returns a list of services that are running and can be shutdown
    on the current system
.PARAMETER
    None
.EXAMPLE
    Get-BBServicesToShutDn
.INPUTS
    None
.OUTPUTS
    List of services that can be shutdown.
.LINK
    None
.NOTES
#########################################################################
Author:		Brad W. Beckwith
Date:	    2018	
Version:	v1.0.0
Purpose:	Get a list of Services that can be shutdown to the user.
#########################################################################
	
#>
    [cmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Low')]
    param (
        
    )
    
    Write-Verbose "Listing Services that can be shut down."
    Get-Service |
    Where { $_.Status -eq "Running" -and $_.CanStop }
    
} #End: Function Get-BBServicesToShutDn

Function Get-BBiKGFServers
{
    
	<#
	.SYNOPSIS
		This Function creates output of sorted Computer names.
		
	.DESCRIPTION
		This Function creates output of sorted Computer names from a Domain.
	
	.PARAMETER None
		None at this time
	    
	.EXAMPLE 
		PS> Get-BBIKGFServers.ps1
	    
	    Just run the script and the output will be created in the directory
		you run this script from.
		PS>Get-BBiKGFServers
	    
	    The script check these names by default:
	    "AZSKGF*" 
	    "JFSKGF*"
	    "devazcam*" 
	    "devegcam*" 
	    "prdazcam*" 
	    "prdegcam*" 
	    "tstazcam*" 
	    "tstazcam*"
	
	.EXAMPLE 
		PS> Get-BBIKGFServers.ps1 | Out-File "C:\temp\Output.txt"
	    
	    This example outputs the server names to a file named 'Output.txt', located
	    in the 'C:\temp' directory
	    
	.INPUTS
	
	.OUTPUTS
	
	.NOTES
	    Updated by:     Brad Beckwith
	    v1.1.2:         Edited Help verbage and added 'ShouldProcess'
	    
		Updated by:		Brad Beckwith
		v1.1.0:         To create a list of Computer/Server names from our OU.
		Date:			September '16
		Change(s):      Function just outputs sorted computer name list from
						Active Directory
	
		Updated by:		Brad Beckwith
		v1.0.2:         To create a list of Computer/Server names from our OU.
		Date:			April'16
		Change(s):      Fixed to work in SA LAN
	        
		Written by:		Brad Beckwith
		v1.0.1:         To create a list of Computer/Server names from our OU.
		Date:			April'16
	    
	#>
    
    [cmdletBinding(SupportsShouldProcess)]
    param (
        
    )
    
    BEGIN
    {
        #Import Active Directory Module before running
        Import-Module ActiveDirectory
        
        $ad = Get-Module | Select Name -First 1
        $ans = ($ad).Name.Trim()
        
        Write-Host "`n"
        
    }
    PROCESS
    {
        if ($PSCmdlet.ShouldProcess)
        {
            
            If (!($ans -eq "ActiveDirectory"))
            {
                Write-Warning "Active Directory Module not loaded, exiting script!"
                break
            }
            
            $MyServerList = Get-ADComputer -Filter { Name -like "AZSKGF*" } | select -ExpandProperty Name
            $MyServerList += Get-ADComputer -Filter { Name -like "JFSKGF*" } | select -ExpandProperty Name
            $MyServerList += (Get-ADComputer -Filter { Name -like "devazcam*" }) | select -ExpandProperty Name
            $MyServerList += (Get-ADComputer -Filter { Name -like "devegcam*" }) | select -ExpandProperty Name
            $MyServerList += (Get-ADComputer -Filter { Name -like "prdazcam*" }) | select -ExpandProperty Name
            $MyServerList += (Get-ADComputer -Filter { Name -like "prdegcam*" }) | select -ExpandProperty Name
            $MyServerList += (Get-ADComputer -Filter { Name -like "tstazcam*" }) | select -ExpandProperty Name
            $MyServerList += (Get-ADComputer -Filter { Name -like "tstazcam*" }) | select -ExpandProperty Name
            
            try
            {
                If ($MyServerList)
                {
                    #Write-Output $MyServerList | Sort
                    $MyServerList | Sort
                }
                else
                {
                    Write-Warning "MyServerList Array was not created, exiting script!"
                    break
                }
            }
            catch
            {
                Write-Warning "Can't Write output to screen!"
                break
            }
            
        }
        else
        {
            Write-Error "Nothing to search or 'SupportsShouldProcess' is False"
        } #End: Should Process
    }
    END
    {
        
        Write-Host "`nCompleted" -ForegroundColor Green
        Write-Host "`n"
        
    }
    
    
} #End: Function Get-BBiKGFServers

Function Get-BBLocalGroupMembers
{
	<#
	
	    .SYNOPSIS
	    This Function will grab all users in a specific group or from multiple groups if "GroupName" is
	    left blank.
	
	    .DESCRIPTION
	
	    .PARAMETER Log
	
	    .EXAMPLE
	        Get-BBLocalGroupMembers -server . -GroupName administrators
	        Server      : .
	            Local Group : administrators
	            Name        : Administrator
	            Type        : User
	            Domain      :
	            SID         : S-1-5-21-1993726024-3208652947-2595274682-500
	
	            Server      : .
	            Local Group : administrators
	            Name        : Domain Admins
	            Type        : Group
	            Domain      : amr
	            SID         : S-1-5-21-725345543-602162358-527237240-512
	
	            Server      : .
	            Local Group : administrators
	            Name        : bwbeckwi
	            Type        : User
	            Domain      : amr
	            SID         : S-1-5-21-725345543-602162358-527237240-2154407
	    .EXAMPLE
	        Get-BBLocalGroupMembers -server . -GroupName administrators | ft -AutoSize
	            Server Local Group    Name                   Type  Domain SID
	            ------ -----------    ----                   ----  ------ ---
	            .      administrators Administrator          User         S-1-5-21-1993726024-3208652947-2595274682-500
	            .      administrators Domain Admins          Group amr    S-1-5-21-725345543-602162358-527237240-512
	            .      administrators bwbeckwi               User  amr    S-1-5-21-725345543-602162358-527237240-2154407
	            .      administrators Desktop Support Admins Group amr    S-1-5-21-725345543-602162358-527237240-6131
	            .      administrators IT Local Admins        Group amr    S-1-5-21-725345543-602162358-527237240-2112572
	            .      administrators sys_policymgr          User  amr    S-1-5-21-725345543-602162358-527237240-2393742
	    .EXAMPLE
	        Get-BBLocalGroupMembers -server . -GroupName administrators | ft -AutoSize | Out-File LocalGroupMembers.txt
	            Server Local Group    Name                   Type  Domain SID
	            ------ -----------    ----                   ----  ------ ---
	            .      administrators Administrator          User         S-1-5-21-1993726024-3208652947-2595274682-500
	            .      administrators Domain Admins          Group amr    S-1-5-21-725345543-602162358-527237240-512
	            .      administrators bwbeckwi               User  amr    S-1-5-21-725345543-602162358-527237240-2154407
	            .      administrators Desktop Support Admins Group amr    S-1-5-21-725345543-602162358-527237240-6131
	            .      administrators IT Local Admins        Group amr    S-1-5-21-725345543-602162358-527237240-2112572
	            .      administrators sys_policymgr          User  amr    S-1-5-21-725345543-602162358-527237240-2393742
	    .EXAMPLE
	        Get-BBLocalGroupMembers -server . -GroupName administrators | Sort-Object Name | Select-Object -Property Name, "Local Group", SID
	            Name                                                      Local Group                                               SID
	            ----                                                      -----------                                               ---
	            Administrator                                             administrators                                            S-1-5-21-1993726024-3208652947-2595274682-500
	            bwbeckwi                                                  administrators                                            S-1-5-21-725345543-602162358-527237240-2154407
	            Desktop Support Admins                                    administrators                                            S-1-5-21-725345543-602162358-527237240-6131
	            Domain Admins                                             administrators                                            S-1-5-21-725345543-602162358-527237240-512
	            IT Local Admins                                           administrators                                            S-1-5-21-725345543-602162358-527237240-2112572
	            sys_policymgr                                             administrators                                            S-1-5-21-725345543-602162358-527237240-2393742
	    .EXAMPLE
	        Get-BBLocalGroupMembers -server . -GroupName administrators | Sort-Object Name | Out-GridView
	    .EXAMPLE
	        Get-BBLocalGroupMembers -server . -GroupName administrators | Sort-Object Name | Select -Property "Local Group", Name,Server,SID,Domain | Out-GridView
	    .NOTES
	
	#>
    
    [cmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Low')]
    param (
        [Parameter(ValuefromPipeline = $true)] `
        [array]$server = $env:computername,
        [string]$GroupName = $null
    ) # End: param
    
    PROCESS
    {
        $finalresult = @()
        $computer = [ADSI]"WinNT://$server"
        
        if (!($groupName))
        {
            $Groups = $computer.psbase.Children | Where { $_.psbase.schemaClassName -eq "group" } |
            select -expand name -ErrorAction SilentlyContinue
        }
        else
        {
            $groups = $groupName
        }
        
        Try
        {
            $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry() |
            select name, objectsid
            $domain = $currentdomain.name
            $SID = $CurrentDomain.objectsid
            $DomainSID = (New-Object System.Security.Principal.SecurityIdentifier($sid[0], 0)).value
        }
        Catch
        {
            Write-Warning "Not connected to AD domain..."
        }
        Finally
        {
            #Write-Host "  " -ForegroundColor Yellow
        }
        
        foreach ($group in $groups)
        {
            $gmembers = $null
            $LocalGroup = [ADSI]("WinNT://$server/$group,group")
            
            $GMembers = $LocalGroup.psbase.invoke("Members")
            $GMemberProps = @{ Server = "$server"; "Local Group" = $group; Name = ""; Type = ""; ADSPath = ""; Domain = ""; SID = "" }
            $MemberResult = @()
            
            if ($gmembers)
            {
                foreach ($gmember in $gmembers)
                {
                    $membertable = new-object psobject -Property $GMemberProps
                    $name = $gmember.GetType().InvokeMember("Name", 'GetProperty', $null, $gmember, $null)
                    $sid = $gmember.GetType().InvokeMember("objectsid", 'GetProperty', $null, $gmember, $null)
                    $UserSid = New-Object System.Security.Principal.SecurityIdentifier($sid, 0)
                    $class = $gmember.GetType().InvokeMember("Class", 'GetProperty', $null, $gmember, $null)
                    $ads = $gmember.GetType().InvokeMember("adspath", 'GetProperty', $null, $gmember, $null)
                    $MemberTable.name = "$name"
                    $MemberTable.type = "$class"
                    $MemberTable.adspath = "$ads"
                    $membertable.sid = $usersid.value
                    
                    if ($userSID -like "$domainsid*")
                    {
                        $MemberTable.domain = "$domain"
                    } # End: if
                    
                    $MemberResult += $MemberTable
                    
                } #End: Foreach
                
            } #End: if
            
            $finalresult += $MemberResult
            
        } #End: foreach
        
        #$finalresult | select server,"Local Group",Name,Type,Domain,SID
        $finalresult | select server, "Local Group", Name
        
    } #End: Process
    
} #End: Function Get-LocalGroupMembers

Function Get-BBBiosInfo
{
<#	

.SYNOPSIS
    Returns BIOS information from the computer system.
.DESCRIPTION

.PARAMETER
    None
.EXAMPLE
    Get-BBBiosInfo
.INPUTS
    None
.OUTPUTS
    Returns BIOS information from the computer system to the users
    screen.
.LINK
    None
.NOTES
#########################################################################
Author:		Brad W. Beckwith
Date:		
Version:	v1.0.0
Purpose:	Returns BIOS information from the computer system.
#########################################################################
	
#>
    
    Get-WmiObject -Class win32_bios |`
    Select __SERVER, SMBIOSBIOSVersion, Name, Manufacture,
           SerialNumber, Version
    
} #End: Function Get-BBBiosInfo

Function Get-BBADComputerList
{
<#
.SYNOPSIS
Return a listing of iKGF OU computer names, not including listener names for clustered
servers.

.DESCRIPTION
This Function gets a list of computer names from LDAP (AD) in the IKGF OU

.PARAMETER Directory
This parameter sets the OU location to look for. Valid choices are one of the following
[ AMR | CPDCSA | CPDCSADR | IKGFSA | IKGFSADR ]

.PARAMETER Listen
This is a switch to include listener names (computer) in the output.

.EXAMPLE
PS>Get-BBADComputerList
This displays a sorted list of Computer names

.EXAMPLE
PS>(Get-BBADComputerList).Count
This returns the number of Computers found

.EXAMPLE
PS>Get-BBADComputerList -Directory [ AMR | CPDCSA | CPDCSADR | IKGFSA | IKGFSADR ]
This example works with any of the SA LAN domains

.EXAMPLE
PS>Get-BBADComputerList -Directory [ AMR | CPDCSA | CPDCSADR | IKGFSA | IKGFSADR ] -Verbose
This example works with any of the SA LAN domains and displays
verbose messages

.INPUTS
None

.OUTPUTS
List of sorted domain computer names.
This does not show Listener Names, unless requested.

.NOTES
v1.0.8--Author: Brad Beckwith--Date: May 1, 2018
Adding the 'CCR' domain to this script.

v1.0.7--Author: Brad Beckwith--Date: October 26, 2017
Validate only amr, cpdcsa, cpdcsadr, ikgfsa and ikgfsadr can be used
and that amr is set default

v1.0.6--Author: Brad Beckwith--Date: October 24, 2017
Added ability to change AD directorys for IKGF

v1.0.5--Author: Brad Beckwith--Date: October 23, 2017
Changed help and added a where clause to remove listenernames from the output

v1.0.0--Author: Brad Beckwith

Import-Module ActiveDirectory 
#>
	
	[cmdletBinding()]
	param (
		[ValidateSet("amr", "ccr", "cpdcsa", "cpdcsadr", "ikgfsa", "ikgfsadr")]
		[string]$Directory = 'amr',
		[switch]$Listen,
		[switch]$SetDebug
	)
	
	if ($SetDebug)
	{
		$DebugPreference = "Continue"
	}
	
	Write-Verbose "Search domain directory: $Directory"
	
	if ($Directory -eq 'amr')
	{
		Write-Verbose "Setting AMR search"
		$DirSearcher = New-Object DirectoryServices.DirectorySearcher([adsi]'LDAP://OU=Development,OU=iKGF,OU=Resources,DC=amr,DC=corp,DC=intel,DC=com')
		$DirSearcher = [adsisearcher][adsi]'LDAP://OU=iKGF,OU=Resources,DC=amr,DC=corp,DC=intel,DC=com'
	}
	
	if ($Directory -eq 'ccr')
	{
		#ccr.corp.intel.com/Resources/IT Client/Windows 8/Production/WTG
		Write-Verbose "Setting CCR search"
		$DirSearcher = New-Object DirectoryServices.DirectorySearcher([adsi]'LDAP://OU=Resources,DC=ccr,DC=corp,DC=intel,DC=com')
		$DirSearcher = [adsisearcher][adsi]'LDAP://OU=WTG,OU=Production,OU=Windows 8,OU=IT Client,OU=Resources,DC=ccr,DC=corp,DC=intel,DC=com'
		Write-Debug $DirSearcher
	}
	
	if ($Directory -eq 'cpdcsa')
	{
		Write-Verbose "Setting CPDCSA search"
		$DirSearcher = New-Object DirectoryServices.DirectorySearcher([adsi]'LDAP://OU=CPDC,OU=Resources,DC=CPDCSA,DC=local')
		$DirSearcher = [adsisearcher][adsi]'LDAP://OU=CPDC,OU=Resources,DC=CPDCSA,DC=local'
	}
	
	if ($Directory -eq 'cpdcsadr')
	{
		Write-Verbose "Setting CPDCSA search"
		$DirSearcher = New-Object DirectoryServices.DirectorySearcher([adsi]'LDAP://OU=CPDC,OU=Resources,DC=CPDCSADR,DC=local')
		$DirSearcher = [adsisearcher][adsi]'LDAP://OU=CPDC,OU=Resources,DC=CPDCSADR,DC=local'
	}
	
	if ($Directory -eq 'ikgfsa')
	{
		Write-Verbose "Setting IKGFSA search"
		$DirSearcher = New-Object DirectoryServices.DirectorySearcher([adsi]'LDAP://OU=CPDC,OU=Resources,DC=IKGFSA,DC=local')
		$DirSearcher = [adsisearcher][adsi]'LDAP://OU=CPDC,OU=Resources,DC=IKGFSA,DC=local'
	}
	
	if ($Directory -eq 'ikgfsadr')
	{
		Write-Verbose "Setting IKGFSADR search"
		$DirSearcher = New-Object DirectoryServices.DirectorySearcher([adsi]'LDAP://OU=CPDC,OU=Resources,DC=IKGFSADR,DC=local')
		$DirSearcher = [adsisearcher][adsi]'LDAP://OU=CPDC,OU=Resources,DC=IKGFSADR,DC=local'
	}
	
	
	Write-Verbose "Setting Computer Filter for $Directory"
	$DirSearcher.Filter = '(ObjectClass=Computer)'
	
	Write-Verbose "Finding all computer object names`n"
	Write-Debug "Directory = $Directory"
	
	if ($Listen)
	{
		Write-Debug "Listen is True"
		$Name = $DirSearcher.FindAll().GetEnumerator() | ForEach-Object { $_.Properties.name }
	}
	else
	{
		Write-Debug "Listen is False"
		if ($Directory -ieq 'ccr')
		{
			Write-Debug "Should be checking for CCR CTA"
			$Name = $DirSearcher.FindAll().GetEnumerator() | ForEach-Object { $_.Properties.name } |`
			where {
				($Directory -ieq "ccr") -and
				($_ -match 'cta') -and
				($_ -notmatch "msdtc") -and
				($_ -notmatch "mscs")
			}
		}
		else
		{
			Write-Debug "Checking directory $Directory"
			$Name = $DirSearcher.FindAll().GetEnumerator() | ForEach-Object { $_.Properties.name } |`
			where {
				($_ -notmatch "msdtc") -and
				($_ -notmatch "mscs")
			}
		}
	}
	
	$NewName = ($Name).ToUpper()
	
	$NewName | Sort
	
	Write-Verbose "Completed..."
	
} #End: Function Get-BBADComputerList

Function Get-BBInstalledSoftware
{
	#Requires -RunAsAdministrator
	
<#	
.SYNOPSIS
    This function gathers a list of installed software on a computer.
.DESCRIPTION
    This function gathers a list of installed software on a computer.
.PARAMETER ComputerName
.PARAMETER mdate
.PARAMETER mPath
.PARAMETER output
.PARAMETER outputcsv    
.EXAMPLE
    Get-BBInstalledSoftware
.EXAMPLE
    Get-BBInstalledSoftware -ComputerName 'AZSKGFADMND01'
.EXAMPLE
    Get-BBInstalledSoftware -ComputerName 'AZSKGFADMND01' -mdate '2017101600'
.EXAMPLE
    Get-BBInstalledSoftware -ComputerName 'AZSKGFADMND01' -mdate '2017101600' -mpath 'C:\temp\'
.NOTES
    v1.0.5      Added XML Output-February 12, 2018
    Updated by: Brad Beckwith

    v1.0.4      Added help to the script; not yet completed
    Updated by: Brad Beckwith
    
    v1.0.3      Adding documentation to help section - October 6, 2017
    Updated by: Brad Beckwith
    
    v1.0.2      Changed output file name by including the date and time the 
                script was run. - July 05, 2017
    Updated by: Brad Beckwith
	
    Version:    1.0.1
    Updated:    June 22, 2017
    Purpose:    Stopped information from being displayed on
                the default screen.
    Updated by: Brad Beckwith
	
    Version:	1.0.0
    Author:		Brad Beckwith
    Group:		IKGF ISE Team
    Date:		May 8, 2017
#>
	
	[CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Low')]
	param
	(
		[parameter(
				   ValueFromPipeline = $True,
				   ValueFromPipelineByPropertyName = $True)
		]
		[alias('hostname')]
		[ValidateLength(1, 16)]
		[ValidateCount(1, 125)]
		[string]$computername = ($env:Computername),
		[string]$mdate = (Get-Date -uformat "%Y%m%d%H%M%S"),
		[string]$mPath = 'C:\temp\',
		[string]$output = "$mPath$computername.SoftwareList.$mdate.txt",
		[string]$outputcsv = "$mPath$computername.SoftwareList.$mdate.csv",
		[string]$outputxml = "$mPath$computername.SoftwareList.$mdate.xml"
	)
	
	Write-Debug 'Check Parameter values:$computername,$mdate,$mPath,$output,$outputc'
	Write-Host "`nGathering software list`n" -ForegroundColor Green
	
	Write-Verbose "Creating empty arrays`n"
	$arry = @()
	$arrya = @()
	$arryb = @()
	
	Write-Verbose "Creating Array A`n"
	try
	{
		$arrya = invoke-command -ScriptBlock {
			Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall |
			Foreach { Get-ItemProperty $_.PsPath } |
			Where-Object { $_.Displayname -and ($_.Displayname -match ".*") } |
			Sort-Object Displayname | Select-Object DisplayName, Publisher, DisplayVersion
		} -ComputerName $computername
	}
	catch
	{
		Write-Host "Try for array 'A' Failed" -ForegroundColor Red
		exit
	}
	
	
	Write-Verbose "Creating Array B`n"
	try
	{
		$arryb = invoke-command -ScriptBlock {
			Get-ChildItem HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
			Foreach { Get-ItemProperty $_.PsPath } |
			Where-Object { $_.Displayname -and ($_.Displayname -match ".*") } |
			Sort-Object Displayname | Select-Object DisplayName, Publisher, DisplayVersion
		} -ComputerName $computername
	}
	catch
	{
		Write-Host "Try for array 'B' Failed" -ForegroundColor Red
		exit
	}
	
	Write-Verbose "Creating main Array`n"
	$arry = $arrya + $arryb
	
	
	if (Test-Path $mPath)
	{
		Write-Verbose "Selecting Columns of data and placing into output files.`n"
		#$arry | select DisplayName, Publisher, DisplayVersion -Unique | sort DisplayName
		$array_out = $arry | Select-Object PSComputerName, DisplayName, Publisher, DisplayVersion -Unique | Sort-Object DisplayName
		
		$array_out | Format-Table -AutoSize
		
		$array_out | Out-File $output
		$array_out | Export-Clixml $outputxml
		$array_out | Export-Csv $outputcsv
		
		Write-Host "Output is located in the following files: " -ForegroundColor Green
		Write-Host "`t$output" -ForegroundColor Green
		Write-Host "`t$outputxml" -ForegroundColor Green
		Write-Host "`t$outputcsv`n" -ForegroundColor Green
	}
	else
	{
		Write-Host "Output path does not exist.`n"
		
	}
	
} #End: Function Get-BBInstalledSoftware

Function Get-BBServiceInfo
{
	<#
	.SYNOPSIS
	Returns non standard service credentials for one or more computers
	
	.DESCRIPTION
	This script will use the current computer name to check if one or
	more computer names are not given to the script.
	
	.PARAMETER ComputerName
	The ComputerName parameter can be a string of one computer name or a list of
	comma seperated computer names. -ComputerName 'localhost','.' etc.
	
	.EXAMPLE
	Pipe computer names to the script as comma seperated strings (e.g. 'localhost','.','AZSKGFADMND01')
	PS C:\>'localhost','.','AZSKGFADMND01' | .\Get-BBServiceInfo.ps1
	
	.EXAMPLE
	Pipe computer names to the script as comma seperated strings and save to a file in the current directory.
	PS C:\>'localhost','.','AZSKGFADMND01' | .\Get-BBServiceInfo.ps1 | Out-File .\ServerInfo.txt
	
	.EXAMPLE
	Pipe computer names to the script as comma seperated strings (sorted) and save to a file in the current directory.
	PS C:\>'localhost','.','AZSKGFADMND01' | Sort | .\Get-BBServiceInfo.ps1 | Out-File .\ServerInfo.txt
	
	.EXAMPLE
	Uses a text file with computer names seperated by CR or CRLF (one line)
	for each computer name.
	PS C:\>.\Get-BBServiceInfo.ps1 -ComputerName (gc .\Servers.txt | Sort)
	
	.NOTES
	AUTHOR:        Brad Beckwith
	DATE:          October 3, 2017
	VERSION:       1.0.3
	
	v1.0.3	Updated the help section again by adding content for ".PARAMETER"
	v1.0.2	Created variable for NORMAL (default) Write-Host color and added
			more exampless
	v1.0.1	Added new Credentials to ignore
	v1.0.0	Initial Script
	#>
	
	[cmdletbinding(SupportsShouldProcess = $True, ConfirmImpact = 'Low')]
	param (
		[parameter(mandatory = $false,
				   Position = 0,
				   ValueFromPipeline = $True,
				   ValueFromPipelineByPropertyName = $True)
		]
		[string[]]$ComputerName = $env:COMPUTERNAME
	)
	
	# Set default color for Write-Host out put to screen-NORMAL
	[string]$fgc = 'Green'
	
	$ComputerName | foreach {
		Write-Host "Working on $_" -ForegroundColor $fgc
		$serviceList = @(gwmi -Class Win32_Service -ComputerName $_ -Property Name, StartName, SystemName -ErrorAction SilentlyContinue)
		$serviceList | Where {
			($_.StartName) -and`
			($_.StartName -ne "LocalSystem") -and`
			($_.StartName -ne "NT Authority\LocalService") -and`
			($_.StartName -ne "NT Authority\Local Service") -and`
			($_.StartName -ne "NT Authority\NetworkService") -and`
			($_.StartName -ne "NT Authority\Network Service")
		} | Select SystemName, StartName | Ft -AutoSize
	}
	
	
	Write-Host "`nCompleted`n" -ForegroundColor $fgc
} #End: Function Get-BBServiceInfo

Function Get-BBTestServer
{
	
	<#
		.SYNOPSIS
	
		.DESCRIPTION
	
		.PARAMETER ComputerName
	
		.EXAMPLE
	
		.INPUTS
	
		.OUTPUTS
	
		.LINK
	
		.NOTES
	
	#>
	
	<#
		Edited By:	Brad Beckwith
		Updated:  	September 21, 2016
		Purpose:	Remove Function and use as a tool instead of as a
					Function.
		Version:	1.1.1
	
		Edited By:	Brad Beckwith
		Updated:  	May 3, 2016
		Purpose:	Turn into a Function. Have the ability to use a text file
					of Server names to work from and not hard code the names
					into the script.
		Version:	1.1.0
	
		Author:    	Brad Beckwith
	    Date:      	April 14, 2016
		Purpose:   	Used for Admin Tasks to check for iLO connections
	    Version:   	v1.0.0
	#>
	[CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Low')]
	param (
		[Parameter(Mandatory = $false,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[string[]]$ComputerName = ($env:COMPUTERNAME)
	)
	
	BEGIN
	{
		
	}
	
	PROCESS
	{
		try
		{
			
			foreach ($Computer in $ComputerName)
			{
				
				Write-Verbose "Working on computer: $Computer"
				
				$status = @{
					"ComputerName" = $Computer;
					#	"TimeStamp" = (Get-Date -f s)
				}
				
				if (Test-Connection $Computer -Count 2 -Quiet)
				{
					
					$status["Results"] = "Up"
					
				}
				else
				{
					
					$status["Results"] = "Down"
					
				} # If
				
				$obj = New-Object -TypeName PSObject -Property $status
				
				Write-Output $obj
				
			} # Foreach-Object
			
		} #End: Try
		
		catch
		{
			
			Write-Verbose "Could not test server $Computer"
			
		} #End: Catch
	}
	
	END
	{
		
	}
	
} #End: Function Get-BBTestServer

Function Touch ($newfilename)
{
<#

	.SYNOPSIS
	Creates new file.

	.DESCRIPTION
	Creates new file.

	.PARAMETER N/A

	.EXAMPLE
	PS C:>. .\touch.ps1
	You will need to load the script from the current location
	of the PowerShell script.
	
	You may also load this in memory before hand in a PowerShell
	session and use at any time prior to closing the session.
	
	PS C:>touch [Name of File]
	
	PS C:>touch test.txt
	This will create the new file with the name entered
	by the user.
	
	.INPUTS

	.OUTPUTS
	File is created.
	
	.NOTES

	Author:		Brad Beckwith
	Date:		November 20, 2020
	Purpose:	Create new file
	Version:	1.0.0

#>
	
	if (Test-Path $newfilename)
	{
		$overwrite = Read-Host "File name already exists! Do you want to overwrite 'Y/n'?"
		switch ($overwrite)
		{
			"Y" {
				Remove-Item $newfilename;
				New-Item $newfilename | Out-Null;
				Break;
			}
			"y" {
				Remove-Item $newfilename;
				New-Item $newfilename;
				Break;
			}
			default {
				Write-Output "Please try again..."
			}
		}
	}
	Else
	{
		New-Item $newfilename | Out-Null
	}
	
} #End: Function Touch

Function Get-BBiKGFDomainServerList
{
		<#
	
	
		#>
	
	[cmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Low')]
	param (
		
	)
	
	$chc = Get-adcomputer -filter 'Name -like "AZSKGF*"' -Properties * |`
	Select DisplayName, OperatingSystem |`
	Where { $_.DisplayName -and $_.OperatingSystem } | Select DisplayName
	
	$jfc = Get-adcomputer -filter 'Name -like "JFSKGF*"' -Properties * |`
	Select DisplayName, OperatingSystem |`
	Where { $_.DisplayName -and $_.OperatingSystem } | Select DisplayName
	
	$devaz = Get-adcomputer -filter 'Name -like "DEVAZCAM*"' -Properties * |`
	Select DisplayName, OperatingSystem |`
	Where { $_.DisplayName -and $_.OperatingSystem } | Select DisplayName
	
	$deveg = Get-adcomputer -filter 'Name -like "DEVEGCAM*"' -Properties * |`
	Select DisplayName, OperatingSystem |`
	Where { $_.DisplayName -and $_.OperatingSystem } | Select DisplayName
	
	$tstaz = Get-adcomputer -filter 'Name -like "TSTAZCAM*"' -Properties * |`
	Select DisplayName, OperatingSystem |`
	Where { $_.DisplayName -and $_.OperatingSystem } | Select DisplayName
	
	$tsteg = Get-adcomputer -filter 'Name -like "TSTEGCAM*"' -Properties * |`
	Select DisplayName, OperatingSystem |`
	Where { $_.DisplayName -and $_.OperatingSystem } | Select DisplayName
	
	$prdaz = Get-adcomputer -filter 'Name -like "PRDAZCAM*"' -Properties * |`
	Select DisplayName, OperatingSystem |`
	Where { $_.DisplayName -and $_.OperatingSystem } | Select DisplayName
	
	$prdeg = Get-adcomputer -filter 'Name -like "PRDEGCAM*"' -Properties * |`
	Select DisplayName |`
	Where { $_.DisplayName }
	
	$ikgf = $chc + $jfc + $devaz + $deveg + $tstaz + $tsteg + $prdaz + $prdeg
	
	$ikgf | Sort DisplayName | Where { $_.DisplayName }
	
} #End: Function Get-BBiKGFDomainServerList

Function Get-BBAdvOSInfo
{
<#
.SYNOPSIS
    To get information on one or more computers, which contains 'ComputerName', 'OSVersion',
    'OSBuild', 'OSArchitecture', 'OSSPVersion', 'BIOSVersion', 'BIOSMajorVersion',
    'BIOSMinorVersion' and 'ProcArchitecture'
.DESCRIPTION
    To get information on one or more computers, which contains 'ComputerName', 'OSVersion',
    'OSBuild', 'OSArchitecture', 'OSSPVersion', 'BIOSVersion', 'BIOSMajorVersion',
    'BIOSMinorVersion' and 'ProcArchitecture'
.PARAMETER ComputerName
    Name of one or more computers
.PARAMETER NameLog
    Switch, which determine if a log file is created
.EXAMPLE
    Get-BBAdvOSInfo -ComputerName 'LocalHost'
.EXAMPLE
    Get-BBAdvOSInfo -ComputerName 'LocalHost' -Verbose
.EXAMPLE
    Get-BBAdvOSInfo -ComputerName (Get-Content C:\temp\Servers.txt | Sort)
.EXAMPLE
    Get-BBAdvOSInfo -ComputerName (Get-Content C:\temp\Servers.txt | Sort) -NameLog -Verbose
.EXAMPLE
    Get-BBAdvOSInfo -ComputerName (Get-Content .\Servers.txt | Select -First 3 | sort)
.EXAMPLE
    Get-BBAdvOSInfo -ComputerName (Get-Content .\Servers.txt | sort) | Export-Clixml .\ServerBIOSInfo.xml
.NOTES
    v1.0.8-Author:Brad Beckwith:Date-20171110
    Purpose:    Fixed Error log file

    v1.0.7-Author:Brad Beckwith:Date-20171109
    Purpose:    Fixed PowerShell Version
    
    v1.0.6-Author:Brad Beckwith:Date-20171107
    Purpose:    Added BIOS Manufacturer and Name
    
    v1.0.5-Author:Brad Beckwith:Date-20171024
    Purpose:    Added PowerShell Version

    v1.0.4-Author:Brad Beckwith:Date-20171016
    Purpose:    Changed 'SupportShouldProcess' and 'ConfirmImpact'
    
    v1.0.3-Author:Brad Beckwith:Date-20171016
    Purpose:    Clean up comments/wording and rename log file.
    
    V1.0.2-Author:Brad Beckwith:Date-20171013
    Purpose:    To get information on one or more computers.
#>
	
	[cmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
	param (
		[parameter(mandatory = $true,
				   ValueFromPipeline = $True,
				   ValueFromPipelineByPropertyName = $True)
		]
		[alias('hostname')]
		[ValidateLength(1, 16)]
		[ValidateCount(1, 150)]
		[string[]]$ComputerName,
		[string]$LogFile,
		[switch]$NameLog
		
		
	) #End: Param
	
	BEGIN
	{
		
		If ($NameLog)
		{
			Write-Verbose "Creating new log file"
			
			$i = 0
			
			Do
			{
				$LogFile = ".\BBAdvOSInfoLog-$i.txt"
				$i++
			}
			While (Test-Path -Path $LogFile)
			
		}
		else
		{
			Write-Verbose "Logging off"
		} #End: If $NameLog
		
		If ($LogFile)
		{
			$MyStart = (Get-Date -Format "yyyyMMddHHmmss")
			Write-Output "Log created at $MyStart" | Out-File $LogFile
			Write-Verbose "Log file $LogFile"
		}
		
		Write-Debug "Completed BEGIN block"
		
	} #End: BEGIN Block
	
	PROCESS
	{
		Write-Debug "Starting Process block"
		
		ForEach ($Computer in $ComputerName)
		{
			If ($PSCmdlet.ShouldProcess($Computer))
			{
				Write-Verbose "Now connecting to $Computer"
				
				try
				{
					$Continue = $True
					#EV (ErrorVariable), EA (ErrorAction)
					$os = Get-WmiObject -ErrorVariable myErr `
										-ErrorAction 'Stop' `
										-ComputerName $Computer `
										-Class Win32_OperatingSystem |
					Select Caption, BuildNumber, OSArchitecture,
						   ServicePackMajorVersion `
						   -First 1
				}
				catch
				{
					Write-Verbose "Should be creating Error file now;`
						Connection to $Computer failed"
					$Continue = $false
					
					#If Error log switch is True
					If ($NameLog)
					{
						Write-Debug "Check NameLog"
						#$Computer | Out-File $LogFile -Append
						Write-Output  "Connection to $Computer failed" | Out-File $LogFile -Append
						#$myErr | Out-File $LogFile -Append
					}
					
				} #End: Catch
				
				If ($Continue)
				{
					Write-Verbose "Connection to $Computer succeeded"
					$bios = Get-WmiObject -Class Win32_BIOS -ComputerName $Computer |`
					Select SMBIOSBIOSVersion, SMBIOSMajorVersion, SMBIOSMinorVersion, SerialNumber, BIOSVersion -First 1
					
					$processor = Get-WmiObject -Class Win32_Processor -ComputerName $Computer |`
					Select AddressWidth -First 1
					
					$osarchitecture = $os.osarchitecture -replace '-bit', ''
					
					#$mPSVersion = $PSVersionTable.psversion.major
					$mPSVersion = Invoke-Command -Computername $Computer -Scriptblock { $PSVersionTable.psversion }
					
					Write-Debug "Creating properties"
					#Creating PSCustomObject-properties
					$properties = @{
						'ComputerName' = $Computer;
						'OSVersion'    = $os.Caption;
						'OSBuild'	   = $os.BuildNumber;
						'OSArchitecture' = $osarchitecture;
						'OSSPVersion'  = $os.ServicePackMajorVersion;
						'BIOSSerialNumber' = $bios.SerialNumber;
						'BIOSVersion'  = $bios.SMBIOSBIOSVersion;
						'BIOSMajorVersion' = $bios.SMBIOSMajorVersion;
						'BIOSMinorVersion' = $bios.SMBIOSMinorVersion;
						'BIOSManufacturer' = $bios.Manufacturer;
						'BIOSName'	   = $bios.Name;
						'ProcArchitecture' = $processor.addresswidth;
						'PowerShellVersion' = $mPSVersion
					} #End: $Properties
					
					Write-Debug "Creating output Object, ready to write to pipeline"
					$obj = New-Object -TypeName PSObject `
									  -Property $properties
					Write-Output $obj
					If ($LogFile)
					{
						$obj | Out-File $LogFile -Append
					}
					
				} #End: If $continue
				
			} #End: If $PSCmdlet
			
		} #End: ForEach
		
		Write-Debug "Completing Process block"
	} #End: Process Block
	
	END
	{
		$MyStop = (Get-Date -Format "yyyyMMddHHmmss")
		
		If ($LogFile)
		{
			Write-Output "Log ended at $MyStop" | Out-File $LogFile -Append
		}
		Write-Verbose "Completed END block"
		
	} #End: END Block
	
} #End: Function Get-BBAdvOSInfo

Function Get-BBNICPropInfo
{
<#
.SYNOPSIS

.DESCRIPTION

.PARAMETER

.INPUTS

.OUTPUTS

.NOTES
v1.0.1
Downloaded from Web and modified by Brad Beckwith-January 19, 2018

Create a hash table where the key holds the selected properties to display, 
and the value is the original object
#>
	
	$hashTable = Get-WmiObject -Class Win32_NetworkAdapterConfiguration |
	# sort the objects by a property of your choice
	Sort-Object -Property Description |
	# use an ordered hash table to keep sort order
	# (requires PowerShell 3; for older PowerShell remove [Ordered])
	ForEach-Object { $ht = [Ordered]@{ } }{
		# specify the properties that you would like to show in a grid view window
		$key = $_ | Select-Object -Property Description, IPAddress, MacAddress
		$ht.Add($key, $_)
	}{ $ht }
	Group-Object -Property Description, Index -AsHashTable -AsString
	
	# show the keys in the grid view window 
	$hashTable.Keys |
	Out-GridView -Title "Select Network Card" -OutputMode Multiple |
	ForEach-Object {
		# and retrieve the original (full) object by using
		# the selected item as key into your hash table
		$selectedObject = $hashTable[$_]
		$selectedObject | Select-Object -Property *
	}
	
} #End: Function Get-BBNICProcInfo

Function Write-Log
{
<#
.Synopsis
   Write-Log writes a message to a specified log file with the current time stamp.
.DESCRIPTION
   The Write-Log Function is designed to add logging capability to other scripts.
   In addition to writing output and/or verbose you can write to a log file for
   later debugging.
.NOTES
   Created by: Jason Wasser @wasserja
   Modified: 11/24/2015 09:30:19 AM  

   Changelog:
    * Code simplification and clarification - thanks to @juneb_get_help
    * Added documentation.
    * Renamed LogPath parameter to Path to keep it standard - thanks to @JeffHicks
    * Revised the Force switch to work as it should - thanks to @JeffHicks

   To Do:
    * Add error handling if trying to create a log file in a inaccessible location.
    * Add ability to write $Message to $Verbose or $Error pipelines to eliminate
      duplicates.
.PARAMETER Message
   Message is the content that you wish to add to the log file. 
.PARAMETER Path
   The path to the log file to which you would like to write. By default the Function will 
   create the path and file if it does not exist. 
.PARAMETER Level
   Specify the criticality of the log information being written to the log (i.e. Error, Warning, Informational)
.PARAMETER NoClobber
   Use NoClobber if you do not wish to overwrite an existing file.
.EXAMPLE
   Write-Log -Message 'Log message' 
   Writes the message to c:\Logs\PowerShellLog.log.
.EXAMPLE
   Write-Log -Message 'Restarting Server.' -Path c:\Logs\Scriptoutput.log
   Writes the content to the specified log file and creates the path and file specified. 
.EXAMPLE
   Write-Log -Message 'Folder does not exist.' -Path c:\Logs\Script.log -Level Error
   Writes the message to the specified log file as an error message, and writes the message to the error pipeline.
.LINK
   https://gallery.technet.microsoft.com/scriptcenter/Write-Log-PowerShell-999c32d0
#>	
	
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[Alias("LogContent")]
		[string]$Message,
		[Parameter(Mandatory = $false)]
		[Alias('LogDir')]
		[string]$LogPath = 'C:\Logs\PowerShell_Log.log',
		[Parameter(Mandatory = $false)]
		[ValidateSet("Error", "Warn", "Info")]
		[string]$Level = "Info",
		[Parameter(Mandatory = $false)]
		[switch]$NoClobber
	)
	
	Begin
	{
		# Set VerbosePreference to 'Continue' so that verbose messages are displayed.
		$VerbosePreference = 'Continue'
	}
	Process
	{
		
		# If the file already exists and NoClobber was specified, do not write to the log.
		if ((Test-Path $LogPath) -AND $NoClobber)
		{
			Write-Error "Log file $LogPath already exists, and you specified NoClobber.`
            Either delete the file or specify a different name."
			Return
		}
		
		# If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
		elseif (!(Test-Path $LogPath))
		{
			Write-Verbose "Creating $LogPath."
			$NewLogFile = New-Item $LogPath -Force -ItemType File
		}
		
		else
		{
			# Nothing to see here yet.
		}
		
		# Format Date for our Log File
		$FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
		
		# Write message to error, warning, or verbose pipeline and specify $LevelText
		switch ($Level)
		{
			'Error' {
				Write-Error $Message
				$LevelText = 'ERROR:'
			}
			'Warn' {
				Write-Warning $Message
				$LevelText = 'WARNING:'
			}
			'Info' {
				Write-Verbose $Message
				$LevelText = 'INFO:'
			}
		}
		
		# Write log entry to $LogPath
		"$FormattedDate $LevelText $Message" | Out-File -FilePath $LogPath -Append
	}
	End
	{
		
	}
	
} #End: Function Write-Log

Function GDT
{
	$ret = get-date -uformat "%Y%m%dT%H%M%S"
	Write-Output $ret
}

Function Get-BBLogonInfo
{
<#	

.SYNOPSIS

.DESCRIPTION

.PARAMETER InstanceID
InstanceID

.EXAMPLE
Get-BBLogonInfo.ps1 | Select Time,Domain,User,Method

.EXAMPLE
Get-BBLogonInfo.ps1 | Select Time,Domain,User,Method | Export-CSV .\Logons.txt

.EXAMPLE
Get-BBLogonInfo.ps1 | Select Time,Domain,User,Method | Out-GridView

.EXAMPLE
Get-BBLogonInfo.ps1 | Where-Object {$_.LogonType -eq 7} | Out-GridView

.EXAMPLE
Get-BBLogonInfo.ps1 | Out-GridView

.INPUTS
InstanceID

.OUTPUTS
List of Logons

.LINK
None

.NOTES
#########################################################################
Author:		Brad W. Beckwith
Date:		
Version:	v1.0.0
Purpose:	Print Logon information to the screen or file to provide
            the ability to review logon information
#########################################################################

#>
	
	[cmdletbinding()]
	param (
		[int]$InstanceID = 4624
	)
	
	Get-EventLog -LogName Security -InstanceId $InstanceID |
	ForEach-Object {
		[PSCustomObject]@{
			Time = $_.TimeGenerated
			LogonType = $_.ReplacementStrings[8]
			Process = $_.ReplacementStrings[9]
			Domain = $_.ReplacementStrings[5]
			User = $_.ReplacementStrings[6]
			Method = $_.ReplacementStrings[10]
			Source = $_.Source
			
		}
	}
}



####################################################################
##########################  Stopped Here  ##########################
####################################################################


Function Install-File
{
    
	<#
	.SYNOPSIS
		<TBD>
	.DESCRIPTION
		<TBD>
	.PARAMETER Install Single File
		<TBD>
	.PARAMETER B
		<TBD>
	.EXAMPLE
		Install-File -file "C:\Users\bwbeckwi\Downloads\ActiveState Perl\ActivePerl-5.20.2.2001-MSWin32-x64-298913.msi" -args $true -arguments "/qf /norestart"
		Install-File -file "C:\Users\bwbeckwi\Downloads\ActiveState Perl\ActivePerl-5.20.2.2001-MSWin32-x64-298913.msi" -args $true -arguments "/qf /norestart" -Verbose
	.EXAMPLE
		Install-File -file "C:\Users\bwbeckwi\Downloads\7Zip\7z1604-x64.msi" -args $true -arguments "/qn /norestart"
		Install-File -file "C:\Users\bwbeckwi\Downloads\7Zip\7z1604-x64.msi" -args $true -arguments "/qn /norestart" -Verbose
	.EXAMPLE
		Write-Host "`n[Name of Software and version]" -ForegroundColor Green
	    Install-File -file "[path here]" -args $true -arguments "/qf /norestart"
		The '/qf' makes sure to get information from the person installing the software
	
		Install-File -file "\\$server\0A ISE SW\Utilities\7Zip\7z1602-x64.exe" -args $true -arguments "/qn /norestart"
		The '/qn' just installs in the default location for the program
	
	.NOTES
		Idea by:		Michael Beckwith
		Date:			March 2017
		Writtenby:		Brad Beckwith
		Version:		1.0.0
	
		Updated by:		Brad Beckwith
		Version:		1.0.1
	
	#>
    
    [cmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Low')]
    param
    (
        [parameter(Mandatory = $true,
                   ValueFromPipeline = $True,
                   ValueFromPipelineByPropertyName = $True)]
        [string]$file,
        [parameter(Mandatory = $true,
                   ValueFromPipeline = $True,
                   ValueFromPipelineByPropertyName = $True)]
        [bool]$args = $false,
        [parameter(Mandatory = $false,
                   ValueFromPipeline = $True,
                   ValueFromPipelineByPropertyName = $false)]
        [string]$arguments = "/qf /norestart",
        [parameter(Mandatory = $false,
                   ValueFromPipeline = $True,
                   ValueFromPipelineByPropertyName = $True)]
        [switch]$NameLog = $true
    )
    
    If ($NameLog)
    {
        #Write-Verbose "Finding name log file"
        $LogPath = Get-Location
        
        $i = 0
        Do
        {
            $LogFile = "$LogPath\MasterLog-$i.Log"
            $i++
        }
        While (Test-Path $LogFile)
        
        Write-Host "`nLog file name is: $LogFile" -ForegroundColor Yellow
        
    } #End: If $NameLog
    
    if (Test-path $file)
    {
        Write-Verbose "Installing: $file"
        Write-Output "Installing $file" | Out-File -FilePath $LogFile -Append
        
        if ($args -eq $true)
        {
            Write-Verbose "We have arguments: $arguments"
            Start-Process $file -ArgumentList $arguments -Wait
            Write-Host "Install Complete...`n" -ForegroundColor Green
        }
        else
        {
            Write-Verbose "No arguments provided"
            Start-Process $file -Wait
            Write-Host "Install Complete...`n" -ForegroundColor Green
        } #End:$args
        
    }
    else
    {
        Write-Host "Install not completed..." -ForegroundColor Red
        Write-Host "`tSee Log file $LogFile`n" -ForegroundColor Yellow
        Write-Verbose "Install File: $file does not exist..."
        Write-Output "`nInstall File: $file does not exist..." | Out-File -FilePath $LogFile -Append
    } #End:Test-Path $file
    
} #End: Function Install-File

Function Disable-UAC
{
    ## Disable UAC
    Write-Host "`nDisabling UAC Control" -ForegroundColor Green
    New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system `
                     -Name EnableLUA -PropertyType DWord -Value 0 -Force
} #End: Function Disable-UAC

Function Enable-UAC
{
    ## Disable UAC
    Write-Host "`nDisabling UAC Control" -ForegroundColor Green
    New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system `
                     -Name EnableLUA -PropertyType DWord -Value 1 -Force
} #End: Function Enable-UAC

Function Disable-Cortana
{
    
    # Disable Cortana
    Write-Host "Disabling Cortana..." -ForegroundColor Green
    
    If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings"))
    {
        New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    
    If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization"))
    {
        New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
    }
    
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    
    If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore"))
    {
        New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
} #End: Function Disable-Cortana

Function Enable-Cortana
{
    # Enable Cortana
    Write-Host "Disabling Cortana..." -ForegroundColor Green
    
    If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings"))
    {
        New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 1
    
    If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization"))
    {
        New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
    }
    
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    
    If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore"))
    {
        New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
} #End: Function Enable-Cortana

Function Disable-Firewall
{
    # Disable Firewall
    Write-Host "Disabling Firewall..." -ForegroundColor Green
    Set-NetFirewallProfile -Profile * -Enabled False
} #End: Function Disable-Firewall

Function Enable-Firewall
{
    # Enable Firewall
    Write-Host "Enabling Firewall..." -ForegroundColor Green
    Set-NetFirewallProfile -Profile * -Enabled True
} #End: Function Enable-Firewall

Function Disable-Defender
{
    # Disable Windows Defender
    Write-Host "Disabling Windows Defender..."
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
} #End: Function Disable-Defender

Function Enable-Defender
{
    # Enable Windows Defender
    Write-Host "Enabling Windows Defender..."
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 0
} #End: Function Enable-Defender

Function Enable-RemoteDesktop
{
    # Enable Remote Desktop w/o Network Level Authentication
    Write-Host "Enabling Remote Desktop w/o Network Level Authentication..." -ForegroundColor Green
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0
} #End: Function Enable-RemoteDesktop

Function Hide-SearchButton
{
    # Hide Search button / box
    Write-Host "Hiding Search Box / Button..." -ForegroundColor Green
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
} #End: Function Hide-SearchButton

Function Show-SearchButton
{
    # Show Search button / box
    Write-Host "Enabling Search Box / Button..." -ForegroundColor Green
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1
} #End: Function Show-SearchButton

Function Hide-TaskView
{
    # Hide Task View button
    Write-Host "Hiding Task View button..." -ForegroundColor Green
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
} #End: Function Hide-TaskView

Function Show-TaskView
{
    # Show Task View button
    Write-Host "Enabling Task View button..." -ForegroundColor Green
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 1
} #End: Function Show-Taskview

