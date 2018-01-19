<#

    MODULE:  BBMODULE
   
    Updated: v2.2.7--Added Get-BBNICPropInfo--Lets Users select the NIC they want info for.
    Updated: v2.2.6--Updated Get-BBAdvOSInfo--Fixed the error message when not logging to file.
	Updated: v2.2.5--Updated Get-BBAdvOSInfo--Fixed the error log file switch and log
	Updated: v2.2.4--Updated Get-BBAdvOSInfo--Fixed PowerShell Version
	Updated: v2.2.3--Updated Get-BBAdvOSInfo--Getting more BIOS information
	Updated: v2.2.2--Added Set-BBFileTimeStamps Funciton
	Updated: v2.2.1--Changed Get-BBAdvOSInfo.ps1 to require the ComputerName parameter
	Updated: v2.2.0--Added Validation to Get-BBADComputerList
	Updated: v2.1.9--Updated the Get-BBADComputerList Function for multi-iKGF domains
	Updated: v2.1.8--Updated the Get-BBAdvOSInfo Function
	Updated: v2.1.7--Added the Get-BBADComputerList Function
	Updated: v2.1.6--Added the Get-BBHardDriveSize Function
	Updated: v2.1.5--Updated the following Functions: Get-BBIKGFADGroupACC,Get-BBIKGFADUserACC and Get-BBiKGFServers
	Updated: v2.1.4--Added new Function:Get-BBSAdvOSInfo
	Updated: v2.1.3--Added new Function:Get-BBServiceInfo
#>	
	
	Function Set-BBFileTimeStamps{
	    
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
	    
	} #end function Set-FileTimeStamps
	
	
	function Get-BBHardDriveSize{
	<#
	.SYNOPSYS
	
	.DESCRIPTION
	
	.PARAMETER 
	
	.EXAMPLE
	PS>. .\Get-HardDriveSize
	
	This example gets the hard drive information for the locally attached drive
	
	.INPUTS
	None
	
	.OUTPUTS
	Hard Drive information
	
	.NOTES
	v1.0.0:       Prints out the local hard drive information
	Author:       Brad Beckwith
	Date:         Jan. 2017
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
	                Name = 'DriveLetter'
	                Expression = { $_.DeviceID }
	            }
	            
	            $prop2 = @{
	                Name = 'Free(GB)'
	                Expression = { [Math]::Round(($_.FreeSpace / 1GB), 1) }
	            }
	            
	            $prop3 = @{
	                Name = 'Size(GB)'
	                Expression = { [Math]::Round(($_.Size / 1GB), 1) }
	            }
	            
	            $prop4 = @{
	                Name = 'Percent'
	                Expression = { [Math]::Round(($_.Freespace * 100 / $_.Size), 1) }
	            }
	            
	            # get all hard drives
	            #            $info = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $ComputerName | where { $_.DriveType -eq 3 } |`
	            $info = Get-CimInstance -ClassName Win32_LogicalDisk | where { $_.DriveType -eq 3 } |`
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
	
	
	function Get-BBIKGFADUserACC{
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
	    V1.0.1:     Updated the help, adjusted the $Search VAR and created a function.
	    
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
	
	
	function Get-BBIKGFADGrpMbrACC{
		[cmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Low')]
		param (
			[parameter(
					   mandatory = $false,
					   ValueFromPipeline = $True,
					   ValueFromPipelineByPropertyName = $True)
			]
			[string[]]$Search = ("IKGF Staff")
		)
		
		$Search | % {
			Get-ADGroupMember $Search  |`
			select Name, SamAccountName | Sort Name
		}
	} #End: Function Get-BBIKGFADGrpMbrACC
	
	
	function Get-BBPSVersion{
		
		$PSVersionTable.PSVersion
		
	} #End: Function Get-BBPSVersion
	
	
	function Get-BBSN{
		
		Clear
		cd "C:\"
		$serial = Get-WmiObject -Class Win32_ComputerSystemProduct |
		Select-Object -ExpandProperty IdentifyingNumber
		Write-Host "`n"
		"Serial Number is: $serial"
		Write-Host "`n"
		cd \
	} #End: Function Get-BBSN
	
	
	function Get-BBOSInfo{
	<#
	.SYNOPSIS
	This function will work with one or more computer names. The
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
	incrementing by one each time.
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
					$LogFile = "Names-$i.txt"
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
							'ComputerName' = $Computer;
							'OSVersion'    = $os.Caption;
							'OSBuild'	  = $os.BuildNumber;
							'OSArchitecture' = $osarchitecture;
							'OSSPVersion'  = $os.ServicePackMajorVersion;
							'BIOSSerialNumber' = $bios.SerialNumber;
							'ProcArchitecture' = $processor.addresswidth;
							'PSVersion'    = $mPSVersion
						} #End: $Properties
						
						Write-Debug "Creating output Object; ready to write to pipeline"
						$obj = New-Object -TypeName PSObject -Property $properties #Creates new Object for output
						Write-Output $obj |
						Select ComputerName, BIOSSerialNumber, OSArchitecture, OSBuild,
							   OSSPVersion, OSVersion, PSVersion, ProcArchitecture
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
	
	
	function Get-BBServicesToShutDn{
		
		#This currently work on the local machine only.
		
		[cmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Low')]
		#Support Whatif
		param (
			
		)
		
		Write-Verbose "Listing Services that can be shut down."
		Get-Service |
		Where { $_.Status -eq "Running" -and $_.CanStop }
		
	} #End: Function Get-BBServicesToShutDn
	
	
	function Get-BBiKGFServers{
	    
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
	
	
	Function Get-BBLocalGroupMembers{
	<#
	
	    .SYNOPSIS
	    This function will grab all users in a specific group or from multiple groups if "GroupName" is
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
	
	
	function Get-BBBiosInfo{
		
		Set-Location -Path "C:\"
		get-wmiobject win32_bios | ft -AutoSize
		
	} #End: Function Get-BBBiosInfo
	
	
	Function Get-BBADComputerList{
	<#
	.SYNOPSIS
	Return a listing of iKGF OU computer names, not including listener names for clustered
	servers.
	
	.DESCRIPTION
	This function gets a list of computer names from LDAP (AD) in the IKGF OU
	
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
	        [ValidateSet("amr", "cpdcsa", "cpdcsadr", "ikgfsa", "ikgfsadr")]
	        [string]$Directory = 'amr',
	        [switch]$Listen
	    )
	    
	    Write-Verbose "Search domain directory: $Directory"
	    
	    if ($Directory -eq 'amr')
	    {
	        Write-Verbose "Setting AMR search"
	        $DirSearcher = New-Object DirectoryServices.DirectorySearcher([adsi]'LDAP://OU=Development,OU=iKGF,OU=Resources,DC=amr,DC=corp,DC=intel,DC=com')
	        $DirSearcher = [adsisearcher][adsi]'LDAP://OU=iKGF,OU=Resources,DC=amr,DC=corp,DC=intel,DC=com'
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
	    
	    Write-Verbose "Finding all computer object names"
	    if ($Listen)
	    {
	        $Name = $DirSearcher.FindAll().GetEnumerator() | ForEach-Object { $_.Properties.name } |`
	        Sort-Object -Property Name
	    }
	    else
	    {
	        $Name = $DirSearcher.FindAll().GetEnumerator() | ForEach-Object { $_.Properties.name } |`
	        Sort-Object -Property Name |`
	        where {
	            #            ($_ -notmatch "DV`\d") -AND
	            ($_ -notmatch "msdtc") -AND
	            ($_ -notmatch "mscs")
	        }
	    }
	    
	    ($Name).ToUpper() | Sort
	    
	    Write-Verbose "Completed..."
	    
	} #End: Function Get-BBADComputerList
	
	
	Function Get-BBInstalledSoftware {
	<#	
	.SYNOPSIS
	.DESCRIPTION
	.EXAMPLE
	.PARAMETER
	.NOTES
	Version:    1.0.2
	Updated:    July 05, 2017
	Purpose:    Changed output file name by including the date and time the 
				script was run.
		
	Version:    1.0.1
	Updated:    June 22, 2017
	Purpose:    Stopped information from being displayed on
	            the default screen.
		
	Version:	1.0.0
	Author:		Brad Beckwith
	Group:		IKGF ISE Team
	Date:		May 8, 2017
	#>
		
		[CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Low')]
		param
		(
			[parameter(mandatory = $false,
					   ValueFromPipeline = $True,
					   ValueFromPipelineByPropertyName = $True)
			]
			[alias('hostname')]
			[ValidateLength(1, 16)]
			[ValidateCount(1, 125)]
			[string]$computername = ($ENV:Computername),
			[string]$dt = (Get-Date -uformat "%Y%m%d%H%M%S"),
			[string]$output = "$computername.SoftwareList.$dt.txt",
			[string]$outputcsv = "$computername.SoftwareList.$dt.csv"
		)
		
		#CLEAR
		
		If (test-path 'C:\temp')
		{
			Set-Location -Path 'C:\temp'
		}
		Else
		{
			Write-Warning "Temp directory does not exist; Exiting Script"
			Exit
		}
		
		Write-Host "`nGathering local software list`n" -ForegroundColor Green
		
		Write-Verbose "Creating empty arrays`n"
		$arry = @()
		$arrya = @()
		$arryb = @()
		
		Write-Verbose "Creating Array A`n"
		$arrya = invoke-command {
			Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall |
			Foreach { Get-ItemProperty $_.PsPath } |
			where { $_.Displayname -and ($_.Displayname -match ".*") } |
			sort Displayname | select DisplayName, Publisher, DisplayVersion
		} -ComputerName $computername
		
		Write-Verbose "Creating Array B`n"
		$arryb = invoke-command {
			Get-ChildItem HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
			Foreach { Get-ItemProperty $_.PsPath } |
			where { $_.Displayname -and ($_.Displayname -match ".*") } |
			sort Displayname | select DisplayName, Publisher, DisplayVersion
		} -ComputerName $computername
		
		Write-Verbose "Creating main Array`n"
		$arry = $arrya + $arryb
		
		Write-Verbose "Selecting Columns of data and placing into output files.`n"
		$arry | select DisplayName, Publisher, DisplayVersion -Unique | sort DisplayName | Out-File $output
		
		# Creating CSV File
		if (Test-Path $output)
		{
			$a = Get-Content $output | Select -skip 1
			$a = $a -replace "`0", " "
			$a | out-file $output
			$a = $a -replace "\s{2,}", ","
			$a = $a -replace "Microsoft.P", "Microsoft"
			$a -replace ",$", "" | Out-Null
			$a = $a -replace ",$", ""
			$a | Out-file $outputcsv
			#$a | Select -skip 1 | Out-file $outputcsv
			
			Write-Host "`nCompleted... See ""$output"" for a list of installed software" -ForegroundColor Green
			
			if (Test-Path $outputcsv)
			{
				Write-Host "Completed... See ""$outputcsv"" for a list of installed software in CSV format`n" -ForegroundColor Green
			}
		}
		else
		{
			Write-Warning "Path/File: $output does not exist. Cannot create 'txt' or 'csv' files"
		}
		
	} #End: Function Get-BBInstalledSoftware
	
	
	function Get-BBServiceInfo{
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
	
	
	function Get-BBTestServer{
		
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
		Purpose:	Remove function and use as a tool instead of as a
					function.
		Version:	1.1.1
	
		Edited By:	Brad Beckwith
		Updated:  	May 3, 2016
		Purpose:	Turn into a function. Have the ability to use a text file
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
	
	
	function BBTouch{
	<#
	
	.SYNOPSIS
	Creates an empty file in the current directory
	
	.PARAMETER <none>
	
	.EXAMPLE
	C:\>touch "myfile"
	
	.NOTES
	############################################################
	#
	# Author:		Brad Beckwith
	# Function: 	touch
	# Updated by:	N/A
	# Date:			July 20, 2016
	# Version:		0.0.1
	# Purpose:		To have the ability to create an empty
	#				file.
	#
	############################################################
	Resembles touch in bash
	
	#>
		[cmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Low')]
		param (
			[Parameter(Mandatory = $true)]
			[string]$Name = "EmptyFile.txt",
			[string]$Loc = ".\"
		)
		Write-Debug "Zero"
		$rtn = New-Item -ItemType file -Name $Name
		Write-Debug "One"
		$rtn = "$Loc\$Name"
		Write-Debug "Two"
		Write-Output " " | Out-File $rtn
	} # Function BBTouch
	
	
	Function Get-BBiKGFDomainServerList{
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
	
	
	Function Install-File{
		
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
	
	
	Function Disable-UAC{
		## Disable UAC
		Write-Host "`nDisabling UAC Control" -ForegroundColor Green
		New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system `
						 -Name EnableLUA -PropertyType DWord -Value 0 -Force
	} #End: Function Disable-UAC
	
	
	Function Enable-UAC{
		## Disable UAC
		Write-Host "`nDisabling UAC Control" -ForegroundColor Green
		New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system `
						 -Name EnableLUA -PropertyType DWord -Value 1 -Force
	} #End: Function Enable-UAC
	
	
	Function Disable-Cortana{
		
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
	
	
	Function Enable-Cortana{
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
	
	
	Function Disable-Firewall{
		# Disable Firewall
		Write-Host "Disabling Firewall..." -ForegroundColor Green
		Set-NetFirewallProfile -Profile * -Enabled False
	} #End: Function Disable-Firewall
	
	
	Function Enable-Firewall{
		# Enable Firewall
		Write-Host "Enabling Firewall..." -ForegroundColor Green
		Set-NetFirewallProfile -Profile * -Enabled True
	} #End: Function Enable-Firewall
	
	
	Function Disable-Defender{
		# Disable Windows Defender
		Write-Host "Disabling Windows Defender..."
		Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
	} #End: Function Disable-Defender
	
	
	Function Enable-Defender{
		# Enable Windows Defender
		Write-Host "Enabling Windows Defender..."
		Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 0
	} #End: Function Enable-Defender
	
	
	Function Enable-RemoteDesktop{
		# Enable Remote Desktop w/o Network Level Authentication
		Write-Host "Enabling Remote Desktop w/o Network Level Authentication..." -ForegroundColor Green
		Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
		Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0
	} #End: Function Enable-RemoteDesktop
	
	
	Function Hide-SearchButton{
		# Hide Search button / box
		Write-Host "Hiding Search Box / Button..." -ForegroundColor Green
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
	} #End: Function Hide-SearchButton
	
	
	Function Show-SearchButton{
		# Show Search button / box
		Write-Host "Enabling Search Box / Button..." -ForegroundColor Green
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1
	} #End: Function Show-SearchButton
	
	
	Function Hide-TaskView{
		# Hide Task View button
		Write-Host "Hiding Task View button..." -ForegroundColor Green
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
	} #End: Function Hide-TaskView
	
	
	Function Show-TaskView{
		# Show Task View button
		Write-Host "Enabling Task View button..." -ForegroundColor Green
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 1
	} #End: Function Show-Taskview
	
	
	Function Get-BBAdvOSInfo{
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
	                $LogFile = "BBAdvOSInfoLog-$i.txt"
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
	            Write-Verbose "Log file $LogFile, is located in the current directory"
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
	                    $mPSVersion = Invoke-Command -Computername $Computer -Scriptblock { $PSVersionTable.psversion.major }
	                    
	                    Write-Debug "Creating properties"
	                    #Creating PSCustomObject-properties
	                    $properties = @{
	                        'ComputerName' = $Computer;
	                        'OSVersion' = $os.Caption;
	                        'OSBuild' = $os.BuildNumber;
	                        'OSArchitecture' = $osarchitecture;
	                        'OSSPVersion' = $os.ServicePackMajorVersion;
	                        'BIOSSerialNumber' = $bios.SerialNumber;
	                        'BIOSVersion' = $bios.SMBIOSBIOSVersion;
	                        'BIOSMajorVersion' = $bios.SMBIOSMajorVersion;
	                        'BIOSMinorVersion' = $bios.SMBIOSMinorVersion;
	                        'BIOSManufacturer' = $bios.Manufacturer;
	                        'BIOSName' = $bios.Name;
	                        'ProcArchitecture' = $processor.addresswidth;
	                        'PowerShellVersion' = $mPSVersion
	                    } #End: $Properties
	                    
	                    Write-Debug "Creating output Object, ready to write to pipeline"
	                    $obj = New-Object -TypeName PSObject `
	                                      -Property $properties
	                    Write-Output $obj
	                } #End: If $continue
	                
	            } #End: If $PSCmdlet
	            
	        } #End: ForEach
	        
	        Write-Debug "Completing Process block"
	    } #End: Process Block
	    
	    END
	    {
	        $MyStop = (Get-Date -Format "yyyyMMddHHmmss")
        
        if ($NameLog)
        {
            Write-Output "Log ended at $MyStop" | Out-File $LogFile
        }
        
        Write-Verbose "Completed END block"
	        
	    } #End: END Block
    
} #End: Function Get-BBAdvOSInfo


    function Get-BBNICPropInfo{
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
	
	#Export-ModuleMember -Function 'Get-*'