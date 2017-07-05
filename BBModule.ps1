#Requires -Version 3

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
				   ValueFromPipelineByPropertyName = $True)]
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
				
				if (Test-Connection $Computer -Count 2 -ea 0 -Quiet)
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

Function DisableUAC{
	## Disable UAC
	Write-Host "`nDisabling UAC Control" -ForegroundColor Green
	New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system `
					 -Name EnableLUA -PropertyType DWord -Value 0 -Force
}

Function EnableUAC{
	## Disable UAC
	Write-Host "`nDisabling UAC Control" -ForegroundColor Green
	New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system `
					 -Name EnableLUA -PropertyType DWord -Value 1 -Force
}

Function DisableCortana{
	
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
}

Function EnableCortana{
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
}

Function DisableFirewall{
	# Disable Firewall
	Write-Host "Disabling Firewall..." -ForegroundColor Green
	Set-NetFirewallProfile -Profile * -Enabled False
}

Function EnableFirewall{
	# Enable Firewall
	Write-Host "Enabling Firewall..." -ForegroundColor Green
	Set-NetFirewallProfile -Profile * -Enabled True
}

Function DisableDefender{
	# Disable Windows Defender
	Write-Host "Disabling Windows Defender..."
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
}

Function EnableDefender{
	# Enable Windows Defender
	Write-Host "Enabling Windows Defender..."
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 0
}

Function EnableRemoteDesktop{
	# Enable Remote Desktop w/o Network Level Authentication
	Write-Host "Enabling Remote Desktop w/o Network Level Authentication..." -ForegroundColor Green
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0
}

Function HideSearchButton{
	# Hide Search button / box
	Write-Host "Hiding Search Box / Button..." -ForegroundColor Green
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}

Function ShowSearchButton{
	# Show Search button / box
	Write-Host "Enabling Search Box / Button..." -ForegroundColor Green
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1
}

Function HideTaskView{
	# Hide Task View button
	Write-Host "Hiding Task View button..." -ForegroundColor Green
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}

Function ShowTaskView{
	# Show Task View button
	Write-Host "Enabling Task View button..." -ForegroundColor Green
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 1
}