<# The script performs the following:
        1. Updates the IP address and Hostname, creates a Scheduled Task, and restarts the OS
        2. Installs Active Directory and DNS, creates a Scheduled Task, and restarts the OS
        3. Installs DHCP and restarts the OS
#>

# Each parameter below has a default value; the default value is used if no param specified on script execution

[cmdletbinding()]
Param
    (
        # Set IP Address for this host
        [string]$ipAddress = '10.10.10.14',

        # Set DNS address (set to localhost IP because DNS runs on this server)
        [string]$dnsAddress = '127.0.0.1',

        # Set Hostname for this host
        [string]$hostname = 'ServerVM',

        # Set domain name
        [string]$domainName = 'homelab',

        # Set minimum IP address for DHCP to issue
        [string]$dhcpScopeStart = '10.10.10.20',

        # Set maximum IP address for DHCP to issue
        [string]$dhcpScopeEnd = '10.10.10.254',

        # Set Subnet Mask for this network
        [string]$dhcpSubnetMask = '255.255.255.0',

        # Set the time in which IP addresses issued by DHCP are valid for - e.g. 8.00:00:00 is good for 8 days
        [string]$dhcpLeaseDuration = '8.00:00:00',

        # Set the password in case you ever need to Repair, Restore, or otherwise Recover your Active Directory database
        [string]$password = 'homelab1!',

        # Set switch to know which part of the script to run. Needed for automatic script restart after user logon
        [switch]$one,
        [switch]$two,
        [switch]$three
    )

# Get the name of this script - this command only works if you run the script file, i.e., not from powershell_ise.exe
$scriptName = 'setup-server'

# Get the location where this script ran from
$location = 'C:\'

# Path to log file
$logPath = "$location$scriptName.log"


Function Get-TimeStamp
    {
        return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)  
    } # Get-TimeStamp


Function Update-Log
    {
        [cmdletbinding()]
        Param
        (
            $logMessage
        )

        Add-Content -Value "$(Get-TimeStamp) $logMessage." -Path $logPath -Force
    } # Update-Log


Function Configure-IPandDNS
    {
        [cmdletbinding()]
        Param
        (
            [string]$new_IPv4,
            [string]$new_DNS
        )

        Update-Log -logMessage "Configuring IPv4 interface settings"

        # Get old IPv4 address
        $old_IPv4 = (Get-NetIPConfiguration).IPv4Address.IPAddress

        Update-Log -logMessage "Identified previous IP address: $old_IPv4"

        # Remove old IPv4 address
        Remove-NetIPAddress -InterfaceAlias Ethernet -IPAddress $old_IPv4 -Confirm:$false

        Update-Log -logMessage "Replacing with new IP address: $new_IPv4"

        # Set new IPv4 address
        New-NetIPAddress -InterfaceAlias Ethernet -IPAddress $new_IPv4 -PrefixLength 24

        # Get current IPv4 address
        $current_IPv4 = (Get-NetIPConfiguration).IPv4Address.IPAddress

        # Verify IPv4 address is set correctly
        If ($current_IPv4 -ne $new_IPv4)
            {
                Update-Log -logMessage "Error: IPv4 address not set correctly. The script will now exit"
                Exit
            }
        Else
            {
                Update-Log -logMessage "IPv4 address set successfully"
                
                Update-Log -logMessage "Configuring DNS to use IP address: $new_DNS"

                # Configure DNS address
                Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses $new_DNS

                # Get DNS address
                $current_DNS = (Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).ServerAddresses

                # Verify DNS address is set correctly
                If ($current_DNS -ne $new_DNS)
                    {
                        Update-Log -logMessage "Error: DNS address not set correctly. The script will now exit"
                        Exit
                    }
                Else
                    {
                        Update-Log -logMessage "DNS address set successfully"
                    }
            }
    } # Configure-IPandDNS


Function Set-Hostname
    {
        [cmdletbinding()]
        Param
        (
            [string]$new_hostname
        )

        # Get current computer name
        $current_hostname = [Environment]::MachineName

        Update-Log -logMessage "Identified previous hostname: $current_hostname"

        Update-Log -logMessage "Replacing with new hostname: $new_hostname"

        # Configure hostname
        Rename-Computer -ComputerName $current_hostname -NewName $new_hostname -Force -ErrorAction SilentlyContinue
    } # Set-Hostname


Function Create-ScheduledTask
    {
        [cmdletbinding()]
        Param
        (
            [string]$stArg,
            [string]$taskName
        )

        $Action = New-ScheduledTaskAction -Execute 'c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe' -Argument "-ExecutionPolicy Bypass $location$scriptName -$stArg"
        $Trigger = New-ScheduledTaskTrigger -AtLogon
        $Principal = New-ScheduledTaskPrincipal SYSTEM
        $Settings = New-ScheduledTaskSettingsSet
        $Define = New-ScheduledTask -Action $Action -Principal $Principal -Trigger $Trigger -Settings $Settings

        Register-ScheduledTask $taskName -InputObject $Define
    } #Create-ScheduledTask


Function Setup-ActiveDirectory_DNS
    {
        [cmdletbinding()]
        Param
        (
            [string]$domainName,
            [string]$password
        )

        $secure_password = ConvertTo-SecureString -String $password -AsPlainText -Force

        # Install Active Directory Domain Services - Windows Feature (no restart needed)
        Install-WindowsFeature -Name AD-Domain-Services

        # Ask for AD database password
        # $password = Read-Host -Prompt "Please type a password if you ever need to Repair, Restore, or otherwise Recover your Active Directory database. Don't lose this!" -AsSecureString

        # Configure Active Directory (restart required)
        Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath “C:\Windows\NTDS” -DomainMode “WinThreshold” -DomainName “$domainName.com” -SafeModeAdministratorPassword $secure_password -DomainNetbiosName “$domainName” `
            -ForestMode “WinThreshold” -InstallDns:$true -LogPath “C:\Windows\NTDS” -NoRebootOnCompletion:$true -SysvolPath “C:\Windows\SYSVOL” -Force:$true
    
        # Installs AD management tools	
        Install-WindowsFeature -Name RSAT-AD-AdminCenter

    } # Setup-ActiveDirectory_DNS


Function Setup-DHCP
    {
        [cmdletbinding()]
        Param
        (
            [string]$ipAddress,
            [string]$dhcpScopeStart,
            [string]$dhcpScopeEnd,
            [string]$dhcpSubnetMask,
            [string]$dhcpLeaseDuration
        )

        # Installs DHCP server role
        Install-WindowsFeature -Name 'DHCP' –IncludeManagementTools

        Update-Log -logMessage "Configuring IP range in DHCP"

        # Configures IP range "scope"
        Add-DhcpServerV4Scope -Name "Lab Scope" -State Active -StartRange $dhcpScopeStart -EndRange $dhcpScopeEnd -SubnetMask $dhcpSubnetMask -LeaseDuration $dhcpLeaseDuration

        Update-Log -logMessage "Authorizing the DHCP server"

        # Authorize in Active Directory; security feature that prevents unauthorized DHCP servers from assigning IPs to your systems
        # No need to specify the parameters -DnsName or -IPAddress because we're using this host as the DHCP server
        Add-DhcpServerInDC

        Update-Log -logMessage "Removing Post-Installation DHCP message"

	    # Remove the DHCP post-installation message seen in Server Manager
        Set-ItemProperty –Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 –Name ConfigurationState –Value 2

    } # Setup-DHCP


Function Add-DomainUser
    {
        # Converts the plaintext password into a Secure String
        $secPass = ConvertTo-SecureString -String 'samplep@ssword123' -AsPlainText -Force

        # Creates the user
        New-ADUser -Name 'DomainNewAccount' -AccountPassword $secPass -Enabled:$true -PasswordNeverExpires:$true

    } # Add-DomainUser


####  Begin Script Logic ####

If ( [switch]$one )
    {
        Update-Log -logMessage "First run of the script"

        Update-Log -logMessage "Configuring this host with a new IP and DNS address"

        # Configure this host's IP and DNS addresses
        Configure-IPandDNS -new_IPv4 $ipAddress -new_DNS $dnsAddress

        Update-Log -logMessage "Configuring this host with a new Hostname"
        
        # Configure this host's Hostname
        Set-Hostname -new_hostname $hostname

        Update-Log -logMessage "Creating a scheduled task to run on the next user logon"

        Create-ScheduledTask -stArg 'two' -taskName 'Install AD and DNS'

        Update-Log -logMessage "A restart is required to apply these changes. Run this script again after logon"

        # Restart computer - required for hostname change to take effect
        Restart-Computer -Force
    }
ElseIf ( [switch]$two )
    {
	    Update-Log -logMessage "Second run of the script"

        Update-Log -logMessage "Removing the scheduled task - Install AD and DNS"

        Unregister-ScheduledTask -TaskName 'Install AD and DNS' -Confirm:$false

        Update-Log -logMessage "Configuring Active Directory and DNS"

        # Configure Active Directory and DNS
        Setup-ActiveDirectory_DNS -domainName $domainName -password $password

	    Update-Log -logMessage "Creating a scheduled task to run on the next user logon"

        Create-ScheduledTask -stArg 'three' -taskName 'Install DHCP'

        Update-Log -logMessage "A restart is required to apply these changes. Run this script again after logon"

        # Restart computer
        Restart-Computer -Force
    }
ElseIf ( [switch]$three )
    {
        Update-Log -logMessage "Third run of the script"

        Update-Log -logMessage "Removing the scheduled task - Install DHCP"

        Unregister-ScheduledTask -TaskName 'Install DHCP' -Confirm:$false

    	Update-Log -logMessage "Configuring DHCP"

        # Configure DHCP
        Setup-DHCP -ipAddress $ipAddress -dhcpScopeStart $dhcpScopeStart -dhcpScopeEnd $dhcpScopeEnd -dhcpSubnetMask $dhcpSubnetMask -dhcpLeaseDuration $dhcpLeaseDuration

        Update-Log -logMessage "Creating a domain user account - used in the Client Setup Script for joining the host to the domain"
        
        Add-DomainUser

        Update-Log -logMessage "After the next restart, this domain controller will be fully functional!"

        # Restart computer
        Restart-Computer -Force
    }
Else
    {
        # Nothing selected
    }
