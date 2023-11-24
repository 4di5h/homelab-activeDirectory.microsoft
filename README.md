homelab-activeDirectory.microsoft
=================================
Setup a Basic Home Lab running Active Directory using Oracle Virtual Box, included custom Powershell scripts | Inspired from [Josh Madakor](https://github.com/joshmadakor1)'s [tutorial](https://www.youtube.com/watch?v=MHsI8hJmggI&t=1377s) | System that I am setting this upon is Windows 11

## Platforms
- Windows Server 2022
- Windows 10 2022 Version 22H2

## Technologies Used
- Active Directory
- Oracle Virtualbox 7.0.12
- Windows PowerShell ISE

## Steps for Setup
#### Gathering the tools
1. Download VirtualBox and the VB Extension Pack from [here](https://www.virtualbox.org/wiki/Downloads).
2. Download the Windows 10 ISO Image file pack from [here](https://www.microsoft.com/en-us/software-download/windows10ISO).
3. Download the Windows Server ISO Image file from [here](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2019)
Note: In case the links don't work, try to get the respective softwares/files only from Official website to avoid infiltrating any malware into your system.
#### Setting up the VM
5. Once all the files are downloaded, installed the Virtual Box exe.
6. Open the VB application, set up a new VM by pressing 'New'
7. Can put anything as the name, ideally it should be DC since we are setting up the Windows server which essentially acts as the Domain Controller.
8. For the version option, choose 'Other Windows(64-bit)' *Obviously if your downloded ISO is 32-bit version then choose that*
9. The memory allocation should atleast be 2GB, but you can set it up according to your system. *Since there are 3 machines to set up, make sure there's enough memory for all 3 VM's*
Follow the same rule for the processor settings.
10. In the 'Advanced' tab make sure Shared Clipboard and Drag'n'Drop is selected to 'Bidirectional' *This means we can copy and paste across the host and VM*
11. For the Network settings, since we are setting up the DC, set up 2 adapters; __One for NAT and the other for Internal Network__
#### Setting up the Windows Server System
12. Press Ok to create the VM, then press on the newly created VM in the left column.
13. It will ask for the ISO file, select the Windows Server ISO file downloaded previously. Once selected, press start.
14. Go ahead and install the desktop experience and install the Windows server onto the VM.
15. Use my Powershell script setup-server.ps1 script to apply the AD setup on the Server VM
> >cd C:\
> >powershell.exe -ExecutionPolicy Bypass .\setup-server.exe -one
16. In order to create more users and generate user names, Josh's [scripts](https://github.com/joshmadakor1/AD_PS), namely 1_CREATE_USERS.ps1 and Generate-Names-Create-Users.ps1 is to be used along with the name list file names.txt | These files are in my repo as well for reference.
#### Setting up the client - Windows 10
17. Followed the same steps for setting up the VM as the server, except no need for NAT, only to choose Internal Network
18. Installed the Windows OS on the VM.
19. Use my Powershell script setup-client.ps1 script to connect the domain controller
> >cd C:\
> >powershell.exe -ExecutionPolicy Bypass .\setup-client.exe -one
20. To verify whether the client has been properly connected, on the Server VM, head over to the DHCP tab in Server Manager and there should be a machine available under the Address Leases, this is the client machine and it verifies this has been properly connected.
21. To add further client computers, can follow the same steps as above, obviously with a different DHCP IP available in the range.

###### That concludes my successful Active Directory setup

