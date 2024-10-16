# Active-Directory-Splunk-Home-Lab 

Introduction
This guide will walk you through the process of building a home lab using Active Directory (AD) and Splunk Security Information and Event Management (SIEM). By the end of this tutorial, you will have a functional lab environment where you can practice threat detection, incident response, and security monitoring.

Overview
In this home lab today we will learn how to setup Active directory & how to create users & add machines to the Domain. We will also setup sysmon & splunk for log collection & analysis. Finally we will use Kali linux & ART (Atomic Red Team) to create telemetry which we can analyse in splunk.

                                                                             **1. Install & setup Windows 10 as a Victim**
First we will install VMware using this guide https://www.virtualizationhowto.com/2024/05/vmware-workstation-pro-free-for-personal-use-download/
Now we will download windows 10 tool from here https://www.microsoft.com/en-ca/software-download/windows10. Install & accept the agreement -> create installation media -> language edition : default -> save as ISO file where you like.
Open VMware select File (left corner) -> New virtual machine -> Typical -> Disc image : select path where you downloaded above file for windows 10 -> location : default -> storage : default -> Customize hardware : RAM 4GB -> Finish.
Select windows 10 -> edit virtual machine settings -> Options -> Advanced -> Firmware type : change to BIOS close ->Power On windows 10 -> Language, Time : Default -> Install now -> I dont have product key -> Windows 10 pro -> accept license terms -> Custom install -> Next -> Finish
Setup & give credentials which you can remember.


                                                                           **2. Install & setup Kali linux for Attacking**
Download kali linux virtual machine for VMware using https://www.kali.org/get-kali/#kali-virtual-machines. Unzip the 7zip file same path.
Open VMware select File (left corner) -> Open -> Path for kali linux .vmx file from above extracted file -> Customize hardware : RAM 4GB -> Finish.
Default credentials (Username : kali password : kali)

                                                                        **3. Install & setup Windows server for Active Directory **

Download windows server 2022 ISO 64-bit using this link https://www.microsoft.com/en-in/evalcenter/download-windows-server-2022
Open VMware select File (left corner) -> New virtual machine -> Typical -> Disc image : select path where you downloaded above file for windows server -> location : default -> storage : default -> Customize hardware : RAM 4GB -> Finish.
Select windows server -> edit virtual machine settings -> Options -> Advanced -> Firmware type : change to BIOS close ->Power On windows server -> Language, Time : Default -> Install now -> Windows server 2022 standard desktop -> accept license terms -> Custom install -> Next -> Finish
Setup & give credentials which you can remember.

                                                                         **4. Install & setup Ubuntu server for Splunk SIEM**
Download the Ubuntu server 22.04 using this link https://releases.ubuntu.com/jammy/
Open VMware select File (left corner) -> New virtual machine -> Typical -> Disc image : select path where you downloaded above file for Ubuntu server -> location : default -> storage : default -> Customize hardware : RAM 4GB -> Finish.
Power on Ubuntu server -> Install ubuntu server -> English -> Continue without updating -> Default -> Ubuntu server -> Default -> Default -> Default -> Continue -> Default -> Default -> Continue -> Credentials -> Continue -> Default -> Default -> Reboot.
update your repositories by sudo apt-get update && sudo apt-get upgrade -y

                                                                                  **5. Install & setup Splunk**
First lets check if we have connectivity by ping -c 2 google.com on your kali linux device
Now we will install splunk in ubuntu for that go to this site & signup if not, then log-in & go to Products -> Free trials -> Splunk enterprise : get free trial -> Linux -> .deb -> copy wget link -> paste in command prompt of ubuntu & hit enter
Now we will need to install guest addons which we will install by using sudo apt-get install virtualbox-guest-addittions-iso -y
Now we will go to folder where we downloaded splunk deb file. Now we will install splunk using sudo dpkg -i splunk.deb
Now we will check if splunk folder has splunk service user as owner by ls -la /opt/splunk, we can see that splunk is owner so its good.
Now we will change to user splunk by sudo -u splunk bash now change to bin directory cd /opt/splunk/bin as splunk user then use ./splunk start to start the installer then press Y
Now give a Administrator name for splunk server & password & exit the splunk user by using exit on command line.
Lastly we will make splunk to start everytime machine boots by cd /opt/splunk/bin & sudo ./splunk enable boot-start -user splunk
Now we will install splunk universal forwarder to forward logs to the splunk server from windows machine.
Go to windows pc -> browser -> splunk.com -> log in -> products -> free trials -> universal forwarder : get free -> Windows -> 64-bit .msl : download now -> open the installer in downloads folder -> accept license and select on premise -> username : admin & select random password -> default -> Receiving indexer : splunk server ip address & port 9997 -> install.


                                                                                    **6. Install & setup Sysmon**
Download sysmon https://download.sysinternals.com/files/Sysmon.zip from sysinternal page.
We will download olaf config for sysmon, save the doc as config.xml file
Now extract the sysmon zip, open admin powershell & go to the same folder where sysmon is extracted. Also copy the config to sysmon folder.
Now start sysmon with olaf config ./sysmon64.exe -i sysmonconfig.xml & hit enter -> accept agreement -> sysmon will be installed & started.
Open notepad as Admin & fill in as below for sysmon & save it under C:\Program files\SplunkUniversalForwarder\etc\system\local as inputs.conf. This will allow splunk forwarder to take sysmon logs as well as system, security & application winevent logs.
Now we will restart splunk forwarder service & change service account of splunk to local system by going to services as admin. search splunk forwarder -> double click to open -> log on -> change log on as : local system account -> apply & ok -> restart the splunk forwarder.
Now login to splunk web portal using splunk server IP & port number as 192.168.0.142:8000 -> settings -> indexes -> new index -> index name : endpoint (we configured inputs.conf in which we have index endpoint) -> save
Now go to settings -> forwarding & receiving -> configure receiving -> new receiving port -> 9997 -> save this will be our log receiving port
If we have done everything correctly we will start seeing logs from windows. Go to Apps (upper left corner) -> search & reporting -> In search : index= “endpoint” -> you will see events for windows pc & server

                                                                             **7. Configure Active Directory & Joining Windows Pc to Domain**
Open server manager -> manage (right corner) -> add roles & features -> Next -> role-based -> Next -> Active Directory Domain Services -> Add features -> Next -> Next -> Next -> Install -> Configuration required -> Close
Go to server manager -> flag -> Promote -> Add new forest -> domain.local -> give secure password -> all default -> Install
Go to server manager -> Tools (right corner) -> AD Users & Computers -> right click AD domain active.local -> New -> Organizational Unit -> Give name -> Inside Ogr. unit -> right click -> New -> user -> give name, username & password -> uncheck user must change password -> repeat above steps & create another Org. unit & user for it
Now that we have configured AD & created users, lets add windows pc to the domain using above created account. Go to windows pc -> log-in -> network adapter (bottom right corner)->right click -> open network setting -> change adapter options -> adapter (right click) -> properties -> double click IPv4 -> use following DNS -> Active Directory IP address -> Ok
Search bar : PC -> properties -> Advanced system settings -> computer name -> Change -> Domain -> domain_u_created (active.local)-> ok -> enter username & password for admin of AD to authenticate & join to domain -> ok -> restart pc -> at log-in : other user -> sign into domain name check -> enter username & password for user u created -> log-in
Congrats we have successfully configured Active Directory, created new Org. units, created users for domains & joined the pc to the domain.

                                                                              **8. Use kali linux & ART to generate telemetry & observe in Splunk**
Now we will attack using Kali linux. Log-in to kali -> test connectivity ping google.com & ping splunk server IP -> update the repositories by sudo apt-get update && sudo apt-get upgrade
Now we will install crowbar (brute force tool) using sudo apt-get install -y crowbar. Now we will create a wordlist for this attack by going to wordlists folder by doing cd /usr/share/wordlists -> now unzip the worlist file by sudo gunzip rockyou.txt.gz -> now we will get this file to desktop for accessibility by cp rockyou.txt /home/kali/desktop -> change to the desktop folder by cd ~/Desktop
Now to make our own wordlist we will use head -n 20 rockyou.txt > password.txt then in this file we will add our test user’s password as we will have to see in telemetry how does successful log-in looks using nano password.txt now we will put the password of user & save it using CTRL + X & press Y & hit enter.
For this attack to work we need to turn RDP (remote desktop protocol) for that go to windows pc -> log-in -> search bar : PC -> properties -> advanced system settings -> enter admin credentials -> remote -> allow remote connections -> select users -> add the test user you created for the attack -> check name -> Ok -> ok -> apply -> ok
Now to attack open terminal -> type crowbar -b rdp -u testusername -C password file path -s target machine IP/32 -> attack is success
Now we will look at the telemetry for the attack go to splunk web portal -> log-in -> search & reporting -> search bar : index=”endpoint” testusername & time for last 15 mins -> shows brute force attack
We can see that 20 attempts were failed as code 4625 means failed attempts, 1 brute force attempt was successfull which is 4624.
As we see the timings, the logon attempts are basically happening one-after-other which is definitely brute force as no normal traffic can be this quick
So if we go to event id : 4624 which is successful logon we ca find more info about the attacker like the workstation name of Attacker was KALI & IP address of the Attacker was 192.168.0.136
Now we will generate telemetry using ART (Atomic Red Team). Go to windows pc -> open admin powershell -> run Set-ExecutionPolicy Bypass CurrentUser (to execute anything for this session)
Now we will exclude C drive because defender will try to delete ART file go to search bar : windows security -> Virus & threat protection -> manage settings -> exclusions -> add -> folder -> this pc -> select C drive
Now install ART using command IEX (IWR ‘https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getatomics -Force
We will see Mitre Attack tactic persistence : create local account telemetry by using Invoke-AtomicTest T1136.001 (tactic id)
We can see that new user was created by name NewLocalUser we can search for that in splunk like index=”endpoint” NewLocalUser
Now we will see Mitre attack tactic for powershell execution with id T1059.001 by using Invoke-AtomicTest T1059.001 (tactic id)
We see lot of powershell in this we can use that to search in SIEM by using index=”endpoint” powershell bypass & we see results indicating that powershell commands have been executed on system which should be ringing red bells.


So if we do this correctly & we cant find traces of ART events in SIEM that means we are blind to this attacks. Then we can build mechanisms to detect this kinds of attacks.
You can use ART to generate telemetry for various more tactics & techniques & query them in SIEM for better understanding

This brings us to the end of this Home Lab. Hope u enjoyed it & learned from it.
