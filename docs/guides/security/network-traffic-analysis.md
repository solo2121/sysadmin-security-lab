# Network Traffic Analysis — Lab Guide

A practical guide for capturing and analyzing network traffic in the AD Pentest Lab and DevOps Lab using Wireshark, tcpdump, and tshark. Grounded in the actual lab networks and attack scenarios configured in the Vagrantfiles.

**Flat lab network:** `172.28.128.0/24`
**VLAN lab networks:** `172.28.10-40.0/24` per VLAN
**DevOps lab:** libvirt private network (typically `192.168.121.0/24`)

---

## Table of Contents

1. [Setup and Tool Installation](#1-setup-and-tool-installation)
2. [tcpdump Fundamentals](#2-tcpdump-fundamentals)
3. [Wireshark Fundamentals](#3-wireshark-fundamentals)
4. [Capturing Lab Attack Traffic](#4-capturing-lab-attack-traffic)
5. [Analyzing LLMNR and NBT-NS Poisoning](#5-analyzing-llmnr-and-nbt-ns-poisoning)
6. [Analyzing NTLM Authentication](#6-analyzing-ntlm-authentication)
7. [Analyzing Kerberos Traffic](#7-analyzing-kerberos-traffic)
8. [Analyzing SMB Traffic](#8-analyzing-smb-traffic)
9. [Analyzing DNS Traffic](#9-analyzing-dns-traffic)
10. [Analyzing HTTP and Web Traffic](#10-analyzing-http-and-web-traffic)
11. [Detecting Attack Patterns in Captures](#11-detecting-attack-patterns-in-captures)
12. [tshark for Automated Analysis](#12-tshark-for-automated-analysis)
13. [Capture Filters Reference](#13-capture-filters-reference)
14. [Display Filters Reference](#14-display-filters-reference)

---

## 1. Setup and Tool Installation

### On Kali Linux (Lab Attacker)

```bash
# All tools are pre-installed on Kali
# Verify
tcpdump --version
wireshark --version
tshark --version

# Allow non-root Wireshark capture
sudo dpkg-reconfigure wireshark-common
# Select Yes when asked to allow non-superusers
sudo usermod -aG wireshark $USER
newgrp wireshark
```

### On Ubuntu Lab Nodes

```bash
sudo apt update
sudo apt install -y tcpdump wireshark-common tshark net-tools

# Allow non-root capture
sudo setcap cap_net_raw,cap_net_admin+eip /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/tshark
```

### Find Your Lab Network Interface

```bash
# List all interfaces
ip link show
ip addr show

# On Kali in the flat lab — look for the interface in 172.28.128.0/24
ip addr show | grep "172.28.128"

# Typically eth0 (NAT) and eth1 (lab network)
# The lab interface is usually eth1
```

### Output Directory Setup

```bash
mkdir -p ~/lab/captures
cd ~/lab/captures
```

---

## 2. tcpdump Fundamentals

### Basic Syntax

```
tcpdump [options] [filter expression]
```

| Option | Purpose |
|--------|---------|
| `-i eth1` | Capture on interface eth1 |
| `-w file.pcap` | Write to file instead of screen |
| `-r file.pcap` | Read from saved file |
| `-n` | No DNS resolution (faster, shows real IPs) |
| `-nn` | No DNS or service name resolution |
| `-v` / `-vv` / `-vvv` | Verbosity level |
| `-c 100` | Stop after 100 packets |
| `-s 0` | Capture full packets (not just headers) |
| `-A` | Print packet content as ASCII |
| `-X` | Print content as hex + ASCII |
| `-e` | Print MAC addresses (link layer) |
| `-S` | Print absolute sequence numbers |

### Capture to File and Read Later

```bash
# Capture all traffic on lab interface
sudo tcpdump -i eth1 -w ~/lab/captures/full_capture.pcap -s 0

# Read and display a capture file
tcpdump -r ~/lab/captures/full_capture.pcap -nn

# Read with verbose output
tcpdump -r ~/lab/captures/full_capture.pcap -nnvv
```

### Capture Rotation (Long Sessions)

```bash
# Rotate files every 100MB, keep 10 files
sudo tcpdump -i eth1 \
  -w ~/lab/captures/rolling_%Y%m%d_%H%M%S.pcap \
  -C 100 -W 10 -s 0
```

---

## 3. Wireshark Fundamentals

### Launch

```bash
# GUI (recommended for interactive analysis)
wireshark &

# Open a specific capture file
wireshark ~/lab/captures/full_capture.pcap &
```

### Key Columns in the Packet List

| Column | Meaning |
|--------|---------|
| No. | Packet number |
| Time | Seconds since capture start |
| Source | Source IP or MAC |
| Destination | Destination IP or MAC |
| Protocol | Highest-level protocol detected |
| Length | Packet size in bytes |
| Info | Protocol-specific summary |

### Essential Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+F` | Find packet |
| `Ctrl+G` | Go to packet number |
| `Ctrl+R` | Start/stop capture |
| `Ctrl+E` | Stop capture |
| `Ctrl+Shift+E` | Export specified packets |
| `F5` | Refresh |
| `Alt+→` | Next packet in conversation |
| `Alt+←` | Previous packet in conversation |

### Follow a Stream

Right-click any packet → **Follow** → select the stream type:
- TCP Stream — full conversation in readable text
- UDP Stream — same for UDP
- HTTP Stream — decoded HTTP request/response
- TLS Stream — shows encrypted TLS (cannot read content without key)

### Statistics Menu

Key views under **Statistics:**
- **Conversations** — top talkers by IP pair and byte count
- **Protocol Hierarchy** — breakdown of all protocols in the capture
- **IO Graphs** — traffic rate over time
- **Expert Information** — errors, warnings, and anomalies detected automatically

---

## 4. Capturing Lab Attack Traffic

### Full Lab Capture During an Attack Session

Start this before launching any attacks to capture everything:

```bash
# On Kali — capture all lab traffic
sudo tcpdump -i eth1 -w ~/lab/captures/attack_session_$(date +%Y%m%d_%H%M).pcap -s 0 &
CAPTURE_PID=$!

# ... run your attacks ...

# Stop capture
kill $CAPTURE_PID
```

### Targeted Captures by Protocol

```bash
# Capture only DNS traffic
sudo tcpdump -i eth1 -w ~/lab/captures/dns.pcap -s 0 port 53

# Capture only SMB
sudo tcpdump -i eth1 -w ~/lab/captures/smb.pcap -s 0 port 445

# Capture only Kerberos
sudo tcpdump -i eth1 -w ~/lab/captures/kerberos.pcap -s 0 port 88

# Capture only LDAP
sudo tcpdump -i eth1 -w ~/lab/captures/ldap.pcap -s 0 port 389

# Capture traffic to/from the DC only
sudo tcpdump -i eth1 -w ~/lab/captures/dc_traffic.pcap -s 0 \
  host 172.28.128.21

# Capture traffic between Kali and WIN10
sudo tcpdump -i eth1 -w ~/lab/captures/kali_win10.pcap -s 0 \
  host 172.28.128.10 and host 172.28.128.30

# Capture LLMNR and NBT-NS (ports 5355 and 137)
sudo tcpdump -i eth1 -w ~/lab/captures/llmnr_nbns.pcap -s 0 \
  port 5355 or port 137
```

### Capture on a Windows Lab Host

If you have a shell on a Windows host (via Meterpreter or evil-winrm):

```powershell
# Check available interfaces
Get-NetAdapter

# Capture with netsh (built-in, no install needed)
netsh trace start capture=yes tracefile=C:\capture.etl

# Stop capture
netsh trace stop

# Convert ETL to pcap for Wireshark (needs Microsoft Message Analyzer or etl2pcapng)
```

Or via Meterpreter:

```bash
meterpreter > run packetrecorder -i 1 -l /tmp/win10_capture.pcap
```

---

## 5. Analyzing LLMNR and NBT-NS Poisoning

LLMNR uses UDP port 5355. NBT-NS uses UDP port 137. When Responder is running, it responds to these broadcasts and forces NTLM authentication.

### Capture While Running Responder

```bash
# Terminal 1: Start capture
sudo tcpdump -i eth1 -w ~/lab/captures/llmnr_attack.pcap -s 0 \
  port 5355 or port 137 or port 445

# Terminal 2: Start Responder
sudo responder -I eth1 -wPFbv
```

### What to Look For in Wireshark

**Wireshark display filter:**
```
llmnr or nbns
```

**What you will see:**

1. A Windows host sends an LLMNR query for a hostname that does not exist in DNS:
   - Protocol: `LLMNR`
   - Info: `Standard query 0x... A NONEXISTENT-HOST`
   - Source: Windows victim IP (e.g., `172.28.128.30`)
   - Destination: `224.0.0.252` (LLMNR multicast address)

2. Responder replies claiming to be that host:
   - Source: `172.28.128.10` (Kali/Responder)
   - Destination: `172.28.128.30` (victim)
   - Info: `Standard query response 0x... A 172.28.128.10`

3. The victim connects to Kali for SMB/authentication:
   - Protocol: `SMB2` or `NTLMSSP`
   - The NTLM challenge-response follows immediately after

**tcpdump filter to verify Responder is responding:**
```bash
tcpdump -r llmnr_attack.pcap -nn 'port 5355' | grep "172.28.128.10"
```

### NTLM Hash in the Capture

The captured NTLMv2 hash is embedded in the SMB authentication packets. In Wireshark:

1. Filter: `ntlmssp`
2. Look for `NTLMSSP_AUTH` packets
3. Expand: `SMB2 → Session Setup Request → Security Blob → NTLM Secure Service Provider → NTLM Response`
4. You will see the NTLMv2 Response — this is the crackable hash

---

## 6. Analyzing NTLM Authentication

NTLM authentication uses a three-way challenge-response embedded in SMB, HTTP, or LDAP packets.

### Wireshark Filter

```
ntlmssp
```

### The Three NTLM Messages

| Message | Direction | Content |
|---------|-----------|---------|
| NTLMSSP_NEGOTIATE | Client → Server | Client capabilities and flags |
| NTLMSSP_CHALLENGE | Server → Client | 8-byte server challenge (random nonce) |
| NTLMSSP_AUTH | Client → Server | Username, domain, NT Response (the hash) |

### Extracting the Hash Manually from a Capture

```bash
# Use tshark to extract NTLM fields
tshark -r ~/lab/captures/llmnr_attack.pcap \
  -Y "ntlmssp.messagetype == 0x00000003" \
  -T fields \
  -e ntlmssp.auth.username \
  -e ntlmssp.auth.domain \
  -e ntlmssp.ntlmresponse \
  -e ntlmssp.challenge.server_challenge
```

### Reconstruct the NTLMv2 Hash for Hashcat

The hashcat format for NTLMv2 (-m 5600) is:

```
USERNAME::DOMAIN:CHALLENGE:NTProofStr:BLOB
```

Where:
- `CHALLENGE` is the server challenge from `NTLMSSP_CHALLENGE`
- `NTProofStr` is the first 32 hex characters of the NTLMv2 response
- `BLOB` is the remaining bytes of the NTLMv2 response

Responder extracts this automatically. This manual analysis is for understanding what you are seeing in the capture.

---

## 7. Analyzing Kerberos Traffic

Kerberos uses TCP/UDP port 88. All domain authentication in a Windows AD environment flows through Kerberos by default.

### Capture Kerberos Traffic

```bash
sudo tcpdump -i eth1 -w ~/lab/captures/kerberos.pcap -s 0 port 88
```

### Wireshark Filter

```
kerberos
```

### Key Kerberos Message Types

| Message | Abbreviation | Purpose |
|---------|-------------|---------|
| Authentication Service Request | AS-REQ | Client requests TGT |
| Authentication Service Response | AS-REP | DC issues TGT |
| Ticket Granting Service Request | TGS-REQ | Client requests service ticket |
| Ticket Granting Service Response | TGS-REP | DC issues service ticket |
| Application Request | AP-REQ | Client presents ticket to service |

### Identifying AS-REP Roasting in a Capture

When `impacket-GetNPUsers` runs an AS-REP roasting attack:

**Wireshark filter:**
```
kerberos.msg_type == 10 or kerberos.msg_type == 11
```

- `msg_type == 10` = AS-REQ (request for TGT)
- `msg_type == 11` = AS-REP (TGT issued)

**What makes an AS-REP roasting packet distinctive:**
- AS-REQ does NOT include a `PA-ENC-TIMESTAMP` pre-authentication field
- The AS-REP response includes the encrypted TGT encrypted with the user's password hash

**tshark command to find AS-REP roasting:**
```bash
tshark -r ~/lab/captures/kerberos.pcap \
  -Y "kerberos.msg_type == 10 and not kerberos.PA_ENC_TIMESTAMP" \
  -T fields \
  -e ip.src \
  -e kerberos.cname \
  -e kerberos.realm
```

### Identifying Kerberoasting in a Capture

Kerberoasting generates TGS-REQ/TGS-REP pairs for service accounts.

**Wireshark filter:**
```
kerberos.msg_type == 12 or kerberos.msg_type == 13
```

- `msg_type == 12` = TGS-REQ
- `msg_type == 13` = TGS-REP

**Detection indicator:** RC4 encryption type in the TGS-REP
- Expand: `TGS-REP → enc-part → etype`
- Value `17` = RC4-HMAC (the crackable type)
- Value `18` = AES256 (not crackable offline)

**tshark command to find Kerberoasting:**
```bash
tshark -r ~/lab/captures/kerberos.pcap \
  -Y "kerberos.msg_type == 13 and kerberos.etype == 17" \
  -T fields \
  -e ip.src \
  -e ip.dst \
  -e kerberos.sname \
  -e kerberos.etype
```

### Golden Ticket in a Capture

A Golden Ticket is a forged TGT. Detection signs in the capture:
- TGT with an unusually long validity period (10 years by default)
- TGT encrypted with RC4 when AES is enforced (downgrade attack)
- Authentication from unexpected hosts using the forged ticket

---

## 8. Analyzing SMB Traffic

SMB (port 445) is the most common protocol for lateral movement and credential relay in AD environments.

### Wireshark Filter

```
smb or smb2
```

### Capture SMB Traffic

```bash
sudo tcpdump -i eth1 -w ~/lab/captures/smb.pcap -s 0 port 445
```

### SMB Session Setup — What to Examine

In Wireshark, follow any SMB2 Session Setup Request:

1. Filter: `smb2.cmd == 1` (Session Setup)
2. Expand: `SMB2 → Session Setup Request → Security Blob`
3. You will see the NTLM negotiation embedded here

### SMB Signing Status

SMB signing is critical for relay attacks. Look for signing in the Negotiate Protocol Response:

```
smb2.cmd == 0   (Negotiate Protocol)
```

Expand: `SMB2 → Negotiate Response → Security Mode`
- Bit 0 set = Signing Enabled
- Bit 1 set = Signing Required

**tshark command to check signing across all hosts:**
```bash
tshark -r ~/lab/captures/smb.pcap \
  -Y "smb2.cmd == 0" \
  -T fields \
  -e ip.src \
  -e ip.dst \
  -e smb2.sec_mode
```

### PsExec / Lateral Movement in SMB

PsExec creates a service on the remote host. Look for:
- `IPC$` share access followed by `ADMIN$` or `C$` access
- A new service creation via named pipes (`\PIPE\svcctl`)

**Wireshark filter for PsExec indicators:**
```
smb2 and (smb2.filename contains "PSEXEC" or smb2.filename contains "svcctl")
```

### Pass-the-Hash in SMB

PtH shows as NTLM authentication in the Session Setup where the NTLM Auth contains a hash rather than a plaintext-derived credential. The packet structure is identical — the difference is on the credential origin side, not the wire format.

---

## 9. Analyzing DNS Traffic

DNS (port 53) in a lab environment reveals a lot about what is happening — domain lookups, failed resolutions that trigger LLMNR, and DC queries.

### Capture DNS

```bash
sudo tcpdump -i eth1 -w ~/lab/captures/dns.pcap -s 0 port 53
```

### Wireshark Filters

```
dns                           # All DNS
dns.qry.type == 1             # A record queries
dns.qry.type == 28            # AAAA (IPv6) queries
dns.flags.rcode != 0          # Failed DNS lookups (potential LLMNR trigger)
dns.qry.name contains "lab"   # Queries for lab.local domain
```

### What Normal Lab DNS Looks Like

```
172.28.128.30 → 172.28.128.21  DNS Standard query A dc01.lab.local
172.28.128.21 → 172.28.128.30  DNS Standard query response A 172.28.128.21
```

### What Failed DNS Looks Like (LLMNR Trigger)

```
172.28.128.30 → 172.28.128.21  DNS Standard query A DOESNOTEXIST
172.28.128.21 → 172.28.128.30  DNS Standard query response Name Error
172.28.128.30 → 224.0.0.252    LLMNR Standard query A DOESNOTEXIST
172.28.128.10 → 172.28.128.30  LLMNR Standard query response A 172.28.128.10
```

### DNS Zone Transfer in a Capture

```
dig axfr @172.28.128.21 lab.local
```

In the capture:
- Client sends a DNS query with `QTYPE=AXFR` (type 252)
- DC responds with all zone records in sequence

**Wireshark filter:**
```
dns.qry.type == 252
```

---

## 10. Analyzing HTTP and Web Traffic

### Capture HTTP

```bash
# All web traffic
sudo tcpdump -i eth1 -w ~/lab/captures/http.pcap -s 0 port 80 or port 8080 or port 443

# Juice Shop only (172.28.128.15 or 172.28.40.15 in VLAN)
sudo tcpdump -i eth1 -w ~/lab/captures/juiceshop.pcap -s 0 \
  host 172.28.128.15 and port 80
```

### Wireshark HTTP Filters

```
http                          # All HTTP
http.request                  # Only requests
http.response                 # Only responses
http.request.method == "POST" # POST requests (login forms, data submission)
http contains "password"      # HTTP traffic containing the word password
http.response.code == 200     # Successful responses
http.response.code == 500     # Server errors
```

### Extracting Credentials from HTTP

Many web apps send credentials in plain HTTP POST requests. In Wireshark:

1. Filter: `http.request.method == "POST"`
2. Right-click → Follow → HTTP Stream
3. Look for form fields containing `password`, `passwd`, `secret`, `token`

```bash
# tshark — extract all HTTP POST body content
tshark -r ~/lab/captures/http.pcap \
  -Y "http.request.method == POST" \
  -T fields \
  -e http.host \
  -e http.request.uri \
  -e http.file_data
```

### SQL Injection in HTTP Traffic

When running SQLmap against Juice Shop:

1. Filter: `http.request.uri contains "'"` or `http.request.uri contains "OR"`
2. You will see repeated requests with SQL payloads in the URI or POST body
3. Error responses (500) indicate the injection is working

---

## 11. Detecting Attack Patterns in Captures

This section maps common attack patterns to what they produce in a packet capture — useful for both offensive awareness and blue team detection.

### LLMNR/NBT-NS Poisoning

**Indicators in capture:**
- LLMNR queries for non-existent hostnames
- Unusually fast responses to LLMNR queries (Responder responds within milliseconds)
- SMB connection initiated immediately after an LLMNR response
- NTLMSSP_AUTH following the SMB connection

**Filter:**
```
(udp.port == 5355 or udp.port == 137) and (ip.src == 172.28.128.10)
```

### Kerberoasting

**Indicators in capture:**
- Multiple TGS-REQ packets from one source to the DC in rapid succession
- All TGS-REQ packets targeting different service accounts (SPNs)
- TGS-REP responses with RC4 (etype 17) encryption

**Filter:**
```
kerberos.msg_type == 12 and ip.src == 172.28.128.10
```

### AS-REP Roasting

**Indicators in capture:**
- AS-REQ packets without PA-ENC-TIMESTAMP
- Multiple requests for different usernames in rapid succession
- All requests from the same source

**Filter:**
```
kerberos.msg_type == 10 and not kerberos.PA_ENC_TIMESTAMP
```

### NTLM Relay

**Indicators in capture:**
- An NTLMSSP_CHALLENGE from an unexpected host (not the real DC)
- The same NTLM credentials being authenticated to two different hosts within milliseconds
- A connection from Kali to a target immediately after a Windows host connected to Kali

**Filter:**
```
ntlmssp and ip.src == 172.28.128.10
```

### DCSync

**Indicators in capture:**
- MSRPC traffic (port 135 or dynamic ports) from a non-DC host to the DC
- The traffic contains `DrsReplicaSync` or `NtdsaDsa` RPC calls
- Large amount of LDAP traffic immediately after the RPC bind

**Filter:**
```
(dcerpc or msrpc) and ip.src != 172.28.128.21 and ip.dst == 172.28.128.21
```

### EternalBlue (MS17-010)

**Indicators in capture:**
- SMB1 `Trans2` request with specific malformed buffer
- Unusually large SMB packet with many repeated bytes (NOP sled)
- A new SMB session establishing from the target back to Kali immediately after

**Filter:**
```
smb and ip.dst == 172.28.128.30 and frame.len > 4000
```

### Port Scanning (Nmap)

**Indicators in capture:**
- SYN packets to many consecutive ports in rapid sequence
- Many RST responses from closed ports
- One source IP contacting dozens of destination ports on one target

**Filter:**
```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.src == 172.28.128.10
```

---

## 12. tshark for Automated Analysis

tshark is the command-line version of Wireshark. Useful for scripting, remote captures, and automated analysis.

### Basic tshark Usage

```bash
# Live capture to screen
sudo tshark -i eth1

# Live capture with filter
sudo tshark -i eth1 -f "port 88"

# Read from file with display filter
tshark -r capture.pcap -Y "kerberos"

# Statistics
tshark -r capture.pcap -q -z io,stat,1      # Traffic per second
tshark -r capture.pcap -q -z conv,tcp        # TCP conversations
tshark -r capture.pcap -q -z phs             # Protocol hierarchy
```

### Extract Specific Fields

```bash
# Extract all DNS queries and responses
tshark -r capture.pcap \
  -Y "dns" \
  -T fields \
  -e frame.time \
  -e ip.src \
  -e ip.dst \
  -e dns.qry.name \
  -e dns.a \
  -E header=y \
  -E separator=,

# Extract all Kerberos SPN requests
tshark -r capture.pcap \
  -Y "kerberos.msg_type == 12" \
  -T fields \
  -e frame.time \
  -e ip.src \
  -e kerberos.sname \
  -e kerberos.etype \
  -E header=y

# Extract all HTTP credentials from POST requests
tshark -r capture.pcap \
  -Y "http.request.method == POST" \
  -T fields \
  -e http.host \
  -e http.request.uri \
  -e http.file_data \
  -E header=y
```

### Top Talkers Script

```bash
# Find the most active IP pairs
tshark -r capture.pcap \
  -q \
  -z conv,ip \
  | sort -k7 -rn \
  | head -20
```

### Extract Files from HTTP Captures

```bash
# Extract files transferred over HTTP
tshark -r capture.pcap --export-objects http,/tmp/extracted_files/
ls /tmp/extracted_files/
```

### Automated Lab Attack Detection Script

```bash
#!/usr/bin/env bash
# Save as ~/lab/analyze_capture.sh

PCAP="$1"
if [ -z "$PCAP" ]; then
  echo "Usage: $0 <capture.pcap>"
  exit 1
fi

echo "=== CAPTURE ANALYSIS: $PCAP ==="
echo ""

echo "--- Protocol Hierarchy ---"
tshark -r "$PCAP" -q -z phs 2>/dev/null
echo ""

echo "--- Top 10 Conversations ---"
tshark -r "$PCAP" -q -z conv,ip 2>/dev/null | sort -k7 -rn | head -10
echo ""

echo "--- DNS Failures (LLMNR triggers) ---"
tshark -r "$PCAP" -Y "dns.flags.rcode != 0" -T fields \
  -e frame.time -e ip.src -e dns.qry.name 2>/dev/null | head -20
echo ""

echo "--- LLMNR Queries ---"
tshark -r "$PCAP" -Y "llmnr" -T fields \
  -e frame.time -e ip.src -e ip.dst -e dns.qry.name 2>/dev/null | head -20
echo ""

echo "--- NTLM Authentication Events ---"
tshark -r "$PCAP" -Y "ntlmssp.messagetype == 3" -T fields \
  -e frame.time -e ip.src -e ip.dst -e ntlmssp.auth.username \
  -e ntlmssp.auth.domain 2>/dev/null | head -20
echo ""

echo "--- Kerberos TGS Requests (Kerberoasting candidates) ---"
tshark -r "$PCAP" -Y "kerberos.msg_type == 12 and kerberos.etype == 17" \
  -T fields -e frame.time -e ip.src -e kerberos.sname \
  -e kerberos.etype 2>/dev/null | head -20
echo ""

echo "--- AS-REP Roasting candidates ---"
tshark -r "$PCAP" -Y "kerberos.msg_type == 10 and not kerberos.PA_ENC_TIMESTAMP" \
  -T fields -e frame.time -e ip.src -e kerberos.cname 2>/dev/null | head -20
echo ""

echo "--- Port Scan Indicators (SYN flood from single source) ---"
tshark -r "$PCAP" -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" \
  -T fields -e ip.src 2>/dev/null | sort | uniq -c | sort -rn | head -5
echo ""

echo "=== ANALYSIS COMPLETE ==="
```

```bash
chmod +x ~/lab/analyze_capture.sh
~/lab/analyze_capture.sh ~/lab/captures/attack_session.pcap
```

---

## 13. Capture Filters Reference

Capture filters use BPF (Berkeley Packet Filter) syntax. They filter at capture time and cannot be changed after the fact.

```bash
# By host
sudo tcpdump -i eth1 host 172.28.128.21
sudo tcpdump -i eth1 src host 172.28.128.10
sudo tcpdump -i eth1 dst host 172.28.128.21

# By network
sudo tcpdump -i eth1 net 172.28.128.0/24

# By port
sudo tcpdump -i eth1 port 445
sudo tcpdump -i eth1 port 88 or port 389

# By protocol
sudo tcpdump -i eth1 udp
sudo tcpdump -i eth1 tcp

# Combined
sudo tcpdump -i eth1 host 172.28.128.21 and port 88
sudo tcpdump -i eth1 'host 172.28.128.10 and (port 445 or port 88)'
sudo tcpdump -i eth1 'not port 22'

# Key lab capture filters
# LLMNR and NBT-NS
sudo tcpdump -i eth1 'port 5355 or port 137'

# All AD protocols
sudo tcpdump -i eth1 'port 88 or port 389 or port 445 or port 636 or port 3268'

# All traffic to/from DC
sudo tcpdump -i eth1 host 172.28.128.21

# Exclude SSH (reduce noise from your own session)
sudo tcpdump -i eth1 'not port 22' -w capture.pcap
```

---

## 14. Display Filters Reference

Display filters use Wireshark's own syntax. They filter after capture and can be changed live.

### Protocol Filters

```
# Active Directory protocols
kerberos
ldap
ntlmssp
smb or smb2
dcerpc
dns

# Network layer
tcp
udp
icmp
arp

# Application
http
http2
tls
ftp
ssh
```

### Attack-Specific Filters

```
# LLMNR poisoning
llmnr
llmnr and ip.src == 172.28.128.10

# NTLM relay
ntlmssp.messagetype == 3
ntlmssp and ip.dst != 172.28.128.21

# AS-REP roasting
kerberos.msg_type == 11

# Kerberoasting (RC4 service tickets)
kerberos.msg_type == 13 and kerberos.etype == 17

# DCSync (replication RPC)
dcerpc.cn_call_id and ip.dst == 172.28.128.21

# SMB lateral movement
smb2.cmd == 1 and ip.src == 172.28.128.10

# Port scan
tcp.flags.syn == 1 and tcp.flags.ack == 0

# Large SMB packets (possible EternalBlue)
smb and frame.len > 4000

# HTTP credentials
http.request.method == "POST" and http contains "password"

# DNS failures
dns.flags.rcode != 0

# TLS certificate inspection
tls.handshake.type == 11
```

### Time and Size Filters

```
# Packets in a specific time range
frame.time >= "2026-06-23 10:00:00" and frame.time <= "2026-06-23 10:05:00"

# Large packets (possible data exfil or exploits)
frame.len > 10000

# Small packets (possible heartbeat or C2 check-in)
frame.len < 100 and tcp
```

---

## Lab Quick Reference — What to Capture for Each Attack

| Attack | Protocols | Ports | Key Filter |
|--------|-----------|-------|-----------|
| LLMNR poisoning | LLMNR, SMB, NTLMSSP | 5355, 445 | `llmnr or ntlmssp` |
| NBT-NS poisoning | NetBIOS, SMB | 137, 445 | `nbns or ntlmssp` |
| AS-REP roasting | Kerberos | 88 | `kerberos.msg_type == 11` |
| Kerberoasting | Kerberos | 88 | `kerberos.msg_type == 13` |
| NTLM relay | SMB, NTLMSSP | 445 | `ntlmssp.messagetype == 3` |
| DCSync | MSRPC, LDAP | 135, 389 | `dcerpc and ip.dst == DC_IP` |
| PsExec | SMB | 445 | `smb2 and smb2.filename contains "svcctl"` |
| EternalBlue | SMB | 445 | `smb and frame.len > 4000` |
| Nmap SYN scan | TCP | any | `tcp.flags.syn==1 and tcp.flags.ack==0` |
| SQL injection | HTTP | 80, 8080 | `http.request.method == POST` |
| DNS zone transfer | DNS | 53 | `dns.qry.type == 252` |

---

## Disclaimer

All capture and analysis work described in this guide must be performed only on networks and systems you own or have explicit written authorization to monitor. Capturing network traffic on unauthorized networks is illegal.
