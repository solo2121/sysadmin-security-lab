# 🧪 Active Directory Pentest Lab (libvirt/KVM)

> **Enterprise‑style Active Directory attack‑chain documentation** for the AD Pentest Lab using **Vagrant + libvirt/KVM**.

⚠️ **Intentionally vulnerable. Documentation and lab use only. Do NOT expose to the internet.**

---

## 🎯 Purpose of This Document

This document explains the **architecture, networking model, and attack intent** of the Active Directory Pentest Lab.

It is meant to:

- Clarify **how the lab is designed**
- Prevent **libvirt networking misconfiguration**
- Serve as **official documentation** (not deployment scripts)
- Support PJPT / CRTP‑style training and self‑study

---

## 🧱 Lab Architecture Overview

The lab simulates a **modern enterprise network** combining:

- On‑prem Active Directory
- AD Certificate Services
- Legacy and modern Windows systems
- Linux servers
- Cloud / container attack surfaces
- Web application targets

All attack paths are **intentional and controlled**.

---

## 🌐 Networking Model (CRITICAL – libvirt)

This lab is **optimized for libvirt/KVM**. Networking behavior **differs from VirtualBox**.

### Network Segments

### 1️⃣ Management Network (NAT)

- Provided by libvirt `default` network
- Internet access for updates and tooling
- **Not used** for attack traffic

### 2️⃣ Corporate Internal Network (Isolated LAN)

- Subnet: `172.28.128.0/24`
- Fully isolated Layer‑2 network
- No routing to external networks
- All attack traffic remains internal

---

## 🧠 libvirt Design Rules (Do Not Ignore)

- ✅ **Two NICs per VM**
  - NIC 1: NAT (management)
  - NIC 2: Corporate LAN

- ✅ **Static IP addresses required**
- ✅ Named libvirt network with `forward_mode: none`
- ❌ No DHCP assumptions
- ❌ No host‑only or bridged LANs

> Misconfigured networking will break AD, DNS, Kerberos, SMB relay, and certificate attacks.

---

## 🖥️ Systems & Roles

| Hostname        | IP            | Role                    |
| --------------- | ------------- | ----------------------- |
| kali-libvirt    | 172.28.128.10 | Attacker                |
| DC01            | 172.28.128.21 | Domain Controller       |
| DB01            | 172.28.128.23 | SQL / Kerberoast target |
| CA01            | 172.28.128.24 | AD CS                   |
| WIN10           | 172.28.128.30 | Domain workstation      |
| vuln-ubuntu     | 172.28.128.11 | Cloud / DevOps          |
| metasploitable2 | 172.28.128.12 | Legacy Linux            |
| metasploitable3 | 172.28.128.13 | Web server              |
| msf-win2k8      | 172.28.128.14 | Legacy Windows          |
| juice-shop      | 172.28.128.15 | OWASP web app           |

---

## 🧪 Intended Attack Paths

### Active Directory

- LLMNR / NetBIOS poisoning
- AS‑REP roasting
- Kerberoasting (SQL SPNs)
- Delegation abuse
- ACL abuse
- AdminSDHolder

### AD Certificate Services

- ESC1 – Template misconfiguration
- ESC6 – SAN abuse
- ESC8 – Web enrollment relay
- ESC9 – Weak binding

### Lateral Movement & Privilege Escalation

- SMB relay
- Credential reuse
- Service abuse
- Local privilege escalation

### Cloud & Containers

- Hardcoded cloud credentials
- Terraform state leakage
- Docker socket abuse
- Kubernetes misconfigurations

---

## 🧠 Post‑Boot Validation (Conceptual)

### Windows Systems

- DNS must point to **DC01 (172.28.128.21)**
- Internal LAN NIC handles domain traffic
- NAT NIC has **no DNS configured**

### Kali

- Internet traffic via NAT
- Attack traffic via `172.28.128.0/24`

---

## ⚠️ Security & Ethics Notice

- Never expose this lab to real networks
- Never reuse credentials
- Use only in isolated environments
- Authorized training and education only

---

## 📚 References

- SpecterOps Active Directory Attack Paths
- Microsoft AD & AD CS documentation
- Certipy, Impacket, BloodHound toolchains

---
