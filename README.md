
---

# ![Sysadmin Security Lab](assets/banner.png)

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Bash](https://img.shields.io/badge/Bash-5.x-blue.svg)
![Vagrant](https://img.shields.io/badge/Vagrant-Libvirt-green.svg)
![Security](https://img.shields.io/badge/Security-Pentesting-red.svg)
![AD Lab](https://img.shields.io/badge/ActiveDirectory-Lab-orange.svg)
![LLM Lab](https://img.shields.io/badge/LLM-AI_Security-purple.svg)

> Enterprise-grade system administration and offensive security lab designed for hands-on learning, realistic attack simulation, and AI/LLM security research.

---

## Overview

The **Sysadmin Security Lab** is a modular and reproducible environment built to simulate real-world enterprise infrastructure and attack scenarios.

It combines:

* Linux system administration automation
* Active Directory attack and defense labs
* Segmented enterprise network environments (VLANs)
* Offensive security tooling and workflows
* AI / LLM security experimentation

This project is intended for:

* System administrators developing security skills
* Penetration testers and red teamers
* Security engineers
* Researchers exploring AI security risks in enterprise systems

---

## Key Capabilities

* Reproducible enterprise lab environments using Vagrant and Libvirt
* End-to-end Active Directory attack chain simulation
* VLAN-based network segmentation and isolation testing
* Integrated offensive security tooling
* Hands-on AI/LLM vulnerability research
* Modular structure for incremental learning and experimentation

---

## Offensive Security Toolkit

| Category                          | Tools                             |
| --------------------------------- | --------------------------------- |
| AD Enumeration & Lateral Movement | NetExec, CrackMapExec, BloodHound |
| Protocol Exploitation             | Impacket                          |
| Credential Attacks                | Responder, mimikatz               |
| Certificate Abuse                 | Certipy                           |
| Web Exploitation                  | sqlmap                            |

---

## Quick Start

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab
```

### Install dependencies

```bash
pip install -r requirements.txt
sudo apt install qemu-kvm libvirt-daemon-system virt-manager vagrant shellcheck
```

### Launch a lab (example)

```bash
cd labs/ad-pentest-lab
vagrant up
```

Each lab contains detailed documentation covering setup, execution, and validation steps.

---

## Labs

### Active Directory Pentest Lab (PJPT-aligned)

**Path:** `labs/ad-pentest-lab/`
**Platform:** Vagrant + Libvirt/KVM

Focus areas:

* Active Directory Certificate Services exploitation (ESC1, ESC6, ESC8, ESC9)
* Kerberoasting and AS-REP Roasting
* SMB relay and lateral movement
* Privilege escalation and persistence

---

### VLAN Enterprise Lab

**Path:** `labs/ad-pentest-lab-vlan/`

Focus areas:

* VLAN segmentation
* Linux bridges
* Enterprise network isolation

Includes:

* Network diagrams (Mermaid)
* Automation scripts
* Troubleshooting documentation

---

## AI / LLM Security Lab

This lab focuses on risks associated with deploying AI systems in enterprise environments.

Coverage includes:

* Prompt injection attacks
* Data exfiltration via context manipulation
* API abuse and weak authentication
* Misconfigured AI services and containers
* Supply-chain vulnerabilities
* Cloud credential leakage via integrations

Aligned with the OWASP Top 10 for LLM Applications.

---

## Tutorials

Located in `tutorials/`:

* Active Directory logging and MITRE mapping
* AppArmor configuration and hardening
* Git fundamentals for Linux environments
* KVM/QEMU setup and usage
* Backup strategies with TimeShift
* Vagrant and Libvirt management
* Windows Active Directory pentesting

---

## Repository Structure

```
sysadmin-security-lab/
├── assets/
├── labs/
│   ├── ad-pentest-lab/
│   ├── ad-pentest-lab-vlan/
├── tutorials/
├── security/
├── sysadmin/
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

---

## Suggested Learning Path

1. Linux system administration fundamentals
2. Virtualization and networking
3. Active Directory enumeration
4. Credential attacks and lateral movement
5. Privilege escalation techniques
6. AI / LLM security testing

---

## Contributing

Contributions are welcome.

Please review:

```
CONTRIBUTING.md
```

before submitting pull requests.

---

## License

This project is licensed under the MIT License.

See:

```
LICENSE
```

---
