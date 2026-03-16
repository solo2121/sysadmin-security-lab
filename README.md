# ![Sysadmin Security Lab](assets/banner.png)

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Bash](https://img.shields.io/badge/Bash-5.x-blue.svg)
![Vagrant](https://img.shields.io/badge/Vagrant-Libvirt-green.svg)
![Security](https://img.shields.io/badge/Security-Pentesting-red.svg)
![AD Lab](https://img.shields.io/badge/ActiveDirectory-Lab-orange.svg)
![LLM Lab](https://img.shields.io/badge/LLM-AI_Security-purple.svg)

> **Professional system administration and security lab environment** for hands-on learning, enterprise pentesting, and AI/LLM security research.

---

## Table of Contents

* [Overview](#overview)
* [Features](#features)
* [Quick Start](#quick-start)
* [Labs](#labs)

  * [Active Directory Pentest Lab](#active-directory-pentest-lab-pjpt)
  * [VLAN Enterprise Lab](#vlan-enterprise-lab)
* [LLM & AI Security Training](#llm--ai-security-training)
* [Tutorials](#tutorials)
* [Installation](#installation)
* [Usage](#usage)
* [Repository Structure](#repository-structure)
* [Learning Path](#learning-path)
* [Contribution](#contribution)
* [License](#license)

---

## Overview

The **Sysadmin Security Lab** is a **modular toolkit** combining:

* Linux system administration automation
* Enterprise Active Directory attack labs
* Network and container security environments
* Web application testing platforms
* AI / LLM security experimentation

> Realistic enterprise attack simulations with **repeatable lab setups**.

---

## Features

* Modular **security and sysadmin scripts**
* PJPT-aligned Active Directory pentest lab
* Full **enterprise attack chain simulation**
* VLAN-based enterprise lab for realistic network segmentation
* Windows, Linux, cloud, and container targets
* AI / LLM security labs with OWASP LLM Top 10 coverage
* Vagrant + Libvirt/KVM environments
* Clear documentation with repeatable setups

**Offensive Security Tools Included:**

| Tool         | Purpose                            |
| ------------ | ---------------------------------- |
| NetExec      | AD attack automation               |
| BloodHound   | Attack graph mapping               |
| Impacket     | SMB, LDAP, Kerberos attacks        |
| Certipy      | Certificate abuse                  |
| Responder    | Network credential harvesting      |
| CrackMapExec | AD exploitation & lateral movement |
| sqlmap       | Database attacks                   |
| mimikatz     | Privilege escalation               |

---

## Quick Start

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab
```

Then explore labs:

```
labs/
tutorials/
security/
sysadmin/
```

Each directory has its own **README with step-by-step instructions**.

---

## Labs

### Active Directory Pentest Lab (PJPT)

**Path:** `labs/ad-pentest-lab/`
**Platform:** Vagrant + Libvirt/KVM

**Focus:**

* Enterprise AD attack chains
* AD CS exploitation (ESC1, ESC6, ESC8, ESC9)
* Kerberoasting / AS-REP Roasting
* SMB relay & lateral movement
* Privilege escalation and persistence

**Contents:**

```
README.md        # Lab documentation
Vagrantfile      # VM orchestration
configs/         # Lab configuration
scripts/         # Automation & attack helpers
requirements.txt
```

[View PJPT AD Lab Documentation](labs/ad-pentest-lab/README.md)

---

### VLAN Enterprise Lab

**Path:** `labs/ad-pentest-lab-vlan/`
**Focus:** VLAN segmentation, Linux bridges, realistic enterprise network isolation

Includes:

* Network diagrams (Mermaid)
* VLAN automation scripts
* Troubleshooting documentation

---

## LLM & AI Security Training

### LLM01 – AI Security Lab

**Purpose:** Explore AI and LLM attack surfaces in enterprise environments.

**Training Coverage:**

* Prompt injection
* API abuse & weak authentication
* Sensitive data exposure via context manipulation
* Misconfigured containerized AI services
* Cloud credential leaks via AI integrations
* AI supply-chain / dependency risks

---

## Tutorials

Located in `tutorials/`, covering:

* AD MITRE log source playbooks
* AppArmor security guides
* Git fundamentals for Linux
* Pacstall / AUR package management
* KVM/QEMU CLI and setup
* TimeShift backups
* Vagrant & Libvirt management
* Windows AD pentesting

---

## Installation

### Python Dependencies

```bash
pip install -r requirements.txt
```

### Bash Tooling

```bash
sudo apt install shellcheck
```

### Virtualization Dependencies

```bash
sudo apt install qemu-kvm libvirt-daemon-system virt-manager vagrant
```

---

## Usage

* Scripts and labs include **purpose, usage instructions, configuration notes, and safety guidance**
* Organized by **category**: `security/`, `sysadmin/`, `labs/`, `tutorials/`

---

## Repository Structure

```
sysadmin-security-lab/
├── assets/                     # Images & diagrams
├── labs/
│   ├── ad-pentest-lab/
│   ├── ad-pentest-lab-vlan/
├── tutorials/                   # Step-by-step learning guides
├── security/                    # Security tooling & scripts
├── sysadmin/                    # Automation scripts
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

---

## Suggested Learning Path

1. Linux system administration basics
2. Networking & virtualization setup
3. Active Directory enumeration
4. Lateral movement & credential attacks
5. Privilege escalation techniques
6. AI / LLM security testing

> Mirrors real-world enterprise pentesting workflow

---

## Contribution

Contributions welcome!
Please review:

```
CONTRIBUTING.md
```

before submitting PRs.

---

## License

Licensed under **MIT License**.
See:

```
LICENSE
```

---