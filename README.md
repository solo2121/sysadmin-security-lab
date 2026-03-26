# ![Sysadmin Security Lab](assets/banner.png)

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Bash](https://img.shields.io/badge/Bash-5.x-blue.svg)
![Vagrant](https://img.shields.io/badge/Vagrant-Libvirt-green.svg)
![Security](https://img.shields.io/badge/Security-Pentesting-red.svg)
![AD Lab](https://img.shields.io/badge/ActiveDirectory-Lab-orange.svg)
![LLM Lab](https://img.shields.io/badge/LLM-AI_Security-purple.svg)

> Professional system administration and security lab environment for hands-on learning, enterprise pentesting, and AI/LLM security research.

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

The **Sysadmin Security Lab** is a modular toolkit that combines:

* Linux system administration automation
* Enterprise Active Directory attack labs
* Network and container security environments
* Web application testing platforms
* AI / LLM security experimentation

This project focuses on **realistic enterprise attack simulations** with repeatable and structured lab environments.

---

## Features

* Modular security and sysadmin scripts
* PJPT-aligned Active Directory pentest lab
* Full enterprise attack chain simulation
* VLAN-based enterprise lab for realistic network segmentation
* Windows, Linux, cloud, and container targets
* AI / LLM security labs (OWASP LLM Top 10 aligned)
* Vagrant + Libvirt/KVM virtualization environments
* Clear documentation with reproducible setups

### Offensive Security Tools Included

| Tool         | Purpose                                      |
| ------------ | -------------------------------------------- |
| NetExec      | AD attack automation                         |
| BloodHound   | Attack path visualization                    |
| Impacket     | SMB, LDAP, Kerberos attacks                  |
| Certipy      | Active Directory Certificate abuse           |
| Responder    | Network credential harvesting                |
| CrackMapExec | AD exploitation & lateral movement           |
| sqlmap       | Database exploitation                        |
| mimikatz     | Credential extraction & privilege escalation |

---

## Quick Start

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab
```

Explore the main directories:

```
labs/
tutorials/
security/
sysadmin/
```

Each directory contains its own documentation with step-by-step instructions.

---

## Labs

### Active Directory Pentest Lab (PJPT)

**Path:** `labs/ad-pentest-lab/`
**Platform:** Vagrant + Libvirt/KVM

#### Focus Areas

* Enterprise Active Directory attack chains
* AD CS exploitation (ESC1, ESC6, ESC8, ESC9)
* Kerberoasting and AS-REP Roasting
* SMB relay and lateral movement
* Privilege escalation and persistence

#### Structure

```
README.md        # Lab documentation
Vagrantfile      # VM orchestration
configs/         # Lab configuration
scripts/         # Automation and attack helpers
requirements.txt
```

[View PJPT AD Lab Documentation](labs/ad-pentest-lab/README.md)

---

### VLAN Enterprise Lab

**Path:** `labs/ad-pentest-lab-vlan/`

#### Focus

* VLAN segmentation
* Linux bridges
* Enterprise network isolation

#### Includes

* Network diagrams (Mermaid)
* VLAN automation scripts
* Troubleshooting documentation

---

## LLM & AI Security Training

### LLM01 – AI Security Lab

This lab focuses on exploring **AI and LLM attack surfaces** in enterprise environments.

#### Training Coverage

* Prompt injection attacks
* API abuse and weak authentication
* Sensitive data exposure via context manipulation
* Misconfigured AI services and containers
* Cloud credential leakage via AI integrations
* AI supply-chain and dependency risks

---

## Tutorials

Located in `tutorials/`, covering:

* Active Directory MITRE log source playbooks
* AppArmor security configuration
* Git fundamentals for Linux users
* Pacstall and AUR package management
* KVM/QEMU CLI usage and setup
* TimeShift backup strategies
* Vagrant and Libvirt management
* Windows Active Directory pentesting

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

* Each script and lab includes:

  * Purpose
  * Usage instructions
  * Configuration notes
  * Safety considerations

* Repository is organized by category:

  * `security/`
  * `sysadmin/`
  * `labs/`
  * `tutorials/`

---

## Repository Structure

```
sysadmin-security-lab/
├── assets/                     # Images and diagrams
├── labs/
│   ├── ad-pentest-lab/
│   ├── ad-pentest-lab-vlan/
├── tutorials/                 # Step-by-step learning guides
├── security/                  # Security tools and scripts
├── sysadmin/                  # Automation scripts
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

---

## Suggested Learning Path

1. Linux system administration fundamentals
2. Networking and virtualization setup
3. Active Directory enumeration
4. Credential attacks and lateral movement
5. Privilege escalation techniques
6. AI / LLM security testing

This progression mirrors real-world enterprise pentesting workflows.

---

## Contribution

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
