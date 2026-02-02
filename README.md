# Security & System Administration Toolkit

A comprehensive collection of **security**, **system administration**, and **enterprise penetration testing labs** for Linux-based environments.

This repository includes **PJPT-aligned Active Directory labs**, **Linux and cloud targets**, **AI/LLM security practice**, and automation scripts designed for **hands-on offensive security training**.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Labs](#labs)
- [LLM & AI Security Training](#llm--ai-security-training)
- [Tutorials](#tutorials)
- [Installation](#installation)
- [Usage](#usage)
- [Repository Structure](#repository-structure)
- [Contribution](#contribution)
- [Community Guidelines](#community-guidelines)
- [License](#license)

---

## Overview

This repository provides a curated set of tools, scripts, and intentionally vulnerable lab environments for:

- **Linux system administration automation**
- **Enterprise penetration testing**
- **Active Directory attack chains**
- **Cloud and container security**
- **Web application security**
- **LLM and AI security testing**

> ⚠️ All labs and scripts are intended **only for systems you own or are explicitly authorized to test**.  
> Unauthorized use is strictly prohibited.

---

## Features

- Modular **security and sysadmin scripts**
- **PJPT-focused Active Directory pentest lab**
- Full **enterprise attack chain simulation**
- Windows, Linux, cloud, and container targets
- **LLM01 AI/Language Model security lab**
- OWASP Top 10 and modern API vulnerabilities
- Vagrant + libvirt/KVM based environments
- Clear documentation and repeatable setups

---

## Quick Start

Clone the repository:

```bash
git clone https://github.com/solo2121/sysadmin-security-scripts.git
cd sysadmin-security-scripts
```

````

Install development dependencies:

```bash
./scripts/setup-dev-env.sh
```

Follow instructions in each lab or script directory.

---

## Labs

### Active Directory Pentest Lab (PJPT)

- **Location:** `labs/ad-pentest-lab/`
- **Setup:** Vagrant + libvirt/KVM
- **Focus:**
  - Enterprise Active Directory attack chains
  - AD CS abuse (ESC1, ESC6, ESC8, ESC9)
  - Kerberoasting, AS-REP Roasting
  - SMB relay and lateral movement
  - Privilege escalation and persistence

- **Expanded Scope:**
  - Linux, cloud, container, and AI/LLM targets
  - OWASP Top 10 web vulnerabilities
  - Full internal network simulation

**Contents:**

- `README.md` — Detailed lab documentation
- `Vagrantfile` — VM orchestration
- `configs/` — Lab configuration files
- `scripts/` — Automation and attack helpers
- `requirements.txt` — Python dependencies

> 📘 [View PJPT AD Lab Documentation](labs/ad-pentest-lab/README.md)

---

### VLAN-Based Enterprise Lab (Advanced)

- **Location:** `labs/ad-pentest-lab-vlan/`
- **Focus:**
  - VLAN segmentation
  - Linux bridges
  - Realistic enterprise network isolation

- **Includes:**
  - Network diagrams (Mermaid)
  - VLAN automation scripts
  - Troubleshooting and networking documentation

---

## LLM & AI Security Training

### LLM01 – Language Model Security Lab

The **LLM01 VM** introduces **AI and LLM attack surfaces** into the enterprise environment.

**Training Coverage:**

- Prompt Injection (direct and indirect)
- AI API abuse and weak authentication
- Sensitive data disclosure through context manipulation
- Misconfigured containerized AI services
- Cloud credential leakage via AI integrations
- AI supply-chain and dependency risks

**Purpose:**

LLM01 bridges **traditional pentesting** with **modern AI security testing**, allowing realistic practice against AI-enabled enterprise systems.

---

## Tutorials

Tutorials and guides are located in `tutorials/` and include:

- Active Directory MITRE log source playbooks
- AppArmor configuration guides
- Git fundamentals for Linux users
- Pacstall AUR tutorial
- KVM/QEMU installation and CLI management
- TimeShift CLI backup management
- Vagrant and libvirt usage
- Windows Server Active Directory assessment

Each tutorial includes **step-by-step instructions** and **practical examples**.

---

## Installation

### Python Dependencies

```bash
pip install -r requirements.txt
```

### Bash / Linting Tools

```bash
sudo apt install shellcheck
```

---

## Usage

Each script and lab includes:

- Description
- Usage instructions
- Configuration notes
- Author information

Scripts are grouped by **category** for clarity and maintainability.

---

## Repository Structure

```
assets/                     ← Images and GitHub visuals
labs/
├── ad-pentest-lab/          ← PJPT Enterprise AD Pentest Lab
│   ├── README.md
│   ├── Vagrantfile
│   ├── configs/
│   ├── scripts/
│   └── requirements.txt
├── ad-pentest-lab-vlan/     ← VLAN-based enterprise lab
│   ├── diagrams/
│   ├── docs/
│   ├── scripts/
│   └── Vagrantfile
tutorials/                  ← Tutorials and guides
security/                   ← Security scripts
sysadmin/                   ← System administration tools
LICENSE
CONTRIBUTING.md
```

---

## Contribution

Contributions are welcome.

Please review [CONTRIBUTING.md](CONTRIBUTING.md) before submitting pull requests.

---

## Community Guidelines

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)

For discussions and questions, visit **GitHub Discussions**.

---

## License

This project is licensed under the **MIT License**.
See the [LICENSE](LICENSE) file for details.

```

---
```
````
