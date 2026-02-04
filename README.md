# Sysadmin Security Lab

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Bash](https://img.shields.io/badge/Bash-5.x-blue.svg)
![Vagrant](https://img.shields.io/badge/Vagrant-Libvirt-green.svg)
![Security](https://img.shields.io/badge/Security-Pentesting-red.svg)

A professional and comprehensive **security and system administration toolkit** for Linux environments, including **enterprise Active Directory pentest labs**, **cloud and container targets**, **LLM/AI security training**, and automation scripts designed for **hands-on learning and offensive/defensive practice**.

> ⚠️ Use only in environments you own or are explicitly authorized to test. Unauthorized use is strictly prohibited.

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
- [License](#license)

---

## Overview

This repository provides a **curated set of scripts, tools, and lab environments** for:

- Linux system administration automation
- Enterprise penetration testing
- Active Directory attack chains
- Network, cloud, and container security
- Web application testing
- AI / LLM security experimentation

---

## Features

- Modular **security and sysadmin scripts**
- PJPT-aligned Active Directory pentest lab
- Full enterprise attack chain simulation
- VLAN-based enterprise lab for realistic network segmentation
- Windows, Linux, cloud, and container targets
- LLM / AI security labs
- OWASP Top 10 and modern API vulnerabilities
- Vagrant + Libvirt/KVM environments
- Clear documentation with repeatable setups

---

## Quick Start

Clone the repository:

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab
```

Follow instructions inside each **lab** or **script** directory.

---

## Labs

### Active Directory Pentest Lab (PJPT)

- **Path:** `labs/ad-pentest-lab/`
- **Platform:** Vagrant + Libvirt/KVM
- **Focus:**
  - Enterprise Active Directory attack chains
  - AD CS abuse (ESC1, ESC6, ESC8, ESC9)
  - Kerberoasting / AS-REP Roasting
  - SMB relay & lateral movement
  - Privilege escalation and persistence

**Contents:**

- `README.md` — Detailed lab documentation
- `Vagrantfile` — VM orchestration
- `configs/` — Lab configuration
- `scripts/` — Automation & attack helpers
- `requirements.txt` — Python dependencies

📘 [View PJPT AD Lab Documentation](labs/ad-pentest-lab/README.md)

---

### VLAN-Based Enterprise Lab (Advanced)

- **Path:** `labs/ad-pentest-lab-vlan/`
- **Focus:** VLAN segmentation, Linux bridges, realistic enterprise network isolation

**Includes:**

- Network diagrams (Mermaid)
- VLAN automation scripts
- Networking troubleshooting docs

---

## LLM & AI Security Training

### LLM01 – Language Model Security Lab

**Purpose:** Introduces AI and LLM attack surfaces into enterprise environments.

**Training Coverage:**

- Prompt injection
- API abuse & weak authentication
- Sensitive data exposure via context manipulation
- Misconfigured containerized AI services
- Cloud credential leaks via AI integrations
- AI supply-chain / dependency risks

---

## Tutorials

Tutorials and guides are located in `tutorials/` and cover:

- AD MITRE log source playbooks
- AppArmor guides
- Git fundamentals for Linux
- Pacstall (AUR) package management
- KVM/QEMU CLI and setup
- TimeShift backups
- Vagrant & Libvirt management
- Windows AD pentesting

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

---

## Usage

Scripts and labs include:

- Purpose & description
- Usage instructions
- Configuration notes
- Safety considerations

Scripts are organized by **category** for clarity and maintainability.

---

## Repository Structure

```
assets/                     # Images & GitHub visuals
labs/
├── ad-pentest-lab/          # PJPT AD Pentest Lab
│   ├── README.md
│   ├── Vagrantfile
│   ├── configs/
│   ├── scripts/
│   └── requirements.txt
├── ad-pentest-lab-vlan/     # VLAN Enterprise Lab
│   ├── diagrams/
│   ├── docs/
│   ├── scripts/
│   └── Vagrantfile
tutorials/                  # Step-by-step guides
security/                   # Security tooling
sysadmin/                   # Sysadmin automation scripts
LICENSE
CONTRIBUTING.md
```

---

## Contribution

Contributions are welcome!  
Please review [CONTRIBUTING.md](CONTRIBUTING.md) before submitting pull requests.

---

## License

Licensed under the **MIT License**.  
See [LICENSE](LICENSE) for details.
