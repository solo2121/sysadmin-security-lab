````markdown
# Security & System Administration Toolkit

A comprehensive collection of **security**, **system administration**, and **training tools** for Linux environments.  
Includes **PJPT-focused Active Directory labs**, tutorials, and automation scripts for practical hands-on learning.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Labs](#labs)
- [Tutorials](#tutorials)
- [Installation](#installation)
- [Usage](#usage)
- [Repository Structure](#repository-structure)
- [Contribution](#contribution)
- [Community Guidelines](#community-guidelines)
- [License](#license)

---

## Overview

This repository provides a set of tools, scripts, and labs for:

- **Linux system administration automation**
- **Security auditing and penetration testing**
- **Educational labs**, including PJPT-style Active Directory exercises

> All scripts and labs are intended for use on systems you **own** or have **explicit authorization** to test. Unauthorized use is strictly prohibited.

---

## Features

- Modular scripts organized by category (security, sysadmin)
- **PJPT-aligned Active Directory lab** with attack chains and network design
- Tutorials and reference guides for tools, Linux, KVM/QEMU, and AD administration
- Clear documentation and usage instructions

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

Run scripts according to headers in each file.

---

## Labs

### Active Directory Pentest Lab (PJPT)

- **Location:** `labs/ad-pentest-lab/`
- **Focus:** Enterprise-style AD attack chains, post-exploitation, AD CS abuse, lateral movement
- **Setup:** Vagrant + libvirt/KVM
- **Contents:**
  - `README.md` — Lab documentation, attack chains, and network topology
  - `scripts/` — Automation scripts for attacks and lab management
  - `configs/` — Vagrantfile and lab configuration YAML
  - `requirements.txt` — Python dependencies

> [View PJPT AD Lab Documentation](labs/ad-pentest-lab/README.md)

---

## Tutorials

All tutorials are located in `tutorials/`:

- **AD MITRE log source playbook**
- **AppArmor configuration guide**
- **Complete Git tutorial for Linux users**
- **Pacstall AUR tutorial for Ubuntu**
- **KVM/QEMU installation and CLI management**
- **TimeShift CLI backup guide**
- **Vagrant management tutorial**
- **Windows Server 2025 Active Directory assessment**

> Each tutorial includes step-by-step instructions and practical examples.

---

## Installation

For Python scripts:

```bash
pip install -r requirements.txt
```

For Bash scripts:

```bash
sudo apt install shellcheck
```

---

## Usage

Each script contains:

- Script name
- Description
- Usage instructions
- Author

Run scripts according to instructions. Scripts are **grouped by category** for clarity.

---

## Repository Structure

```
assets/                  ← Images, GitHub card
labs/                     ← Complete lab environments
└── ad-pentest-lab/       ← PJPT-focused Active Directory lab
    ├── README.md         ← Lab documentation
    ├── scripts/          ← Python/Bash automation scripts
    ├── configs/          ← Vagrantfile and YAML configs
    └── requirements.txt  ← Python dependencies
tutorials/                ← Tutorials and reference guides
security/                 ← Security scripts (audit, exploitation, reconnaissance, network, post-exploitation, wireless)
sysadmin/                 ← System administration scripts (automation, monitoring, utilities)
LICENSE                   ← Project license
CONTRIBUTING.md           ← Contribution guidelines
```

---

## Contribution

We welcome contributions.
Please review [CONTRIBUTING.md](CONTRIBUTING.md) before submitting pull requests.

---

## Community Guidelines

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)

For questions or discussions, visit [Discussions](https://github.com/solo2121/sysadmin-security-scripts/discussions).

---

## License

This project is licensed under the [MIT License](LICENSE).

```

```
