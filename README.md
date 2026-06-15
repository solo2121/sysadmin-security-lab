<h1 align="center">Sysadmin Security Lab</h1>

<p align="center">

![Last Commit](https://img.shields.io/github/last-commit/solo2121/sysadmin-security-lab)
![License](https://img.shields.io/github/license/solo2121/sysadmin-security-lab)
![Top Language](https://img.shields.io/github/languages/top/solo2121/sysadmin-security-lab)
![Repo Size](https://img.shields.io/github/repo-size/solo2121/sysadmin-security-lab)
![Stars](https://img.shields.io/github/stars/solo2121/sysadmin-security-lab?style=social)

</p>

---

## Overview

A modular DevSecOps and security engineering lab simulating enterprise-grade infrastructure for offensive security, detection engineering, and infrastructure automation practice.

Maintained by: **solo2121**  
Status: Active  
Last Updated: 2026-06-15

---

## What This Project Is

This repository is a hands-on, reproducible security lab designed to simulate real enterprise environments for learning and research.

It focuses on:

- Infrastructure automation and provisioning
- Active Directory attack and defense simulation
- Detection engineering aligned with MITRE ATT&CK
- Network segmentation and traffic analysis
- DevSecOps pipelines and observability
- AI / LLM security research

---

## Core Domains

- Active Directory security (Kerberos, LDAP, AD CS attack paths)
- DevSecOps infrastructure (Vagrant, KVM/QEMU, Ansible, Terraform)
- Detection engineering and security telemetry
- Network security and VLAN-based segmentation
- Monitoring stacks (Prometheus, Grafana, Loki)
- AI / LLM security experimentation

---

## Key Highlights

- Full attack chain simulation: ESC8 → NTLM relay → domain compromise
- Multi-VM enterprise environments using Vagrant + KVM/QEMU
- Detection rules mapped to MITRE ATT&CK techniques
- Isolated network segmentation with traffic inspection
- Kubernetes-based observability stack (Prometheus, Grafana, Loki)

---

## Quick Start

**Requirements:** Linux host with KVM support, 16 GB+ RAM recommended
### Requirements

- Linux host with KVM support
- 16GB+ RAM (32GB recommended)
- Vagrant + libvirt

### Installation

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab

sudo apt update && sudo apt install -y qemu-kvm libvirt-daemon-system virt-manager vagrant

vagrant plugin install vagrant-libvirt vagrant-reload vagrant-winrm
```

# Start a specific lab
### Run a Lab

```bash
cd labs/security/ad-pentest
vagrant up dc01
vagrant status
```

---

## Navigate This Repo

→ **[PORTFOLIO.md](docs/PORTFOLIO.md)** — full lab index, techniques, and documentation map.

## Repository Structure

```text
.
├── docs/               # Architecture, workflows, and detailed guides
├── labs/               # Enterprise-grade lab environments
├── security/           # Phase-based security tooling (Audit, Network, Recon, Exploitation)
├── sysadmin/           # Platform automation and monitoring
├── docs/               # Architecture, workflows, and technical guides
├── labs/               # Enterprise security lab environments
├── security/           # Offensive, defensive, and audit tooling
├── sysadmin/           # Automation and infrastructure tools
├── assets/             # Supporting documentation and references
├── CHANGELOG.md        # Project history
├── CODE_OF_CONDUCT.md  # Community standards
└── requirements-dev.txt # Dev environment dependencies (linting, docs)
├── CONTRIBUTING.md     # Contribution workflow rules
└── requirements-dev.txt# Development dependencies
```

## Documentation Index
---

| Resource | Description |
|----------|-------------|
| [ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) | High-level system design and directory map |
| [SECURITY-SCOPE.md](docs/architecture/SECURITY-SCOPE.md) | Critical safety boundaries and authorized use policy |
| [INSTALLATION.md](INSTALLATION.md) | Full environment setup (KVM, Vagrant, Libvirt) |
| [CHANGELOG.md](CHANGELOG.md) | Version history and latest updates |
## Documentation

| Resource                                                 | Description                                 |
| -------------------------------------------------------- | ------------------------------------------- |
| [PORTFOLIO.md](docs/PORTFOLIO.md)                        | Full lab index and technical breakdown      |
| [ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md)     | System architecture and design              |
| [SECURITY-SCOPE.md](docs/architecture/SECURITY-SCOPE.md) | Security boundaries and rules of engagement |
| [INSTALLATION.md](INSTALLATION.md)                       | Full environment setup guide                |
| [CHANGELOG.md](CHANGELOG.md)                             | Project updates and history                 |

---

## License & Disclaimer
## Security & Ethics

Licensed under the [MIT License](LICENSE). All testing must be performed in isolated environments you own and control. Do not use any tooling from this project against systems without explicit written authorization.
This project is strictly for educational and authorized security research purposes.

All testing must be performed in isolated environments that you own or have explicit permission to use.

Unauthorized use against real systems is strictly prohibited.

---

## License

Licensed under the MIT License.
