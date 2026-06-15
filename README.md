<h1 align="center">Sysadmin Security Lab</h1>

<p align="center">

![Last Commit](https://img.shields.io/github/last-commit/solo2121/sysadmin-security-lab)
![License](https://img.shields.io/github/license/solo2121/sysadmin-security-lab)
![Top Language](https://img.shields.io/github/languages/top/solo2121/sysadmin-security-lab)
![Repo Size](https://img.shields.io/github/repo-size/solo2121/sysadmin-security-lab)
![Stars](https://img.shields.io/github/stars/solo2121/sysadmin-security-lab?style=social)
![Issues](https://img.shields.io/github/issues/solo2121/sysadmin-security-lab)

</p>

---

## Overview

A modular **DevSecOps, DevOps, and security engineering lab** designed to simulate enterprise-grade infrastructure for penetration testing, detection engineering, and infrastructure automation.

This repository demonstrates real-world engineering capability across offensive and defensive security domains.

**Maintained by:** solo2121  
**Status:** Active  
**Last Updated:** 2026-06-15  

---

## What This Project Is

This is a production-style security lab environment that replicates real enterprise infrastructure for hands-on security engineering practice.

It is designed to demonstrate:

- Realistic Active Directory attack and defense scenarios
- Infrastructure automation and reproducible environments
- Detection engineering aligned with MITRE ATT&CK
- Network segmentation and traffic analysis
- DevSecOps pipelines and infrastructure provisioning
- Observability and security monitoring systems

---

## Core Domains

- Active Directory security (Kerberos, LDAP, AD CS attack paths)
- Penetration testing and attack simulation
- DevOps / DevSecOps automation (Vagrant, KVM/QEMU, Ansible, Terraform)
- Detection engineering and log analysis (MITRE ATT&CK mapping)
- Network security and segmentation (VLANs, isolated lab environments)
- Monitoring and observability (Prometheus, Grafana, Loki)

---

## Key Highlights

- Full enterprise attack chain simulation (ESC8 → NTLM relay → domain compromise)
- Multi-node reproducible lab environments using Vagrant + KVM/QEMU
- Detection rules mapped to MITRE ATT&CK techniques
- Isolated network architecture with full traffic visibility
- Infrastructure monitoring stack with Prometheus, Grafana, and Loki
- Designed for repeatable security research and training

---

## Architecture Overview

```text
                 [ Attacker VM ]
                        |
                        v
        -----------------------------------
        |        Isolated Lab Network     |
        -----------------------------------
             |                  |
     [ Domain Controller ]  [ Member Servers ]
             |                  |
             ------ Logging / Monitoring ------
                        |
        [ Grafana / Prometheus / Loki Stack ]
```

---

## Quick Start

### Requirements

* Linux host with KVM support
* 16 GB RAM minimum (32 GB recommended)
* Vagrant + libvirt

---

### Installation

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab

sudo apt update && sudo apt install -y qemu-kvm libvirt-daemon-system virt-manager vagrant

vagrant plugin install vagrant-libvirt vagrant-reload vagrant-winrm
```

---

### Run a Lab

```bash id="run"
cd labs/security/ad-pentest
vagrant up dc01
vagrant status
```

---

## Repository Structure

```text id="structure"
.
├── docs/               # Architecture and technical documentation
├── labs/               # Security lab environments
├── security/           # Offensive and defensive tooling
├── sysadmin/           # Automation and infrastructure tools
├── assets/             # Supporting documentation and resources
├── CHANGELOG.md        # Project history and updates
├── CONTRIBUTING.md     # Contribution workflow and standards
└── requirements-dev.txt# Development dependencies
```

---

## Documentation

| Resource                                                 | Description                                 |
| -------------------------------------------------------- | ------------------------------------------- |
| [PORTFOLIO.md](docs/PORTFOLIO.md)                        | Full lab index and technical breakdown      |
| [ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md)     | System design and infrastructure model      |
| [SECURITY-SCOPE.md](docs/architecture/SECURITY-SCOPE.md) | Security boundaries and rules of engagement |
| [INSTALLATION.md](INSTALLATION.md)                       | Full setup guide                            |
| [CHANGELOG.md](CHANGELOG.md)                             | Project history and updates                 |

---

## Security & Ethics

This project is strictly for educational and authorized security research purposes.

All testing must be performed only in environments you own or have explicit permission to use.

Unauthorized access or testing against real systems is strictly prohibited.

---

## License

Licensed under the MIT License.

```