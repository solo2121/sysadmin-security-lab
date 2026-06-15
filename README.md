````md
# Sysadmin Security Lab

A reproducible DevSecOps and security engineering lab for simulating Active Directory attacks, building detection pipelines, and automating infrastructure using virtualization and infrastructure-as-code tools.

---

## Overview

This project is a modular security lab environment designed to replicate enterprise infrastructure for:

- Active Directory attack simulation and defense
- Detection engineering aligned with MITRE ATT&CK
- Infrastructure automation and reproducible lab deployment
- Security monitoring and observability
- DevSecOps pipeline experimentation

It is built for hands-on security research, blue team detection engineering, and offensive security validation in a controlled environment.

**Maintained by:** solo2121  
**Status:** Active  
**Last Updated:** 2026-06-15  

---

## Core Domains

- Active Directory security (Kerberos, LDAP, AD CS attack paths)
- Attack simulation (NTLM relay, ESC techniques, domain compromise chains)
- Detection engineering (MITRE ATT&CK mapping, log analysis)
- Infrastructure as Code (Vagrant, Ansible, Terraform)
- Virtualization (KVM/QEMU, libvirt)
- Security monitoring (Prometheus, Grafana, Loki)
- Network segmentation and isolated lab design

---

## Architecture

```text
[ Attacker VM ]
       |
       v
-------------------------------------
|     Isolated Lab Network          |
-------------------------------------
     |                  |
[ Domain Controller ] [ Member Servers ]
     |                  |
------ Logging & Monitoring ---------
               |
 [ Grafana | Prometheus | Loki ]
````

---

## Key Capabilities

* End-to-end Active Directory attack chain simulation
* Reproducible multi-node lab environments using Vagrant + KVM/QEMU
* Detection engineering mapped to MITRE ATT&CK techniques
* Centralized logging and observability stack
* Isolated network design for safe offensive security testing
* Infrastructure automation for rapid lab deployment

---

## Skills Demonstrated

* Active Directory exploitation and defense
* Detection engineering and security analytics
* Infrastructure as Code (Vagrant, Ansible, Terraform)
* Linux system administration and virtualization
* Network security and segmentation
* Security monitoring and observability systems
* DevSecOps workflow design

---

## Quick Start

### Requirements

* Linux host with KVM support
* 16–32 GB RAM recommended
* Vagrant + libvirt

---

### Installation

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab

sudo apt update && sudo apt install -y \
qemu-kvm libvirt-daemon-system virt-manager vagrant

vagrant plugin install vagrant-libvirt vagrant-reload vagrant-winrm
```

---

### Launch Lab

```bash
cd labs/security/ad-pentest
vagrant up dc01
vagrant status
```

---

## Repository Structure

```text
docs/               Technical documentation and architecture
labs/               Lab environments (attack & defense scenarios)
security/           Offensive & defensive security tooling
sysadmin/           Infrastructure automation scripts
assets/             Supporting resources and documentation
```

---

## Documentation

| Resource          | Description                       |
| ----------------- | --------------------------------- |
| PORTFOLIO.md      | Lab index and technical breakdown |
| ARCHITECTURE.md   | Infrastructure design model       |
| SECURITY-SCOPE.md | Security boundaries and rules     |
| INSTALLATION.md   | Setup and deployment guide        |
| CHANGELOG.md      | Project history                   |

---

## Security & Ethics

This project is strictly for educational and authorized security research purposes.

All testing must be performed only in environments you own or are explicitly authorized to use.

Unauthorized access or testing against real systems is strictly prohibited.

---

## License

MIT License

```

---
