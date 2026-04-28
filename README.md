# Sysadmin Security Lab

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB.svg?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/Bash-5.x-4EAA25.svg?style=for-the-badge&logo=gnubash&logoColor=white">
  <img src="https://img.shields.io/badge/Vagrant-Libvirt-1563FF.svg?style=for-the-badge&logo=vagrant&logoColor=white">
  <img src="https://img.shields.io/badge/KVM_QEMU-FF6600.svg?style=for-the-badge&logo=qemu&logoColor=white">
  <img src="https://img.shields.io/badge/Security-Pentesting-red.svg?style=for-the-badge">
  <img src="https://img.shields.io/badge/AD-Lab-FF8C00.svg?style=for-the-badge">
  <img src="https://img.shields.io/badge/LLM-Security-8A2BE2.svg?style=for-the-badge">
</p>

---

## Overview

The **Sysadmin Security Lab** is a reproducible, modular infrastructure platform designed to simulate real-world enterprise environments for hands-on learning.

It combines **Linux system administration, DevOps engineering, and offensive security** into a unified learning ecosystem.

It integrates:
- Linux system administration (LFCS / RHCSA level)
- DevOps infrastructure automation
- Kubernetes cluster environments
- Active Directory attack and defense labs
- Network segmentation and virtualization (VLANs)
- Offensive security tooling workflows
- AI / LLM security research scenarios

The goal is to provide a realistic, scalable, and repeatable environment for technical mastery.

---

## ⚠️ Authorized Use

**This repository contains offensive security content.** Before using:

1. **Read** [`docs/SECURITY-SCOPE.md`](docs/SECURITY-SCOPE.md) — Authorized vs. prohibited uses
2. **Verify** you have explicit permission to test any infrastructure
3. **Isolate** labs on VMs you control (never on production networks)
4. **Report** security issues privately to `security@solo2121.com`

**TL;DR:** Use only in authorized, isolated lab environments. See [Security & Authorized Use](docs/SECURITY-SCOPE.md) for details.

---

## Target Audience

This project is designed for:
- Linux system administrators
- DevOps engineers
- Cloud infrastructure engineers
- Security engineers and penetration testers
- Red team / blue team practitioners
- AI security researchers

---

## Architecture

```text
Sysadmin Security Lab Platform
├── Infrastructure Layer (DevOps Lab)
│   └── Terraform + Ansible + Kubernetes + Monitoring
│
├── Security Layer
│   ├── Active Directory Pentest Lab
│   └── VLAN Enterprise Lab
│
├── System Administration Layer
│   └── Linux automation and hardening tools
│
└── Research Layer
    └── AI / LLM security testing
```

Full architecture breakdown: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

---

## Core Capabilities

- Full local enterprise infrastructure simulation using **Vagrant + Libvirt + KVM**
- Multi-node Linux environments
- Kubernetes cluster deployment (kubeadm-based)
- Infrastructure as Code (Terraform + Ansible)
- Observability stack (Prometheus, Grafana, Loki)
- Active Directory attack chain simulation
- Network segmentation using VLANs
- Offensive security tooling workflows
- AI / LLM security experimentation

---

## Labs

### DevOps Linux Lab (Core Platform)
**Path:** `labs/infrastructure/devops-linux-lab/`

This is the main infrastructure and DevOps environment.

**Includes:**
- Kubernetes cluster (kubeadm-based)
- Terraform provisioning layer
- Ansible configuration management
- Helm application deployment
- Monitoring stack (Prometheus, Grafana, Loki)
- Linux certification practice environments

---

### Active Directory Pentest Lab
**Path:** `labs/security/ad-pentest/`

**Focus areas:**
- Active Directory enumeration
- Kerberos attacks (Kerberoasting, AS-REP roasting)
- Certificate Services exploitation (ESC attacks)
- SMB relay and lateral movement
- Privilege escalation and persistence

---

### VLAN Enterprise Lab
**Path:** `labs/security/ad-pentest-vlan/`

**Focus areas:**
- Network segmentation and isolation
- VLAN configuration and testing
- Multi-subnet enterprise simulation
- Network topology analysis

**Includes:**
- Architecture diagrams
- Automation scripts
- Troubleshooting guides

---

## Security Tooling

This repository includes categorized tools for:
- Network reconnaissance and scanning
- Credential attacks and brute force techniques
- Web application exploitation
- Post-exploitation workflows
- Wireless security testing
- Active Directory exploitation techniques

---

## AI / LLM Security Research

This section focuses on security risks in modern AI systems:
- Prompt injection attacks
- Context manipulation and data leakage
- API abuse and weak authentication
- Misconfigured AI deployments
- Supply chain vulnerabilities
- Credential leakage via integrations

---

## Quick Start

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab
```

Install dependencies:

```bash
sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system virt-manager vagrant -y
```

See [`INSTALLATION.md`](INSTALLATION.md) for detailed setup instructions.

---

## Running Labs

Example:

```bash
cd labs/security/ad-pentest
vagrant up
```

Each lab includes setup instructions, architecture overview, execution steps, and troubleshooting guides.

For more details, see [`labs/README.md`](labs/README.md).

---

## Learning Path

Recommended progression:
1. Linux system administration fundamentals
2. Virtualization and networking concepts
3. Infrastructure automation (Ansible, Terraform)
4. Kubernetes and container orchestration
5. Active Directory attack simulation
6. Privilege escalation and persistence
7. AI / LLM security testing

---

## Repository Structure

```text
sysadmin-security-lab/
├── docs/                    # Repository governance & architecture
│   ├── ARCHITECTURE.md      # Directory structure and design
│   ├── SECURITY-SCOPE.md    # Authorized use & ethical boundaries
│   └── WORKFLOWS.md         # CI/CD patterns (coming soon)
│
├── labs/                    # Hands-on learning environments
│   ├── infrastructure/      # DevOps, Kubernetes labs
│   ├── security/            # AD, VLAN, pentest labs
│   └── README.md            # Labs index
│
├── security/                # Standalone security tools
├── sysadmin/                # System administration scripts
├── tutorials/               # Educational documentation
├── assets/                  # Diagrams, templates, references
├── LICENSE                  # MIT License
├── CONTRIBUTING.md          # Contribution guidelines
├── INSTALLATION.md          # Setup instructions
├── TROUBLESHOOTING.md       # Common issues & fixes
├── SECURITY.md              # Vulnerability reporting
└── README.md                # This file
```

**See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for detailed structure.**

---

## 📖 Documentation

| Document | Purpose |
|----------|---------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Repository design, directory structure, contribution workflow |
| [`docs/SECURITY-SCOPE.md`](docs/SECURITY-SCOPE.md) | Authorized use boundaries, ethical framework, lab requirements |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution guidelines |
| [`INSTALLATION.md`](INSTALLATION.md) | Dependency setup and troubleshooting |
| [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | Common issues and fixes |
| [`SECURITY.md`](SECURITY.md) | Vulnerability reporting policy |

---

## Contributing

Contributions are welcome! Please review:
1. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Understand the repo design
2. [`CONTRIBUTING.md`](CONTRIBUTING.md) — Follow the contribution guidelines
3. [`docs/SECURITY-SCOPE.md`](docs/SECURITY-SCOPE.md) — Ensure content is in scope

Submit pull requests that:
- Add new labs or tools with complete documentation
- Improve existing labs/tools
- Fix bugs or security issues
- Enhance documentation

---

## License

This project is licensed under the **MIT License**.  
See [`LICENSE`](LICENSE) for details.

---

## Support

For issues, questions, or suggestions:
- Check existing [GitHub Issues](https://github.com/solo2121/sysadmin-security-lab/issues)
- Review [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) for common problems
- Consult lab-specific README files
- For security concerns, see [`SECURITY.md`](SECURITY.md)
