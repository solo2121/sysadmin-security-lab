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

**Last Updated:** 2026-05-29  
**Maintained By:** solo2121  
**Status:** Active & Maintained

---

## Professional Focus

This project is designed to reflect real-world engineering capabilities aligned with:

- DevSecOps Engineering
- Security Engineering (Blue Team / Red Team fundamentals)
- Site Reliability Engineering (SRE)
- Linux Systems Administration
- Infrastructure Engineering

It emphasizes practical implementation over theoretical exercises.

---

## Overview

The **Sysadmin Security Lab** is a reproducible, modular infrastructure platform designed to simulate real-world enterprise environments for hands-on learning.

It integrates Linux, DevOps, and security domains to enable full lifecycle infrastructure and security engineering workflows.

Core areas include:

- Linux system administration (CompTIA Linux+ / LFCS / RHCSA level)
- DevOps infrastructure automation
- Kubernetes cluster environments
- Active Directory attack and defense labs
- Network segmentation and virtualization (VLANs)
- Security monitoring and detection engineering
- AI / LLM security research scenarios

The goal is to provide a realistic, scalable, and repeatable environment for technical mastery.

---

## What This Project Demonstrates

This repository is not a collection of scripts.

It demonstrates the ability to design and operate:

- Secure Linux and hybrid infrastructure environments
- DevOps automation workflows and infrastructure provisioning concepts
- Security monitoring and detection systems
- Controlled offensive security testing environments
- Enterprise-style Active Directory lab architectures
- Infrastructure-as-Code based reproducible systems
- AI/LLM security testing scenarios

This project reflects practical engineering capability across **SysAdmin, DevOps, DevSecOps, and Security Engineering domains**.

---

## Why This Project?

Unlike isolated labs, this platform provides:

- End-to-end environments (not fragmented exercises)
- Real attack + defense scenarios across multiple layers
- Reproducible infrastructure using Vagrant and virtualization
- Cross-domain learning (Sysadmin → DevOps → Security → AI)

This repository is designed as a portfolio-grade engineering environment intended to demonstrate production-relevant skills to hiring teams.

---

## Authorized Use

This repository contains offensive security content.

Before using:

1. Read `docs/SECURITY-SCOPE.md`
2. Use only in isolated lab environments you control
3. Do not run against production or unauthorized systems
4. Follow responsible security research practices

---

## Architecture

```text
Sysadmin Security Lab Platform
├── Infrastructure Layer (DevOps Lab)
│   └── KVM/QEMU + Vagrant + automation tooling
│
├── Security Layer
│   ├── Active Directory Lab
│   └── Network segmentation (VLAN environments)
│
├── System Administration Layer
│   └── Linux automation, monitoring, and hardening
│
└── Research Layer
    └── AI / LLM security testing environments

Full architecture breakdown: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

---

## Core Capabilities

* Full local enterprise infrastructure simulation using **Vagrant + Libvirt + KVM**
* Multi-node Linux environments
* Kubernetes cluster deployment (kubeadm-based)
* Infrastructure as Code (Terraform + Ansible)
* Observability stack (Prometheus, Grafana, Loki)
* Active Directory attack chain simulation
* Network segmentation using VLANs
* Offensive security workflows
* AI / LLM security experimentation

---

## Labs

### DevOps Linux Lab (Core Platform)

**Path:** `labs/infrastructure/devops-linux-lab/`

Includes:

* Kubernetes cluster (kubeadm-based)
* Terraform provisioning
* Ansible configuration management
* Helm deployments
* Monitoring stack (Prometheus, Grafana, Loki)
* Linux certification practice environments

---

### Active Directory Pentest Lab

**Path:** `labs/security/ad-pentest/`

Focus areas:

* Active Directory enumeration
* Kerberos attacks (Kerberoasting, AS-REP roasting)
* Certificate Services exploitation (ESC attacks)
* SMB relay and lateral movement
* Privilege escalation and persistence

---

### VLAN Enterprise Lab

**Path:** `labs/security/ad-pentest-vlan/`

Focus areas:

* Network segmentation and isolation
* VLAN configuration and testing
* Multi-subnet enterprise simulation
* Network topology analysis

Includes:

* Architecture diagrams
* Automation scripts
* Troubleshooting guides

---

## Security Tooling

Includes practical tooling for:

* Network scanning (e.g., nmap, masscan)
* Active Directory attacks (e.g., impacket, bloodhound)
* Web application testing workflows
* Post-exploitation techniques

---

## AI / LLM Security Research

Hands-on scenarios exploring:

* Prompt injection attacks
* Context manipulation and data leakage
* Abuse of LLM-integrated APIs
* Misconfigured AI deployments
* Supply chain vulnerabilities

Includes experimental environments for testing real-world AI attack surfaces.

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

Validate setup:

```bash
vagrant up
vagrant status
```

Example (Kubernetes validation):

```bash
kubectl get nodes
```

See [`INSTALLATION.md`](INSTALLATION.md) for full setup instructions.

---

## Running Labs

```bash
cd labs/security/ad-pentest
vagrant up
```

Each lab includes setup steps, architecture overview, execution guidance, and troubleshooting.

---

## Learning Path

Follow this progression:

1. Linux fundamentals
2. Virtualization and networking
3. Infrastructure as Code (Ansible, Terraform)
4. Kubernetes and containers
5. Active Directory security
6. Privilege escalation and persistence
7. AI / LLM security testing

---

## Repository Structure

```text
sysadmin-security-lab/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY-SCOPE.md
│   └── WORKFLOWS.md
│
├── labs/
│   ├── infrastructure/
│   ├── security/
│   └── README.md
│
├── security/
├── sysadmin/
├── tutorials/
├── assets/
├── LICENSE
├── CONTRIBUTING.md
├── INSTALLATION.md
├── TROUBLESHOOTING.md
├── SECURITY.md
└── README.md
```

---

## Documentation

| Document | Purpose |
|----------|----------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Design and structure |
| [`docs/SECURITY-SCOPE.md`](docs/SECURITY-SCOPE.md) | Authorized use |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution guidelines |
| [`INSTALLATION.md`](INSTALLATION.md) | Setup instructions |
| [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | Fixes |
| [`SECURITY.md`](SECURITY.md) | Vulnerability reporting |

---

## Contributing

Contributions are welcome.

* Review architecture and structure
* Follow contribution guidelines
* Ensure security scope compliance

Submit pull requests that:

* Add labs or tools with documentation
* Improve existing components
* Fix bugs or issues
* Enhance documentation

---

## License

This project is licensed under the **MIT License**.

See [`LICENSE`](LICENSE) for details.

---

## Support

* Check GitHub Issues
* Review troubleshooting docs
* Consult lab documentation
* Report security issues via [`SECURITY.md`](SECURITY.md)
