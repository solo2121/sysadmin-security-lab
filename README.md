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

It simulates real-world enterprise environments across **Linux, DevOps, and security domains**, enabling hands-on, end-to-end infrastructure and attack/defense workflows.

It integrates:

* Linux system administration (LFCS / RHCSA level)
* DevOps infrastructure automation
* Kubernetes cluster environments
* Active Directory attack and defense labs
* Network segmentation and virtualization (VLANs)
* Offensive security tooling workflows
* AI / LLM security research scenarios

The goal is to provide a realistic, scalable, and repeatable environment for technical mastery.

---

## Why This Project?

Unlike isolated labs, this platform provides:

* **End-to-end environments** (not fragmented exercises)
* **Real attack + defense scenarios** across multiple layers
* **Reproducible infrastructure** using Vagrant and Infrastructure as Code
* **Cross-domain learning** (Sysadmin → DevOps → Security → AI)

This is not a single lab — it's a **complete learning ecosystem**.

---

## ⚠️ Authorized Use

**This repository contains offensive security content.** Before using:

1. **Read** [`docs/SECURITY-SCOPE.md`](docs/SECURITY-SCOPE.md)
2. **Verify** you have explicit permission to test any infrastructure
3. **Isolate** labs on VMs you control (never on production networks)
4. **Report** security issues privately to `security@solo2121.com`

**TL;DR:** Use only in authorized, isolated lab environments.

---

## Target Audience

This project is designed for:

* Linux system administrators
* DevOps engineers
* Cloud infrastructure engineers
* Security engineers and penetration testers
* Red team / blue team practitioners
* AI security researchers

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

## 📖 Documentation

| Document                                           | Purpose                 |
| -------------------------------------------------- | ----------------------- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)     | Design and structure    |
| [`docs/SECURITY-SCOPE.md`](docs/SECURITY-SCOPE.md) | Authorized use          |
| [`CONTRIBUTING.md`](CONTRIBUTING.md)               | Contribution guidelines |
| [`INSTALLATION.md`](INSTALLATION.md)               | Setup instructions      |
| [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md)         | Fixes                   |
| [`SECURITY.md`](SECURITY.md)                       | Vulnerability reporting |

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
