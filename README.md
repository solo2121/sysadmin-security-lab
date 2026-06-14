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

<h1 align="center">Sysadmin Security Lab</h1>

<p align="center">
  A modular, reproducible security and infrastructure lab platform simulating enterprise-grade environments for offensive security, detection engineering, and DevSecOps practice.
</p>

<p align="center">
  <strong>Maintained by:</strong> solo2121 &nbsp;|&nbsp; <strong>Last Updated:</strong> 2026-05-29 &nbsp;|&nbsp; <strong>Status:</strong> Active
</p>

---

## Overview

This repository is a hands-on DevSecOps and security engineering lab designed to replicate real-world enterprise infrastructure. It integrates offensive security, defensive monitoring, and infrastructure automation into a single, reproducible platform.

**Core domains covered:**

- Active Directory attack and defense simulation (Kerberos, LDAP, AD CS)
- Linux system administration, hardening, and automation
- Network security, segmentation, and VLAN-based enterprise simulation
- Detection engineering and log analysis
- DevSecOps tooling: Vagrant, KVM/QEMU, Ansible, Terraform, Kubernetes
- AI/LLM security research (prompt injection, context manipulation, data leakage)

---

## Architecture

```
sysadmin-security-lab/
├── labs/
│   ├── infrastructure/
│   │   └── devops-linux-lab/       # Kubernetes, Terraform, Ansible, monitoring stack
│   └── security/
│       ├── ad-pentest/             # Active Directory attack simulation
│       └── ad-pentest-vlan/        # Network-segmented AD environment
├── docs/
│   ├── ARCHITECTURE.md
│   └── SECURITY-SCOPE.md
├── INSTALLATION.md
├── TROUBLESHOOTING.md
└── CONTRIBUTING.md
```

---

## Labs

### DevOps Linux Lab

**Path:** `labs/infrastructure/devops-linux-lab/`

A full Linux infrastructure environment for practicing DevOps and automation workflows.

- Kubernetes cluster provisioned via `kubeadm`
- Infrastructure-as-code with Terraform and Ansible
- Monitoring stack: Prometheus, Grafana, and Loki
- Linux hardening scripts and system auditing tooling

---

### Active Directory Pentest Lab

**Path:** `labs/security/ad-pentest/`

An isolated Windows Active Directory environment for simulating real-world attack chains.

- AD enumeration and lateral movement
- Kerberoasting and AS-REP roasting
- AD Certificate Services exploitation (ESC1–ESC8)
- SMB relay, persistence, and privilege escalation techniques
- Post-exploitation analysis workflows

---

### VLAN Enterprise Security Lab

**Path:** `labs/security/ad-pentest-vlan/`

Extends the AD lab with full network segmentation to simulate an enterprise perimeter.

- Multi-subnet VLAN configuration and isolation testing
- Network topology analysis and traffic inspection
- Automation scripts for rapid environment teardown and rebuild
- Architecture diagrams included

---

## AI / LLM Security Research

Experimental environments for analyzing security risks in AI-integrated systems:

- Prompt injection and jailbreak testing
- Context manipulation and data leakage scenarios
- Misconfigured LLM integration attack surfaces
- AI-enabled reconnaissance and automation experiments

---

## Quick Start

**Requirements:** Linux host with KVM support, 16 GB+ RAM recommended

```bash
# Clone the repository
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab

# Install dependencies
sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system virt-manager vagrant

# Validate virtualization environment
vagrant up
vagrant status
```

**To start a specific lab:**

```bash
cd labs/security/ad-pentest
vagrant up
```

Each lab directory contains its own `README.md` with setup instructions, architecture notes, and a troubleshooting guide.

---

## Documentation

| Document | Purpose |
|---|---|
| `docs/ARCHITECTURE.md` | Full system design and component diagrams |
| `docs/SECURITY-SCOPE.md` | Authorized usage boundaries |
| `INSTALLATION.md` | Dependency setup and environment validation |
| `TROUBLESHOOTING.md` | Common issues and fixes |
| `CONTRIBUTING.md` | Contribution guidelines |

---

## Contributing

Contributions are welcome. Please ensure changes align with the lab architecture, respect the defined security scope, and include documentation for any new components.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Disclaimer

This repository is intended for educational and authorized security research purposes only. All testing must be performed within isolated lab environments that you own and control. Do not use any tooling or techniques from this project against systems without explicit written authorization.