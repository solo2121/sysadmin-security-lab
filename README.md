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

```markdown
# DevSecOps & Security Engineering Lab Portfolio

This repository is a hands-on DevSecOps, security engineering, and infrastructure automation lab environment designed to simulate enterprise-grade systems.

It integrates offensive security, defensive security, infrastructure engineering, and automation into a single reproducible platform for technical practice and portfolio demonstration.

---

## Professional Focus

This project demonstrates practical capability across the following domains:

- DevSecOps engineering and infrastructure automation
- Linux system administration and hardening
- Active Directory attack and defense simulation
- Network security analysis and penetration testing
- Detection engineering and security monitoring
- Virtualized infrastructure using KVM/QEMU and Vagrant
- AI / LLM security experimentation and research

The objective is to provide a realistic environment that reflects enterprise security and infrastructure workflows.

---

## Portfolio Highlights

This project is structured as a production-style security and infrastructure lab platform.

Key highlights include:

- Active Directory enterprise attack simulation environment (Kerberos, LDAP, ESC attacks)
- Modular DevSecOps infrastructure using Vagrant and KVM/QEMU
- Detection engineering and log analysis automation tooling
- Network segmentation and VLAN-based enterprise simulation
- Linux hardening and system administration automation
- Security testing frameworks for penetration testing workflows
- AI / LLM security experimentation environments

This is designed to reflect real-world engineering responsibilities in security and infrastructure roles, not isolated lab exercises.

---

## Overview

The platform is structured as a modular lab ecosystem combining infrastructure, security, and system administration components.

It is designed to replicate real-world environments where infrastructure, security operations, and automation intersect.

Key characteristics:

- Reproducible lab environments
- Multi-layer enterprise simulation (Linux, Active Directory, networking)
- Offensive and defensive security workflows
- Infrastructure-as-code style automation
- Scalable modular design

---

## What This Project Demonstrates

This repository demonstrates the ability to design, build, and operate:

- Secure Linux and hybrid infrastructure environments
- DevOps automation workflows and lab orchestration
- Security monitoring and detection systems
- Controlled offensive security testing environments
- Active Directory enterprise simulation environments
- Network segmentation and VLAN-based architectures
- Infrastructure automation using scripting and virtualization tools
- AI/LLM security testing scenarios

---

## Architecture

```

Sysadmin Security Lab Platform
├── Infrastructure Layer
│   ├── KVM/QEMU virtualization
│   ├── Vagrant automation
│   └── provisioning scripts
│
├── Security Layer
│   ├── Active Directory lab environments
│   ├── penetration testing tools
│   └── network segmentation (VLANs)
│
├── System Administration Layer
│   ├── Linux automation
│   ├── system hardening
│   └── monitoring scripts
│
└── Research Layer
└── AI / LLM security testing environments

```

Full architecture details: docs/ARCHITECTURE.md

---

## Labs

### DevOps Linux Lab

Path: labs/infrastructure/devops-linux-lab/

Includes:

- Kubernetes cluster (kubeadm-based)
- Terraform provisioning workflows
- Ansible configuration management
- Linux infrastructure automation
- Monitoring stack (Prometheus, Grafana, Loki)

---

### Active Directory Pentest Lab

Path: labs/security/ad-pentest/

Focus areas:

- Active Directory enumeration and attack chains
- Kerberos attacks (Kerberoasting, AS-REP roasting)
- Certificate Services exploitation (ESC attacks)
- Lateral movement and privilege escalation
- SMB relay and persistence techniques

---

### VLAN Enterprise Security Lab

Path: labs/security/ad-pentest-vlan/

Focus areas:

- Network segmentation and isolation
- Multi-subnet enterprise simulation
- VLAN configuration and testing
- Network topology analysis

Includes automation scripts and architecture diagrams.

---

## Security Engineering Tooling

This repository includes tooling and scripts for:

- Network scanning and reconnaissance
- Active Directory security testing
- Web application security workflows
- Post-exploitation and analysis tools
- Linux system auditing and monitoring

---

## AI / LLM Security Research

Experimental environments for analyzing security risks in AI systems:

- Prompt injection testing
- Context manipulation attacks
- Data leakage scenarios
- Misconfigured LLM integrations
- AI-enabled attack surface analysis

---

## Quick Start

```

git clone [https://github.com/solo2121/sysadmin-security-lab.git](https://github.com/solo2121/sysadmin-security-lab.git)
cd sysadmin-security-lab

```

Install dependencies:

```

sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system virt-manager vagrant -y

```

Validate environment:

```

vagrant up
vagrant status

```

Example validation:

```

kubectl get nodes

```

---

## Running Labs

```

cd labs/security/ad-pentest
vagrant up

```

Each lab includes:

- Setup instructions
- Architecture documentation
- Execution workflow
- Troubleshooting guides

---

## Learning Path

Recommended progression:

1. Linux systems administration
2. Virtualization and networking fundamentals
3. Infrastructure automation (Ansible, Terraform)
4. Kubernetes and container orchestration
5. Active Directory security and attack simulation
6. Privilege escalation and persistence techniques
7. AI / LLM security testing

---

## Documentation

| Document | Purpose |
|----------|--------|
| docs/ARCHITECTURE.md | System design and architecture |
| docs/SECURITY-SCOPE.md | Authorized usage boundaries |
| INSTALLATION.md | Setup instructions |
| TROUBLESHOOTING.md | Issue resolution |
| CONTRIBUTING.md | Contribution guidelines |

---

## Contributing

Contributions are welcome.

Please ensure:

- Changes align with lab architecture
- Security scope is respected
- Documentation is included for new features

---

## License

This project is licensed under the MIT License.

See LICENSE for details.

---

## Disclaimer

This repository is intended for educational and security research purposes only.
All testing must be performed in isolated environments you control.
```
