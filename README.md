

````md
# Sysadmin Security Lab

# Sysadmin Security Lab

![License](https://img.shields.io/github/license/solo2121/sysadmin-security-lab?style=for-the-badge)
![Stars](https://img.shields.io/github/stars/solo2121/sysadmin-security-lab?style=for-the-badge)
![Forks](https://img.shields.io/github/forks/solo2121/sysadmin-security-lab?style=for-the-badge)

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-5.x-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![Vagrant](https://img.shields.io/badge/Vagrant-Libvirt-1563FF?style=for-the-badge&logo=vagrant&logoColor=white)
![KVM/QEMU](https://img.shields.io/badge/KVM-QEMU-FF6600?style=for-the-badge&logo=qemu&logoColor=white)

![Linux](https://img.shields.io/badge/Linux-Labs-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![DevOps](https://img.shields.io/badge/DevOps-Automation-0A66C2?style=for-the-badge&logo=githubactions&logoColor=white)
![Security](https://img.shields.io/badge/Security-Pentesting-red?style=for-the-badge&logo=hackaday&logoColor=white)
![Active Directory](https://img.shields.io/badge/AD-Lab-FF8C00?style=for-the-badge)

![LLM Security](https://img.shields.io/badge/LLM-Security-8A2BE2?style=for-the-badge)

A modular Linux, DevOps, and security engineering lab platform designed for hands-on learning, infrastructure simulation, and practical offensive and defensive security training.

---

## Overview

The Sysadmin Security Lab is a reproducible local environment that simulates real-world enterprise infrastructure for technical practice and experimentation.

It integrates:

- Linux system administration environments
- Infrastructure and DevOps workflows
- Active Directory attack and defense labs
- Network segmentation and virtualization (VLANs)
- Offensive security tooling and workflows
- AI / LLM security research scenarios

The platform is designed for iterative learning across infrastructure, security, and automation domains.

---

## Target Audience

This project is intended for:

- Linux system administrators (LFCS / RHCSA / Linux+)
- DevOps engineers
- Security engineers and penetration testers
- Red team and blue team practitioners
- Researchers exploring AI security risks

---

## Architecture

```text
Sysadmin Security Lab Platform

├── Infrastructure Layer (DevOps Lab)
│   └── Kubernetes + Terraform + Ansible + Monitoring
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
````

---

## Core Capabilities

* Local enterprise-grade infrastructure simulation using Vagrant + Libvirt
* Multi-node Linux and Windows-like environments
* Active Directory attack chain simulation
* Network segmentation using VLANs and virtual networking
* Infrastructure as Code practices (Terraform + Ansible)
* Kubernetes cluster deployment and management
* Observability stack integration (Prometheus, Grafana, Loki)
* Security tooling for reconnaissance, exploitation, and post-exploitation
* AI/LLM security experimentation scenarios

---

## Labs

### DevOps Linux Lab (Core Platform)

Path: `labs/devops-linux-lab/`

This is the primary environment of the platform.

Includes:

* Kubernetes (kubeadm-based cluster)
* Terraform infrastructure provisioning
* Ansible configuration management
* Helm application deployment
* Monitoring stack (Prometheus, Grafana, Loki)
* Linux certification practice environments

---

### Active Directory Pentest Lab

Path: `labs/ad-pentest/`

Focus areas:

* Active Directory enumeration and attack chains
* Kerberos-based attacks (Kerberoasting, AS-REP roasting)
* Certificate Services exploitation (ESC attacks)
* SMB relay and lateral movement
* Privilege escalation and persistence techniques

---

### VLAN Enterprise Lab

Path: `labs/ad-pentest-vlan/`

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

The repository includes categorized security tools for:

* Network reconnaissance and scanning
* Credential attacks
* Web exploitation techniques
* Post-exploitation workflows
* Wireless security testing
* Active Directory exploitation

---

## AI / LLM Security Research

This section explores security risks in modern AI systems, including:

* Prompt injection attacks
* Context manipulation and data leakage
* API abuse and authentication weaknesses
* Misconfiguration in AI deployments
* Supply chain risks in AI systems
* Integration-based credential exposure

---

## Quick Start

Clone the repository:

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab
```

Install dependencies:

```bash
pip install -r requirements.txt
sudo apt install qemu-kvm libvirt-daemon-system virt-manager vagrant
```

---

## Running Labs

Example:

```bash
cd labs/ad-pentest
vagrant up
```

Each lab includes:

* Setup instructions
* Architecture documentation
* Execution steps
* Troubleshooting guides

---

## Learning Path

Recommended progression:

1. Linux fundamentals and system administration
2. Virtualization and networking concepts
3. Infrastructure automation (Ansible, Terraform)
4. Kubernetes and container orchestration
5. Active Directory attack simulation
6. Privilege escalation and persistence techniques
7. AI / LLM security testing

---

## Repository Structure

```text
sysadmin-security-lab/
├── labs/
├── security/
├── sysadmin/
├── tutorials/
├── assets/
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

---

## Contributing

Contributions are welcome.

Please review `CONTRIBUTING.md` before submitting pull requests.

---

## License

This project is licensed under the MIT License.

See `LICENSE` for details.

```