# Sysadmin Security Lab

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![Vagrant](https://img.shields.io/badge/Vagrant-Lab-orange)
![Security](https://img.shields.io/badge/Security-Research-red)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Lab-purple)
[![CI](https://github.com/solo2121/sysadmin-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/solo2121/sysadmin-security-lab/actions/workflows/ci.yml)

A modular hands-on lab for **system administration, cybersecurity, DevOps, and DevSecOps** practice.

This repository provides two independent lab environments and supporting tooling for enterprise infrastructure simulation, security research, automation, detection engineering, and professional skill development.

**Maintained by:** Miguel A. Carlo (solo2121) &nbsp;|&nbsp; **Status:** Active Development &nbsp;|&nbsp; **Last Updated:** 2026-06-28

---

## Overview

Sysadmin Security Lab is a modular lab environment for learning and practicing Linux administration, enterprise security, DevOps, and DevSecOps workflows. It is designed around isolated virtual lab environments so each system can be deployed independently and studied in a safe, repeatable way.

The repository is intended for hands-on learning, security research, attack simulation, defensive engineering, automation, and portfolio development. It combines infrastructure, tooling, documentation, and workflows in one place.

![Lab architecture overview](assets/architecture-overview.svg)

---

## Choose Your Lab

Use the lab that matches your goal:

- **Lab 1 — Active Directory Pentest Lab**: Windows enterprise security, AD CS, detection engineering, cloud simulation, and AI/LLM security testing.
- **Lab 2 — DevOps / DevSecOps Lab**: Kubernetes, GitOps, observability, infrastructure as code, runtime security, and policy enforcement.

Each lab is independent and can be deployed separately.

---

## Lab 1: Active Directory Pentest Lab

**Path:** `labs/security/ad-pentest/`  
**Alternate edition:** `labs/security/ad-pentest-vlan/`

This is a Windows-centric enterprise attack simulation lab for Active Directory security research, adversary emulation, detection engineering, cloud attack simulation, and AI/LLM security testing.

| Component | Details |
|---|---|
| Domain Controller | Windows Server 2022, `lab.local` |
| Certificate Authority | AD CS attack paths including ESC1, ESC3, ESC4, ESC7, and ESC9 |
| Member Servers | Exchange, SharePoint, SQL Server, Print Server |
| Workstations | Windows 10 domain-joined systems |
| Attacker Platform | Kali Linux |
| LLM Security Platform | Prompt injection, prompt exfiltration, jailbreak testing, RAG poisoning, token abuse, and AI security research |
| Cloud Simulation | LocalStack for AWS-style services such as S3, IAM, and EC2 |
| Legacy Targets | Metasploitable2 and OWASP Juice Shop |

The lab supports AD and post-exploitation research, cloud attack simulation, and defensive analysis workflows. The VLAN edition expands the environment into segmented subnets for more advanced network and attack-path research.

**Vagrantfile:** `labs/security/ad-pentest/Vagrantfile`  
**VLAN edition:** `labs/security/ad-pentest-vlan/Vagrantfile`

---

## Lab 2: DevOps / DevSecOps Lab

**Path:** `labs/infrastructure/devops-linux-lab/`

This is a Linux-centric cloud-native lab for Kubernetes operations, GitOps workflows, infrastructure automation, observability, and security engineering.

| Component | Details |
|---|---|
| Kubernetes | k3s cluster with control plane and 2 workers |
| Modern K8s Labs | Kind and K3d |
| Container Registry | Harbor with airgap image seeding |
| GitOps | Argo CD |
| Observability | Prometheus, Grafana, Loki, Promtail |
| Runtime Security | Falco |
| Policy Enforcement | Kyverno |
| TLS Automation | Cert-Manager |
| Infrastructure as Code | Terraform and OpenTofu |
| Configuration Management | Ansible |
| Linux Practice Nodes | Ubuntu 24.04, Rocky Linux 10, AlmaLinux 10, openSUSE Leap 15.6 |

This lab is designed for practicing modern platform engineering, cloud-native operations, and security automation in a reproducible environment.

**Vagrantfile:** `labs/infrastructure/devops-linux-lab/Vagrantfile`

---

## Repository Structure

```text
sysadmin-security-lab/
├── labs/
│   ├── infrastructure/
│   │   └── devops-linux-lab/
│   │       └── Vagrantfile
│   └── security/
│       ├── ad-pentest/
│       │   └── Vagrantfile
│       └── ad-pentest-vlan/
│           └── Vagrantfile
├── security/
│   ├── audit/
│   ├── exploitation/
│   ├── network/
│   ├── reconnaissance/
│   └── wireless/
├── sysadmin/
│   ├── automation/
│   ├── monitoring/
│   ├── system-hardening/
│   └── utilities/
├── docs/
│   ├── architecture/
│   ├── guides/
│   ├── workflows/
│   └── archive/reference/
├── assets/
├── requirements-dev.txt
├── CHANGELOG.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
└── LICENSE
```

---

## Requirements

Before deploying either lab, make sure your host system supports virtualization and has the required tools installed.

### Host prerequisites

- Linux host recommended.
- Hardware virtualization enabled in BIOS/UEFI.
- Sufficient CPU, RAM, and disk space for the lab you want to run.
- Network access for package installation and image downloads.

### Core tools

- Vagrant.
- KVM/QEMU.
- Libvirt.
- Virt-Manager.
- Required Vagrant plugins for the selected lab.

---

## Quick Start

### Lab 1: Active Directory Pentest Lab

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab/labs/security/ad-pentest

sudo apt update
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release

wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(grep -oP '(?<=UBUNTU_CODENAME=).*' /etc/os-release || lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list

sudo apt update
sudo apt install -y vagrant qemu-kvm libvirt-daemon-system virt-manager

vagrant plugin install vagrant-libvirt
vagrant plugin install vagrant-reload
vagrant plugin install vagrant-winrm

# Start the Domain Controller first
vagrant up dc01

# Verify status
vagrant status

# Deploy remaining systems
vagrant up
```

### Lab 2: DevOps / DevSecOps Lab

```bash
cd sysadmin-security-lab/labs/infrastructure/devops-linux-lab

sudo apt update
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release

wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(grep -oP '(?<=UBUNTU_CODENAME=).*' /etc/os-release || lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list

sudo apt update
sudo apt install -y vagrant qemu-kvm libvirt-daemon-system virt-manager

vagrant plugin install vagrant-libvirt

# Deploy the full lab
vagrant up
```

---

## Skills Demonstrated

| Area | Technologies |
|---|---|
| Linux Administration | Ubuntu, Rocky Linux, AlmaLinux, openSUSE |
| Virtualization | Vagrant, Libvirt, KVM |
| Active Directory | Windows Server 2022, Kerberos, LDAP, Group Policy |
| AD CS Security | ESC1–ESC9, certificate abuse |
| Cloud | AWS concepts, LocalStack |
| Containers | Docker, Harbor |
| Kubernetes | k3s, Kind, K3d, Argo CD |
| DevOps | Git, CI/CD, Ansible |
| Infrastructure as Code | Terraform, OpenTofu |
| DevSecOps | Falco, Kyverno, security automation |
| Monitoring | Prometheus, Grafana, Loki |
| Security Testing | Nmap, Metasploit, BloodHound, Hashcat |
| Detection Engineering | MITRE ATT&CK mapping, log analysis |
| AI Security | Prompt injection, prompt exfiltration, RAG security, LLM assessment |

---

## Documentation Hub

| Document | Description |
|---|---|
| [Portfolio Index](docs/PORTFOLIO.md) | Full lab index, techniques, and role-based skills mapping |
| [Architecture Design](docs/architecture/ARCHITECTURE.md) | Infrastructure design and system overview |
| [Security Scope](docs/architecture/SECURITY-SCOPE.md) | Security boundaries and rules of engagement |
| [Installation Guide](INSTALLATION.md) | Full host setup and dependency installation |
| [Setup with Examples](docs/SETUP-WITH-EXAMPLES.md) | Step-by-step setup examples and walkthroughs |
| [Troubleshooting](TROUBLESHOOTING.md) | Common issues and fixes |
| [Changelog](CHANGELOG.md) | Project history and version notes |

---

## Security and Ethics

This project is intended for educational, defensive security, and authorized research purposes only.

All testing must be performed only in environments that you own or are explicitly authorized to use. Unauthorized access, testing, or exploitation of systems without permission is illegal and strictly prohibited.

If you use any attack simulation or offensive tooling in this repository, make sure it stays inside your isolated lab and follows your own rules of engagement.

---

## Contributing

Contributions are welcome.

If you want to improve the project, please:
- Open an issue for bugs, documentation gaps, or feature ideas.
- Keep changes focused and well documented.
- Update relevant docs when behavior changes.
- Follow the repository’s code of conduct and security guidelines.

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 Miguel A. Carlo