# Sysadmin Security Lab

![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![Vagrant](https://img.shields.io/badge/Vagrant-Lab-orange)
![Security](https://img.shields.io/badge/Security-Research-red)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Lab-purple)

A modular Sysadmin, Security, DevOps, and DevSecOps laboratory environment for building, testing, automating, and securing enterprise infrastructure.

This repository contains two independent lab environments and a collection of supporting security and sysadmin tooling — all designed for hands-on learning, enterprise infrastructure simulation, security research, certification preparation, and professional portfolio development.

**Maintained by:** Miguel A. Carlo (solo2121) &nbsp;|&nbsp; **Status:** Active Development &nbsp;|&nbsp; **Last Updated:** 2026-06-15

---

## Architecture Overview

The repository contains two fully independent environments that can be deployed separately and do not depend on each other.

### Active Directory Pentest Lab

- Enterprise Active Directory attack simulation
- AD CS exploitation and privilege escalation research
- Cloud attack simulation using LocalStack
- AI/LLM security testing and validation
- Detection engineering and security operations workflows

### DevOps / DevSecOps Lab

- Kubernetes platform engineering
- GitOps workflows and continuous delivery
- Infrastructure automation and configuration management
- Observability and monitoring engineering
- Runtime security and policy enforcement

---

## Two Independent Lab Environments

Each lab has its own Vagrantfile and is deployed separately. They do not share a network and do not depend on each other.

### Lab 1 — Active Directory Pentest Lab

**Path:** `labs/security/ad-pentest/` and `labs/security/ad-pentest-vlan/`

A Windows-centric enterprise attack simulation environment consisting of Windows, Linux, cloud, and security-focused systems. The lab is designed to support Active Directory security research, adversary emulation, detection engineering, cloud attack simulation, and AI/LLM security testing.

| What it runs | Details |
|---|---|
| Domain Controller | Windows Server 2022, `lab.local` |
| Certificate Authority | AD CS with ESC1–ESC9 attack paths |
| Member Servers | Exchange, SharePoint, SQL Server, Print Server |
| Workstations | Windows 10 domain-joined systems |
| Attacker Platform | Kali Linux |
| LLM Security Platform | Prompt injection, prompt exfiltration, jailbreak testing, RAG poisoning, token abuse, and AI security research |
| Cloud Simulation | LocalStack (AWS S3, IAM, EC2) |
| Legacy Targets | Metasploitable2, OWASP Juice Shop |

**Vagrantfile:** `labs/security/ad-pentest/Vagrantfile` (v1.6 Enterprise Edition)

**Network:** `172.28.128.0/24` isolated corporate network (or VLAN-segmented in the VLAN edition)

---

### Lab 2 — DevOps / DevSecOps Lab

**Path:** `labs/infrastructure/devops-linux-lab/`

A Linux-centric cloud-native lab with enterprise-grade tooling. Designed for Kubernetes operations, GitOps workflows, infrastructure as code, automation, observability, and security engineering.

| What it runs | Details |
|---|---|
| Kubernetes | k3s cluster (control plane + workers) |
| Container Registry | Harbor |
| GitOps | ArgoCD |
| Observability | Prometheus, Grafana, Loki |
| Runtime Security | Falco |
| Policy Enforcement | Kyverno |
| TLS Automation | Cert-Manager |
| Configuration Management | Ansible |
| Linux Practice Nodes | Ubuntu, Rocky Linux, AlmaLinux, openSUSE |

**Vagrantfile:** `labs/infrastructure/devops-linux-lab/Vagrantfile` (v7.0.0 Enterprise Release)

---

## Repository Structure

```
sysadmin-security-lab/
├── labs/
│   ├── infrastructure/
│   │   └── devops-linux-lab/       # Lab 2 — DevOps/DevSecOps (Kubernetes, ArgoCD, Harbor)
│   │       └── Vagrantfile         # Deploy independently
│   └── security/
│       ├── ad-pentest/             # Lab 1 — AD Pentest, flat network
│       │   └── Vagrantfile         # Deploy independently
│       └── ad-pentest-vlan/        # Lab 1 — AD Pentest, VLAN-segmented edition
│           └── Vagrantfile         # Deploy independently
├── security/
│   ├── audit/                      # LLM security scanner, validator, Cisco audit
│   ├── exploitation/               # SQL injection, hashcat assistant
│   ├── network/                    # Firewall scan, Scapy, tcpdump, Ettercap
│   ├── reconnaissance/             # Amass, nmap, port scanner
│   └── wireless/                   # Evil-twin and wireless lab tooling
├── sysadmin/
│   ├── automation/                 # Package management and update scripts
│   ├── monitoring/                 # Log analysis and system monitoring
│   ├── system-hardening/           # ClamAV, rootkit scanning, user audits
│   └── utilities/                  # UFW, BIND, Timeshift, Git management
├── docs/
│   ├── architecture/               # Architecture diagrams and security scope
│   ├── guides/                     # Infrastructure and security how-to guides
│   ├── workflows/                  # Lab deployment and operational workflows
│   └── archive/reference/          # Legacy reference documents
├── assets/                         # Repo banner and media
├── requirements-dev.txt            # Contributor Python dependencies
├── CHANGELOG.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
└── LICENSE
```

---

## Quick Start

### Lab 1 — AD Pentest Lab

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab/labs/security/ad-pentest

sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system virt-manager vagrant

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

### Lab 2 — DevOps / DevSecOps Lab

```bash
cd sysadmin-security-lab/labs/infrastructure/devops-linux-lab

sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system virt-manager vagrant

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
| AD CS Security | ESC1–ESC9, Certificate Abuse |
| Cloud | AWS Concepts, LocalStack |
| Containers | Docker, Harbor |
| Kubernetes | k3s, ArgoCD |
| DevOps | Git, CI/CD, Ansible |
| DevSecOps | Falco, Kyverno, Security Automation |
| Monitoring | Prometheus, Grafana, Loki |
| Security Testing | Nmap, Metasploit, BloodHound, Hashcat |
| Detection Engineering | MITRE ATT&CK Mapping, Log Analysis |
| AI Security | Prompt Injection, Prompt Exfiltration, RAG Security, LLM Assessment |

---

## Core Domains

| Domain | Lab |
|---|---|
| Active Directory Attack and Defense (Kerberos, AD CS, NTLM Relay) | Lab 1 |
| Cloud Attack Simulation (AWS IAM, S3, EC2 via LocalStack) | Lab 1 |
| AI / LLM Security (Prompt Injection, RAG Poisoning, Token Abuse) | Lab 1 |
| Kubernetes and Cloud-Native Operations (k3s, ArgoCD, Harbor) | Lab 2 |
| Infrastructure as Code (Vagrant, Ansible, Terraform) | Lab 2 |
| Security Monitoring and Observability (Prometheus, Grafana, Loki) | Lab 2 |
| Detection Engineering (MITRE ATT&CK Mapping, Log Analysis) | Both |
| Linux System Administration and Hardening | Both |

---

## Target Audience

This repository is intended for:

- System Administrators
- Security Engineers
- Penetration Testers
- Blue Team Analysts
- DevOps Engineers
- DevSecOps Engineers
- Cloud Engineers
- Students preparing for certifications and technical interviews

---

## Documentation Hub

| Document | Description |
|---|---|
| [Portfolio Index](docs/PORTFOLIO.md) | Full lab index, techniques, and certification map |
| [Architecture Design](docs/architecture/ARCHITECTURE.md) | Infrastructure design and system overview |
| [Security Scope](docs/architecture/SECURITY-SCOPE.md) | Security boundaries and rules of engagement |
| [Installation Guide](INSTALLATION.md) | Full host setup and dependency installation |
| [Troubleshooting](TROUBLESHOOTING.md) | Common issues and fixes |
| [Changelog](CHANGELOG.md) | Project history and version notes |

---

## Security & Ethics

This project is strictly for educational, defensive security, and authorized research purposes.

All testing must be performed only in environments that you own or are explicitly authorized to use. Unauthorized access, testing, or exploitation of systems without permission is illegal and strictly prohibited.

---

## License

[MIT License](https://github.com/solo2121/sysadmin-security-lab/blob/main/LICENSE)

Copyright (c) 2025 Miguel A. Carlo
