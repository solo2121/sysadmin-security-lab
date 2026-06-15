# Sysadmin Security Lab

A modular Sysadmin, Security, DevOps, and DevSecOps laboratory environment for building, testing, automating, and securing enterprise infrastructure.

This repository contains two independent lab environments and a collection of supporting security and sysadmin tooling — all designed for hands-on learning, certification practice, and portfolio development.

**Maintained by:** Miguel A. Carlo (solo2121) &nbsp;|&nbsp; **Status:** Active &nbsp;|&nbsp; **Last Updated:** 2026-06-15

---

## Two Independent Lab Environments

Each lab has its own Vagrantfile and is deployed separately. They do not share a network and do not depend on each other.

### Lab 1 — Active Directory Pentest Lab

**Path:** `labs/security/ad-pentest/` and `labs/security/ad-pentest-vlan/`

A Windows-centric enterprise attack simulation with 14 VMs. Covers the full offensive security stack: initial access, AD exploitation, lateral movement, privilege escalation, cloud attacks, and LLM security research.

| What it runs | Details |
|---|---|
| Domain Controller | Windows Server 2022, `lab.local` |
| Certificate Authority | AD CS with ESC1–ESC9 vulnerabilities |
| Member servers | Exchange, SharePoint, SQL Server, Print Server |
| Workstation | Windows 10 domain-joined |
| Attacker | Kali Linux |
| LLM platform | 15 vulnerable AI/LLM endpoints |
| Cloud simulation | LocalStack (AWS S3, IAM, EC2) |
| Legacy targets | Metasploitable2, OWASP Juice Shop |

**Vagrantfile:** `labs/security/ad-pentest/Vagrantfile` (v1.6 Enterprise Edition)
**Network:** `172.28.128.0/24` isolated corporate network (or VLAN-segmented in the VLAN edition)

---

### Lab 2 — DevOps / DevSecOps Lab

**Path:** `labs/infrastructure/devops-linux-lab/`

A Linux-centric cloud-native lab with enterprise-grade tooling. Covers Kubernetes operations, GitOps workflows, infrastructure as code, and observability engineering.

| What it runs | Details |
|---|---|
| Kubernetes | k3s cluster (control plane + workers) |
| Container registry | Harbor |
| GitOps | ArgoCD |
| Observability | Prometheus, Grafana, Loki |
| Runtime security | Falco |
| Policy enforcement | Kyverno |
| TLS automation | Cert-Manager |
| Configuration management | Ansible |
| Linux practice nodes | Ubuntu, Rocky, AlmaLinux, openSUSE |

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
└── SECURITY.md
```

---

## Quick Start

### Lab 1 — AD Pentest

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab/labs/security/ad-pentest

# Install dependencies (one time)
sudo apt update && sudo apt install -y qemu-kvm libvirt-daemon-system virt-manager vagrant
vagrant plugin install vagrant-libvirt vagrant-reload vagrant-winrm

# Always start the domain controller first
vagrant up dc01
vagrant status

# Then bring up the rest of the lab
vagrant up
```

### Lab 2 — DevOps / DevSecOps

```bash
cd sysadmin-security-lab/labs/infrastructure/devops-linux-lab

# Install dependencies (one time)
sudo apt update && sudo apt install -y qemu-kvm libvirt-daemon-system virt-manager vagrant
vagrant plugin install vagrant-libvirt

# Deploy the full lab
vagrant up
```

---

## Core Domains

| Domain | Lab |
|--------|-----|
| Active Directory attack and defense (Kerberos, AD CS, NTLM relay) | Lab 1 |
| Cloud attack simulation (AWS IAM, S3, EC2 via LocalStack) | Lab 1 |
| AI / LLM security (prompt injection, RAG poisoning, token bombing) | Lab 1 |
| Kubernetes and cloud-native operations (k3s, ArgoCD, Harbor) | Lab 2 |
| Infrastructure as Code (Vagrant, Ansible, Terraform) | Lab 2 |
| Security monitoring and observability (Prometheus, Grafana, Loki) | Lab 2 |
| Detection engineering (MITRE ATT&CK mapping, log analysis) | Both |
| Linux system administration and hardening | Both |

---

## Documentation Hub

| Document | Description |
|----------|-------------|
| [Portfolio Index](docs/PORTFOLIO.md) | Full lab index, techniques, and certification map |
| [Architecture Design](docs/architecture/ARCHITECTURE.md) | Infrastructure design and system overview |
| [Security Scope](docs/architecture/SECURITY-SCOPE.md) | Security boundaries and rules of engagement |
| [Installation Guide](INSTALLATION.md) | Full host setup and dependency installation |
| [Troubleshooting](TROUBLESHOOTING.md) | Common issues and fixes |
| [Changelog](CHANGELOG.md) | Project history and version notes |

---

## Security & Ethics

This project is strictly for educational and authorized security research purposes. All testing must be performed only in environments you own or are explicitly authorized to use. Unauthorized access or testing against real systems is illegal and strictly prohibited.

---

## License

[MIT License](LICENSE) — Author: Miguel A. Carlo
