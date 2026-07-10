# Sysadmin Security Lab

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![Vagrant](https://img.shields.io/badge/Vagrant-Lab-orange)
![Security](https://img.shields.io/badge/Security-Research-red)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Lab-purple)
[![CI](https://github.com/solo2121/sysadmin-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/solo2121/sysadmin-security-lab/actions/workflows/ci.yml)

A modular, enterprise-grade homelab for hands-on practice in Linux administration, Active Directory security, DevOps, and DevSecOps.

This repository provides two independent enterprise lab environments, along with supporting tooling for infrastructure simulation, security research, automation, detection engineering, and professional portfolio development.

**Maintained by:** Miguel A. Carlo (solo2121)  
**Project Status:** Active Development

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Overview](#overview)
- [Highlights](#highlights)
- [Who This Project Is For](#who-this-project-is-for)
- [Portfolio Goals](#portfolio-goals)
- [Choose Your Lab](#choose-your-lab)
- [Lab 1 – Active Directory Pentest Lab](#lab-1--active-directory-pentest-lab)
- [Lab 2 – DevOps / DevSecOps Lab](#lab-2--devops--devsecops-lab)
- [Repository Structure](#repository-structure)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Skills Demonstrated](#skills-demonstrated)
- [Documentation Hub](#documentation-hub)
- [Security and Ethics](#security-and-ethics)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)

---

## Architecture Overview

![Enterprise Infrastructure Architecture](assets/architecture-overview.png)

### Two Independent Lab Environments

- **Lab 1 – Active Directory Pentest Lab** (`172.28.128.0/24`)  
  A Windows enterprise security environment with domain controllers, member servers, cloud simulation, and AI security testing.

- **Lab 2 – DevOps / DevSecOps Lab**  
  A Linux-centric Kubernetes platform with a k3s control plane, worker nodes, container registry, observability stack, and runtime security.

Each lab deploys independently using its own Vagrantfile on KVM/QEMU virtualization infrastructure. See [Architecture Documentation](docs/architecture/architecture.md) for detailed infrastructure design and networking specifications.

---

## Overview

Sysadmin Security Lab is a modular enterprise homelab built for learning and practicing Linux administration, Active Directory security, cloud-native infrastructure, DevOps, and DevSecOps.

The project is organized into independent lab environments that can be deployed separately, allowing focused practice without impacting others.

It combines enterprise infrastructure, offensive security, defensive engineering, cloud-native technologies, automation, Infrastructure as Code, and modern DevSecOps workflows into a single learning platform.

---

## Highlights

- **14-host Active Directory range** with a complete, scripted attack chain from zero credentials to Domain Admin — Kerberoasting, AS-REP roasting, five AD CS escalation paths (ESC1/4/7/8/9), NTLM relay, DCSync, and Golden/Silver tickets. [See the full walkthrough →](docs/guides/security/domain-compromise-walkthrough.md)
- **DevSecOps platform** on Kubernetes (Kind/K3d) with GitOps, OpenTofu/Terraform, Falco, and Kyverno — including a deliberately backdoored container build and a leaked-secret Terraform state file for hands-on IaC security practice.
- **22 automated tests** (pytest + bats) and a GitHub Actions CI pipeline running shellcheck, flake8, and secret scanning on every push.
- **AI/LLM security testing** against a live LLM endpoint — prompt injection, RAG poisoning, function-call injection, token bombing, and embedding inversion.
- **Cloud attack simulation** against LocalStack: public S3 buckets, EC2 metadata SSRF, and IAM privilege escalation.
- Every lab is independently versioned with its own semver and changelog, and documented down to the credential and IP address of every host.

---

## Who This Project Is For

This repository is intended for:

- Linux system administrators.
- Security engineers.
- Penetration testers.
- DevOps engineers.
- DevSecOps engineers.
- Platform engineers.
- Students building enterprise homelabs.
- Professionals learning modern infrastructure and security engineering.

---

## Portfolio Goals

This repository demonstrates practical experience with:

- Linux system administration.
- Enterprise Active Directory.
- Infrastructure automation.
- DevOps and GitOps workflows.
- DevSecOps engineering.
- Detection engineering.
- Kubernetes administration.
- Infrastructure as Code.
- Security research in isolated lab environments.

---

## Choose Your Lab

Choose the lab that matches your learning objectives.

- **Lab 1** if you want to focus on Windows, Active Directory, and offensive security.
- **Lab 2** if you want to focus on Kubernetes, automation, and DevSecOps.

### Lab 1 – Active Directory Pentest Lab

Focus areas:

- Windows enterprise infrastructure.
- Active Directory.
- AD Certificate Services (AD CS).
- Detection engineering.
- Cloud attack simulation.
- AI and LLM security testing.

### Lab 2 – DevOps / DevSecOps Lab

Focus areas:

- Kubernetes.
- GitOps.
- Infrastructure as Code.
- Observability.
- Runtime security.
- Policy enforcement.
- Platform engineering.

Each lab is independent and can be deployed separately.

---

## Lab 1 – Active Directory Pentest Lab

**Directory:** `labs/security/ad-pentest/`  
**Alternative VLAN deployment:** `labs/security/ad-pentest-vlan/`

This Windows enterprise lab is designed for Active Directory security research, adversary emulation, post-exploitation analysis, detection engineering, cloud attack simulation, and AI/LLM security testing.

| Component | Description |
|---|---|
| Domain Controller | Windows Server 2022 (`lab.local`) |
| Certificate Authority | AD CS (ESC1, ESC3, ESC4, ESC7, ESC8, ESC9) |
| Member Servers | Exchange, SQL Server, SharePoint, Print Server |
| Workstations | Windows 10 domain joined |
| Attacker VM | Kali Linux |
| Cloud Simulation | LocalStack (AWS services) |
| AI Security | Prompt injection, prompt leakage, jailbreaks, token abuse, RAG security |
| Legacy Targets | Metasploitable2, OWASP Juice Shop |

The VLAN edition expands the environment into segmented enterprise networks for advanced attack path and lateral movement simulations.

---

## Lab 2 – DevOps / DevSecOps Lab

**Directory:** `labs/infrastructure/devops-linux-lab/`

This Linux-centric, cloud-native platform engineering environment focuses on Kubernetes operations, infrastructure automation, GitOps, observability, and security engineering.

| Component | Description |
|---|---|
| Kubernetes | k3s cluster |
| Additional Clusters | Kind, K3d |
| GitOps | Argo CD |
| Registry | Harbor |
| Monitoring | Prometheus |
| Dashboards | Grafana |
| Logging | Loki + Promtail |
| Runtime Security | Falco |
| Policy Engine | Kyverno |
| Certificate Management | Cert-Manager |
| Infrastructure as Code | Terraform, OpenTofu |
| Configuration Management | Ansible |
| Linux Nodes | Ubuntu, Rocky Linux, AlmaLinux, openSUSE |

This environment provides practical experience in cloud-native operations, automation, DevSecOps, and platform engineering.

---

## Recent Updates

- **DevSecOps Lab:** Expanded with realistic attack scenarios and vulnerable deployments, added a Terraform state file containing exposed secrets for IaC practice, and introduced an indirect prompt injection (RAG) scenario for AI security.
- **Active Directory Lab:** Added modern enterprise attack scenarios, fixed the CA01 DNS record configuration to support privilege escalation paths, and resolved Vagrantfile validation issues.

---

## Repository Structure

```text
sysadmin-security-lab/
├── .github/
│   └── workflows/
├── assets/
├── docs/
│   ├── architecture/
│   ├── guides/
│   ├── workflows/
│   └── archive/reference/
├── labs/
│   ├── infrastructure/
│   │   └── devops-linux-lab/
│   └── security/
│       ├── ad-pentest/
│       └── ad-pentest-vlan/
├── scripts/
├── security/
├── sysadmin/
├── tests/
├── CHANGELOG.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── installation.md
├── LICENSE
├── SECURITY.md
├── troubleshooting.md
└── README.md
```

---

## Requirements

Before deploying either lab, ensure the following:

### Host Requirements

- Linux host required.
- Hardware virtualization enabled.
- KVM/QEMU.
- Libvirt.
- Vagrant.
- Virt-Manager.
- Sufficient CPU, RAM, and storage.
- Internet connectivity.

---

## Quick Start

### Clone the repository

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab
```

### Install dependencies

Install the required dependencies by following the [Installation Guide](installation.md).

### Deploy Active Directory Lab

```bash
cd labs/security/ad-pentest
vagrant up dc01
vagrant up
```

### Deploy DevOps / DevSecOps Lab

```bash
cd labs/infrastructure/devops-linux-lab
vagrant up
```

---

## Skills Demonstrated

| Area | Technologies |
|---|---|
| Linux Administration | Ubuntu, Rocky Linux, AlmaLinux, openSUSE |
| Virtualization | KVM, Libvirt, Vagrant |
| Infrastructure as Code | Terraform, OpenTofu, Ansible |
| DevOps | Git, CI/CD, Release Workflows |
| Kubernetes | k3s, Kind, K3d |
| GitOps | Argo CD |
| Monitoring | Prometheus, Grafana, Loki |
| DevSecOps | Falco, Kyverno |
| Containers | Docker, Harbor |
| Cloud | AWS Concepts, LocalStack |
| Active Directory | Windows Server, Kerberos, LDAP |
| AD CS | ESC1, ESC3, ESC4, ESC7, ESC8, ESC9 |
| Detection Engineering | MITRE ATT&CK, Log Analysis |
| Security Testing | Nmap, BloodHound, Metasploit, Hashcat |
| AI Security | Prompt Injection, Prompt Leakage, Jailbreak Testing, RAG Security |

---

## Documentation Hub

| Document | Purpose |
|---|---|
| [domain-compromise-walkthrough.md](docs/guides/security/domain-compromise-walkthrough.md) | Full attack chain: zero credentials to Domain Admin |
| [docs/README.md](docs/README.md) | Full documentation index |
| [PORTFOLIO.md](docs/portfolio.md) | Portfolio index and skills mapping |
| [architecture.md](docs/architecture/architecture.md) | Infrastructure design |
| [security-scope.md](docs/architecture/security-scope.md) | Security boundaries |
| [installation.md](installation.md) | Full installation guide |
| [setup-with-examples.md](docs/setup-with-examples.md) | Deployment walkthrough |
| [check-prerequisites.sh](scripts/check-prerequisites.sh) | Validate your host before deploying |
| [minimal-resource-deployment.md](docs/optimization/minimal-resource-deployment.md) | Running either lab on smaller hosts |
| [TROUBLESHOOTING.md](troubleshooting.md) | Common issues |
| [ROADMAP.md](ROADMAP.md) | Planned improvements |
| [CHANGELOG.md](CHANGELOG.md) | Project history |

---

## Security and Ethics

This project is intended solely for education, authorized security research, and defensive security practice.

Only perform testing against systems you own or where you have explicit authorization.

Unauthorized access, testing, or exploitation of external systems is strictly prohibited.

---

## Known Limitations

The following limitations currently apply:

- **Hardware ceiling.** The full Active Directory lab needs 32GB+ RAM and 200GB+ storage. It is not designed for laptops or shared/low-resource hosts. See [minimal-resource-deployment.md](docs/optimization/minimal-resource-deployment.md) for running a smaller subset.
- **Linux hosts only.** Both labs depend on KVM/libvirt and are not supported on macOS or native Windows.
- **Windows evaluation licensing.** The Windows Server and Windows 10 VMs run on Microsoft's free evaluation media, which is time-limited (commonly 180 days) and not licensed for production use.
- **Some AD lab hosts are simulated, not full installs.** `db01`, `exch01`, and `sp01` are domain-joined Windows Server 2022 hosts with product-like config files and credentials for post-exploitation practice — they do not run real SQL Server, Exchange, or SharePoint. Product-specific remote exploits (e.g. ProxyShell, ProxyLogon) will not work against them.
- **Third-party Vagrant boxes.** Several boxes (`peru/*`, `deargle/metasploitable2`, `generic/*`) are community-maintained, not published by this project. Availability, updates, and box versions are outside this repo's control and can occasionally break a build.
- **No blue-team/detection tooling included yet.** This is currently a red-team/offensive lab. SIEM or EDR integration to validate whether attacks are actually detected is not implemented — see [ROADMAP.md](ROADMAP.md).
- **CI checks code, not the lab itself.** GitHub Actions validates all three Vagrantfiles (`vagrant validate`), blocks on real shellcheck errors, and runs flake8/bandit/doc-link-check informationally. It does not run `vagrant up` end-to-end, so a green CI run does not guarantee every VM provisions cleanly on every host. Secret scanning (`detect-secrets`) runs via local pre-commit hooks, not in CI — run `pre-commit run --all-files` before pushing if you haven't installed the hooks.
- **Single-host design.** Both labs assume everything runs on one physical machine via libvirt. There is no multi-host or distributed deployment support.

---

## Contributing

Contributions are welcome and encouraged.

- Open an issue before major changes.
- Keep pull requests focused.
- Update documentation when needed.
- Follow project contribution guidelines.

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## License

This project is licensed under the MIT License.

See [LICENSE](LICENSE) for details.

Copyright (c) 2023–2026 Miguel A. Carlo