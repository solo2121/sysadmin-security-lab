# Sysadmin Security Lab

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![Vagrant](https://img.shields.io/badge/Vagrant-Lab-orange)
![Security](https://img.shields.io/badge/Security-Research-red)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Lab-purple)
[![CI](https://github.com/solo2121/sysadmin-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/solo2121/sysadmin-security-lab/actions/workflows/ci.yml)

**Sysadmin Security Lab is a modular, Vagrant-provisioned lab repository for practicing Active Directory security, network segmentation, Kubernetes / DevSecOps engineering, Linux administration, and infrastructure automation on a Linux host.**

This repository is designed to be runnable, not static. The lab environments, workflows, and examples are implemented in the repository and can be deployed locally with Vagrant and KVM/libvirt.

**Maintained by:** Miguel A. Carlo (solo2121)  
**Project status:** Active development

---

## What this demonstrates

| Domain | What it demonstrates | Where |
|---|---|---|
| Active Directory security | Domain provisioning, Windows lab administration, AD CS, credential attack paths, and post-exploitation workflows | `labs/security/ad-pentest/` |
| Network segmentation | VLAN-based lab design, routing boundaries, and lateral movement constraints | `labs/security/ad-pentest-vlan/` |
| DevOps / DevSecOps | Kubernetes operations, GitOps, observability, policy enforcement, and infrastructure automation | `labs/infrastructure/devops-linux-lab/` |
| Infrastructure as Code | Vagrant, Ansible, and supporting automation for reproducible lab deployment | Repo-wide |
| Security documentation | Architecture, scope, setup, troubleshooting, and workflow documentation | `docs/` and root-level guides |

---

## Architecture overview

![Enterprise Infrastructure Architecture](assets/architecture-overview.png)

### Independent lab environments

- **Lab 1 – Active Directory Pentest Lab** (`labs/security/ad-pentest/`)
  A Windows enterprise security lab for Active Directory research, adversary emulation, post-exploitation analysis, and cloud-related security scenarios.

- **Lab 2 – Active Directory Pentest Lab, VLAN edition** (`labs/security/ad-pentest-vlan/`)
  A segmented version of the Active Directory lab with VLAN boundaries and controlled routing for network-focused testing.

- **Lab 3 – DevOps / DevSecOps Lab** (`labs/infrastructure/devops-linux-lab/`)
  A Linux-centric platform engineering lab focused on Kubernetes, GitOps, observability, runtime security, policy enforcement, and automation.

Each lab deploys independently using its own Vagrantfile on KVM/QEMU virtualization infrastructure. See the [architecture documentation](docs/architecture/architecture.md) for the detailed design, topology, and networking model.

---

## Overview

Sysadmin Security Lab is a modular enterprise homelab for Linux administration, Active Directory security, cloud-native infrastructure, DevOps, and DevSecOps.

The repository is organized into independent lab environments that can be deployed separately, which makes it easier to focus on one domain at a time without affecting the others.

It combines enterprise infrastructure, offensive security practice, defensive engineering concepts, cloud-native technologies, automation, Infrastructure as Code, and modern DevSecOps workflows in a single learning platform.

---

## Highlights

- **Active Directory lab coverage** with a scripted path through common identity and privilege-escalation topics, including Kerberoasting, AS-REP roasting, AD CS abuse, NTLM relay, DCSync, and ticket-based attacks. See the [domain compromise walkthrough](docs/guides/security/domain-compromise-walkthrough.md).
- **VLAN-segmented enterprise lab** for practicing routing boundaries, lateral movement constraints, and segmentation-aware attack paths.
- **DevSecOps platform** with Kubernetes, GitOps, observability, runtime security, and policy enforcement tooling.
- **Automated validation and CI** with repository checks, shell linting, Python linting, and secret scanning support.
- **AI and cloud security practice** through controlled lab scenarios that include cloud-style services and LLM-related testing environments.
- **Reproducible deployment** using Vagrant and supporting automation so the same lab can be rebuilt consistently.

---

## Who this project is for

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

## Portfolio goals

This repository demonstrates practical experience with:

- Linux system administration.
- Enterprise Active Directory.
- Infrastructure automation.
- DevOps and GitOps workflows.
- DevSecOps engineering.
- Detection engineering concepts.
- Kubernetes administration.
- Infrastructure as Code.
- Security research in isolated lab environments.

---

## Choose your lab

Choose the lab that best matches your learning goals.

- **Lab 1** if you want to focus on Windows, Active Directory, and offensive security.
- **Lab 1b** if you want to focus on Windows, Active Directory, and VLAN segmentation.
- **Lab 2** if you want to focus on Kubernetes, automation, and DevSecOps.

### Lab 1 – Active Directory Pentest Lab

Focus areas:

- Windows enterprise infrastructure.
- Active Directory.
- AD Certificate Services (AD CS).
- Detection engineering concepts.
- Cloud-related security scenarios.

### Lab 1b – Active Directory Pentest Lab, VLAN edition

Focus areas:

- Windows enterprise infrastructure.
- Active Directory with VLAN segmentation.
- Controlled routing and lateral movement constraints.
- Detection engineering concepts.
- Network isolation and enterprise boundary design.

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

## Lab 1 details

**Directory:** `labs/security/ad-pentest/`  
**Alternative VLAN deployment:** `labs/security/ad-pentest-vlan/`

This Windows enterprise lab is designed for Active Directory security research, adversary emulation, post-exploitation analysis, and controlled security testing.

| Component | Description |
|---|---|
| Domain Controller | Windows Server 2022 (`lab.local`) |
| Certificate Authority | AD CS |
| Member Servers | Windows server hosts used for enterprise lab scenarios |
| Workstations | Windows 10 domain-joined clients |
| Attacker VM | Kali Linux |
| Cloud simulation | LocalStack (AWS services) |
| AI security | Prompt injection, prompt leakage, jailbreak testing, token abuse, and RAG security |
| Legacy targets | Metasploitable2, OWASP Juice Shop |

The VLAN edition expands the environment into segmented enterprise networks for advanced attack-path and lateral-movement testing.

---

## Lab 2 details

**Directory:** `labs/infrastructure/devops-linux-lab/`

This Linux-centric, cloud-native environment focuses on Kubernetes operations, infrastructure automation, GitOps, observability, and security engineering.

| Component | Description |
|---|---|
| Kubernetes | k3s cluster |
| Additional cluster tools | Kind, K3d |
| GitOps | Argo CD |
| Registry | Harbor |
| Monitoring | Prometheus |
| Dashboards | Grafana |
| Logging | Loki and Promtail |
| Runtime security | Falco |
| Policy engine | Kyverno |
| Certificate management | cert-manager |
| Infrastructure as Code | Terraform, OpenTofu |
| Configuration management | Ansible |
| Linux nodes | Ubuntu, Rocky Linux, AlmaLinux, openSUSE |

This environment provides practical experience in cloud-native operations, automation, DevSecOps, and platform engineering.

---

## Recent updates

- **Documentation accuracy pass:** Added verified network topology diagrams for the lab environments, corrected AD CS documentation to match the implemented lab design, and reduced drift between Vagrantfiles and written documentation.
- **DevSecOps lab:** Expanded with realistic infrastructure and security scenarios for hands-on practice with automation, observability, and policy enforcement.
- **Active Directory lab:** Improved domain lab coverage, corrected directory references, and aligned written guidance with the current repository state.

---

## Repository structure

`labs/` contains the deployable lab environments. `docs/` contains the primary documentation set, and the root-level guides provide quick entry points for installation, troubleshooting, and project navigation.

```text
sysadmin-security-lab/
├── .github/
│   └── workflows/
├── assets/
├── docs/
│   ├── architecture/
│   ├── guides/
│   ├── workflows/
│   └── archive/
├── labs/
│   ├── infrastructure/
│   │   └── devops-linux-lab/
│   └── security/
│       ├── ad-pentest/
│       └── ad-pentest-vlan/
├── scripts/
├── tools/
│   ├── security/
│   └── sysadmin/
├── tests/
├── CHANGELOG.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── LICENSE
├── SECURITY.md
└── README.md
```

---

## Requirements

Before deploying any lab, make sure the host meets the following requirements:

- Linux host required.
- Hardware virtualization enabled.
- KVM/QEMU installed.
- libvirt installed and running.
- Vagrant installed.
- virt-manager installed.
- Sufficient CPU, RAM, and storage.
- Internet connectivity for package installation and box downloads.

---

## Quick start

### 1. Clone the repository

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab
```

### 2. Install dependencies

Follow the [Installation Guide](docs/setup/installation.md) for host setup, Vagrant, libvirt, and required plugins.

### 3. Deploy Lab 1

```bash
cd labs/security/ad-pentest
vagrant up dc01
vagrant up
```

### 4. Deploy Lab 1b

```bash
cd labs/security/ad-pentest-vlan
vagrant up dc01
vagrant up
```

### 5. Deploy Lab 2

```bash
cd labs/infrastructure/devops-linux-lab
vagrant up
```

---

## Skills demonstrated

| Area | Technologies |
|---|---|
| Linux administration | Ubuntu, Rocky Linux, AlmaLinux, openSUSE |
| Virtualization | KVM, libvirt, Vagrant |
| Infrastructure as Code | Terraform, OpenTofu, Ansible |
| DevOps | Git, CI/CD, release workflows |
| Kubernetes | k3s, Kind, K3d |
| GitOps | Argo CD |
| Monitoring | Prometheus, Grafana, Loki |
| DevSecOps | Falco, Kyverno |
| Containers | Docker, Harbor |
| Cloud | AWS concepts, LocalStack |
| Active Directory | Windows Server, Kerberos, LDAP |
| AD CS | Certificate services and escalation scenarios |
| Detection engineering | MITRE ATT&CK, log analysis |
| Security testing | Nmap, BloodHound, Metasploit, Hashcat |
| AI security | Prompt injection, prompt leakage, jailbreak testing, RAG security |

---

## Documentation hub

| Document | Purpose |
|---|---|
| [learning-path.md](docs/learning-path.md) | Start here: which lab to try first and in what order |
| [domain-compromise-walkthrough.md](docs/guides/security/domain-compromise-walkthrough.md) | Full attack-chain walkthrough |
| [docs/README.md](docs/README.md) | Documentation index |
| [portfolio.md](docs/portfolio.md) | Portfolio index and skills mapping |
| [architecture.md](docs/architecture/architecture.md) | Infrastructure design |
| [threat-model.md](docs/architecture/threat-model.md) | Assets, trust boundaries, and attacker assumptions |
| [security-scope.md](docs/architecture/security-scope.md) | Security boundaries |
| [installation.md](docs/setup/installation.md) | Host installation and setup |
| [setup-with-examples.md](docs/setup-with-examples.md) | Deployment walkthrough |
| [check-prerequisites.sh](scripts/check-prerequisites.sh) | Host validation before deployment |
| [minimal-resource-deployment.md](docs/optimization/minimal-resource-deployment.md) | Reduced-resource lab profiles |
| [troubleshooting.md](docs/setup/troubleshooting.md) | Common issues and fixes |
| [roadmap.md](docs/roadmap.md) | Planned improvements |
| [CHANGELOG.md](CHANGELOG.md) | Project history |

---

## Security and ethics

This project is intended only for education, authorized security research, and defensive security practice.

Only perform testing against systems you own or where you have explicit authorization.

Unauthorized access, testing, or exploitation of external systems is strictly prohibited.

---

## Known limitations

- **Hardware requirements.** The full Active Directory lab requires substantial RAM and storage. It is not designed for low-resource laptops. See [minimal-resource-deployment.md](docs/optimization/minimal-resource-deployment.md) for smaller lab profiles.
- **Linux hosts only.** The labs depend on KVM/libvirt and are not supported on macOS or native Windows.
- **Windows evaluation licensing.** The Windows Server and Windows client VMs use Microsoft evaluation media, which is time-limited and not licensed for production use.
- **Some lab hosts are simulated.** A few Windows server roles are represented by lab-safe configurations for security practice rather than production software installations.
- **Third-party Vagrant boxes.** Some boxes are community-maintained and may change outside this repository’s control.
- **Offensive lab focus.** This repository currently emphasizes red-team and offensive security practice; blue-team validation tooling is not the primary focus.
- **CI scope.** CI validates repository files and configuration, but it does not perform full end-to-end provisioning on every run.
- **Single-host design.** The labs are designed to run on one physical machine through libvirt.

---

## Contributing

Contributions are welcome.

- Open an issue before making major changes.
- Keep pull requests focused.
- Update documentation when needed.
- Follow the contribution guidelines.

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

Copyright © 2023–2026 Miguel A. Carlo