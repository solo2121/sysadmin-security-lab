# Sysadmin Security Lab

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![Vagrant](https://img.shields.io/badge/Vagrant-Lab-orange)
[![CI](https://github.com/solo2121/sysadmin-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/solo2121/sysadmin-security-lab/actions/workflows/ci.yml)

**Sysadmin Security Lab is a modular, Vagrant-provisioned lab repository for practicing Active Directory security, network segmentation, Kubernetes / DevSecOps engineering, Linux administration, and infrastructure automation on a Linux host.**

This repository is designed to be runnable, not static. Every lab, workflow, and example here is implemented and deployable locally with Vagrant and KVM/libvirt — nothing is aspirational documentation.

**AD Pentest lab:** minimal subset ~24 GiB RAM, full 14-VM lab ~43.5 GiB RAM (64 GiB+ host recommended). **DevOps lab:** minimal profile ~10 GiB RAM, full profile ~26 GiB RAM. Deploy time not yet benchmarked — see [Technical questions](#technical-questions) below. Figures sourced from [`minimal-resource-deployment.md`](docs/optimization/minimal-resource-deployment.md).

**Maintained by:** Miguel A. Carlo (solo2121) · **Status:** Active development

<!--
  TODO: embed a 30–60s asciinema recording or GIF here showing
  `vagrant up` -> a completed Kerberoasting run, or the Grafana/Argo CD
  dashboard coming up for the DevOps lab. This is the single highest-value
  addition left — it's the difference between "documentation about tools"
  and visible proof the labs run. Suggested placement: directly below
  this comment, before the Labs table.
-->

---

## Contents

- [Labs](#labs)
- [Quick start](#quick-start)
- [Lab 1 details — AD Pentest](#lab-1-details--ad-pentest)
- [Lab 2 details — DevOps / DevSecOps](#lab-2-details--devops--devsecops)
- [Recent updates](#recent-updates)
- [Repository structure](#repository-structure)
- [Requirements](#requirements)
- [Skills demonstrated](#skills-demonstrated)
- [Documentation hub](#documentation-hub)
- [Security and ethics](#security-and-ethics)
- [Known limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)

---

## Labs

Three independent labs, each deployed with its own Vagrantfile on KVM/QEMU. Deploy one without affecting the others.

| Lab | Focus | Directory |
|---|---|---|
| **AD Pentest** | Active Directory attack paths: Kerberoasting, AS-REP roasting, AD CS abuse, NTLM relay, DCSync, ticket-based attacks. Includes cloud (LocalStack) and LLM security scenarios. See the [domain compromise walkthrough](docs/guides/security/domain-compromise-walkthrough.md). | `labs/security/ad-pentest/` |
| **AD Pentest — VLAN** | Same Active Directory lab, segmented into VLANs with controlled routing — for practicing lateral movement against network isolation boundaries. | `labs/security/ad-pentest-vlan/` |
| **DevOps / DevSecOps** | k3s, Argo CD (GitOps), Prometheus/Grafana/Loki, Falco (runtime security), Kyverno (policy), Terraform/OpenTofu, Ansible — platform engineering across Ubuntu, Rocky, AlmaLinux, and openSUSE nodes. | `labs/infrastructure/devops-linux-lab/` |

See [architecture.md](docs/architecture/architecture.md) for topology and networking, or [learning-path.md](docs/learning-path.md) for which lab to start with.

![Enterprise Infrastructure Architecture](assets/architecture-overview.png)

---

## Quick start

### 1. Clone the repository

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab
```

### 2. Install dependencies

Follow the [Installation Guide](docs/setup/installation.md) for host setup, Vagrant, libvirt, and required plugins. Run [`scripts/check-prerequisites.sh`](scripts/check-prerequisites.sh) first to confirm your host is ready.

### 3. Deploy AD Pentest lab

```bash
cd labs/security/ad-pentest
vagrant up dc01
vagrant up
```

### 4. Deploy AD Pentest — VLAN edition

```bash
cd labs/security/ad-pentest-vlan
vagrant up dc01
vagrant up
```

### 5. Deploy DevOps / DevSecOps lab

```bash
cd labs/infrastructure/devops-linux-lab
vagrant up
```

Resource-constrained host? See [minimal-resource-deployment.md](docs/optimization/minimal-resource-deployment.md) for the built-in `LAB_PROFILE` system (DevOps lab) and selective VM startup (AD Pentest lab).

---

## Lab 1 details — AD Pentest

**Directory:** `labs/security/ad-pentest/` · **VLAN edition:** `labs/security/ad-pentest-vlan/`

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

## Lab 2 details — DevOps / DevSecOps

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
- 64 GiB+ RAM for the full AD Pentest lab, 16–32 GiB for minimal profiles (see [minimal-resource-deployment.md](docs/optimization/minimal-resource-deployment.md)).
- Internet connectivity for package installation and box downloads.

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
- **Third-party Vagrant boxes.** Some boxes are community-maintained and may change outside this repository's control.
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

---

## Technical questions

- **Deploy time isn't documented anywhere in the repo**, so I didn't invent a number for the hero line (e.g., "~25 min") — that would be a fabricated claim. If you have a rough real-world time for `vagrant up` to finish on each lab (full and minimal profile), give me the numbers and I'll drop them into the hero line in place of the current placeholder text.
- The terminal recording/GIF is left as a `<!-- TODO -->` comment placeholder near the top, per your note that you'll capture that yourself.
