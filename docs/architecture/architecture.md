# Repository Architecture

## Purpose

Sysadmin Security Lab is organized as a modular DevSecOps and security-learning platform. The repository separates runnable labs, reusable tools, operational scripts, and long-form documentation so each part can be reviewed or improved independently.

The project is intentionally local-first: labs are designed for Vagrant, KVM/QEMU, and libvirt rather than public cloud infrastructure. This keeps security testing contained and makes the environments repeatable on a workstation.

---

## Design Principles

1. **Reproducible labs:** Lab environments should be deployable from documented Vagrantfiles and scripts.
2. **Clear safety boundaries:** Offensive content belongs in isolated lab contexts with explicit authorization guidance.
3. **Separation of concerns:** Labs, standalone security tools, sysadmin utilities, and guides live in distinct directories.
4. **Documentation with examples:** Setup, architecture, workflows, and troubleshooting are documented near the code they support.
5. **Portfolio readability:** A reviewer should be able to identify the purpose, skills demonstrated, and runnable entry points quickly.

---

## Current Structure

```text
sysadmin-security-lab/
├── assets/
│   ├── README.md
│   └── sysadmin-security-lab-banner.png
├── docs/
│   ├── architecture.md
│   ├── LAB-DEPLOYMENT-WORKFLOW.md
│   ├── security-scope.md
│   ├── SETUP-WITH-EXAMPLES.md
│   ├── WORKFLOWS.md
│   └── guides/
├── labs/
│   ├── infrastructure/
│   │   └── devops-linux-lab/
│   └── security/
│       ├── ad-pentest/
│       └── ad-pentest-vlan/
├── security/
│   ├── detection-engineering/
│   ├── network-security-analysis/
│   ├── security-testing-lab/
│   ├── threat-reconnaissance/
│   └── wireless-security-lab/
├── sysadmin/
│   ├── automation/
│   ├── git/
│   ├── monitoring/
│   ├── system-hardening/
│   └── utilities/
├── CHANGELOG.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── INSTALLATION.md
├── LICENSE
├── README.md
├── SECURITY.md
└── TROUBLESHOOTING.md
```

---

## Main Components

### `labs/`

Runnable environments for infrastructure and security practice.

| Lab | Focus |
|-----|-------|
| `labs/infrastructure/devops-linux-lab/` | Linux administration, Vagrant/libvirt, Kubernetes, DevOps workflow documentation |
| `labs/security/ad-pentest/` | Active Directory attack-chain practice in a controlled lab |
| `labs/security/ad-pentest-vlan/` | VLAN segmentation, subnet design, and network isolation testing |

Expected lab contents:

- `Vagrantfile` for VM definition and provisioning
- `README.md` for setup and usage
- `scripts/` for repeatable operations
- `docs/` for architecture, workflow, credentials, or troubleshooting notes
- `configs/` for lab-specific configuration when needed

### `security/`

Standalone security utilities and experiments.

| Directory | Purpose |
|-----------|---------|
| `detection-engineering/` | LLM/security validation and audit tooling |
| `network-security-analysis/` | Packet capture, firewall scanning, and network analysis helpers |
| `security-testing-lab/` | Web/security testing scripts and educational exploit tooling |
| `threat-reconnaissance/` | Reconnaissance and scanning helpers |
| `wireless-security-lab/` | Wireless security lab experiments |

### `sysadmin/`

Linux administration and day-2 operations scripts.

| Directory | Purpose |
|-----------|---------|
| `automation/` | Update, package maintenance, and platform automation scripts |
| `git/` | Git workflow helper scripts |
| `monitoring/` | System, security, and log monitoring utilities |
| `system-hardening/` | Audit, hardening, antivirus, rootkit, user, and network checks |
| `utilities/` | General Linux utilities for backups, firewall, memory, DNS, and media tasks |

### `docs/`

Project-level documentation for architecture, safe use, setup, and workflows. Longer tutorials and reference guides live under `docs/guides/`.

---

## Safety Model

The repository contains intentionally vulnerable configurations, weak lab credentials, and offensive security workflows. These are acceptable only because they are scoped to isolated labs.

Required controls:

- Run labs only on networks you own or control.
- Keep lab networks isolated from production and employer systems.
- Do not bridge intentionally vulnerable systems onto public networks.
- Treat credentials in lab documentation as throwaway training material.
- Review [`security-scope.md`](security-scope.md) before running offensive scenarios.

---

## Quality Standards

New labs should include:

- Clear prerequisites and resource requirements
- One primary setup path
- A validation command such as `vagrant validate`, `vagrant status`, or a lab-specific test script
- Expected outputs or success criteria
- Cleanup instructions
- Security scope and isolation notes

New scripts should include:

- A short usage description
- Safe defaults
- Input validation where practical
- Clear error messages
- Minimal required privileges

---

## Roadmap

| Phase | Goal |
|-------|------|
| Consolidation | Keep repository structure and documentation aligned with the actual tree |
| Validation | Add CI checks for shell, Python, Markdown, and Vagrant configuration |
| Lab UX | Add a common lab launcher or management wrapper |
| Evidence | Add screenshots, diagrams, and expected-output captures for each featured lab |
| Standardization | Add lab metadata files for resources, dependencies, safety level, and validation commands |

---

## Related Documents

- [`../../README.md`](../../README.md)
- [`security-scope.md`](security-scope.md)
- [`../workflows/workflows.md`](../workflows/workflows.md)
- [`../setup-with-examples.md`](../setup-with-examples.md)
- [`../../installation.md`](../../installation.md)
- [`../../troubleshooting.md`](../../troubleshooting.md)
