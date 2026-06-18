# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- GitHub Actions CI/CD pipeline
- Pre-commit hook automation
- Additional AD CS attack scenarios
- Ansible role automation for DevOps lab

---

## [2.1.1] - 2026-06-18 — AD Pentest VLAN Lab

### Added
- ZeroLogon (CVE-2020-1472) attack path
- PetitPotam (CVE-2021-36942) NTLM relay coercion
- NoPac (CVE-2021-42287) SAM account name spoofing
- Resource-Based Constrained Delegation (RBCD) misconfiguration
- Enhanced PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
- AD CS ESC9 — No Security Extension
- Shadow Credentials attack path
- Auto-generated attack cheatsheet on the Kali VM at `/root/attacks/README.txt`

---

## [1.8.0] - 2026-06-17 — AD Pentest Lab (Flat Network)

### Added
- NoPac (CVE-2021-42287) — SAM account name spoofing attack path
- Resource-Based Constrained Delegation (RBCD) misconfiguration
- AD CS ESC9 — No Security Extension certificate template
- LLMNR/NBNS poisoning enabled by default for Responder practice
- Additional Kerberoastable service accounts
- Automated plugin check and install for `vagrant-reload` and `vagrant-libvirt`

---

## [2.1.0] - 2026-06-16 — AD Pentest VLAN Lab

### Added
- Enterprise VLAN segmentation across 5 subnets (Management, Workstations, Servers, DMZ, Attacker)
- 14-VM enterprise topology with Windows Server 2022 DC, CA, Exchange, SharePoint, SQL Server, Print Server
- LocalStack AWS attack simulation (S3, IAM, EC2)
- 15 LLM security research endpoints (prompt injection, RAG poisoning, token abuse)
- OWASP Juice Shop and Metasploitable2 legacy targets
- VLAN setup and validation scripts (`setup-vlans.sh`, `test-vlans.sh`)
- Network architecture diagram (Mermaid)
- Vagrant plugin check with automatic install on first run

### Fixed
- DC readiness detection before domain join
- Worker node join sequencing
- Shell variable expansion in Python heredoc blocks

---

## [1.7.0] - 2026-06-15 — AD Pentest Lab (Flat Network)

### Added
- Windows Server 2022 Domain Controller with full AD CS (ESC1–ESC9 attack paths)
- Kali Linux attacker VM with automated tooling
- Dynamic domain DN construction from `DOMAIN_NAME` constant
- Memory warning banner at `vagrant up` time
- Plugin auto-install for `vagrant-reload` and `vagrant-libvirt`
- Service accounts, delegation paths, and intentional ACL misconfigurations
- `LAB_CREDENTIALS.md` with full account inventory
- `ATTACK_CHAIN.md` documenting ESC8 → NTLM relay → domain compromise path

### Fixed
- Improved DC provisioning reliability with retry logic
- Domain join sequencing with proper readiness checks

---

## [7.1.1] - 2026-06-16 — DevOps / DevSecOps Lab

### Fixed
- Python heredoc quoting to prevent shell variable expansion (`<<'PYEOF'`)
- Pass variables as environment variables into Python generation blocks
- registries.yaml generation syntax errors

---

## [7.1.0] - 2026-06-15 — DevOps / DevSecOps Lab

### Changed
- Use Python to generate `registries.yaml` for Harbor registry configuration

---

## [7.0.0] - 2026-05-29 — DevOps / DevSecOps Lab

### Added
- k3s Kubernetes cluster (control plane + 2 workers)
- Harbor container registry with airgap image seeding (40+ images)
- ArgoCD GitOps platform (v7.7.5)
- Prometheus + Grafana + Loki observability stack
- Falco runtime security
- Kyverno policy enforcement
- Cert-Manager TLS automation
- Terraform (v1.9.8) with bash completion
- Multi-profile deployment: `minimal`, `dev`, `full`
- Zero-cache Harbor mode (`CACHE_MODE=zero`)
- Dynamic libvirt network auto-detection
- Linux practice nodes: Ubuntu 24.04, Rocky Linux 10, AlmaLinux 10, openSUSE Leap 15.6
- Ansible management nodes
- Day-2 tools: k9s, kubectx, kubens, stern
- Idempotency markers for all provisioners (safe re-run)
- Per-tool installation markers for granular retry

---

## [1.0.0] - 2026-06-13 — Initial Public Release

### Added
- Repository structure with `labs/`, `security/`, `sysadmin/`, `docs/` layout
- Security tooling: audit, exploitation, network, reconnaissance, wireless
- Sysadmin scripts: automation, monitoring, system-hardening, utilities
- Documentation: architecture, guides, workflows, archive
- `requirements-dev.txt` for contributor Python dependencies
- MIT License, Code of Conduct, Security Policy, Contributing guidelines

---

## Versioning Policy

- **MAJOR** — Incompatible changes to lab architecture or workflow
- **MINOR** — New VMs, tools, or features added
- **PATCH** — Bug fixes, provisioning reliability improvements

---

## Reporting Changes

To report a bug, request a feature, or suggest improvements:

1. Check [GitHub Issues](https://github.com/solo2121/sysadmin-security-lab/issues)
2. If not already reported, create a new issue with reproduction steps and environment details

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing changes.

---

## License

[MIT License](https://github.com/solo2121/sysadmin-security-lab/blob/main/LICENSE)

Copyright (c) 2025 Miguel A. Carlo
