# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `tests/python/` — pytest unit tests for Python tooling logic (argument parsing, data structures).
- `tests/bash/` — bats unit tests for Bash script helper functions and configuration tables.
- `run-tests` CI job running pytest and bats on every push/PR.
- `check-doc-links` CI job that scans all markdown files for broken links and reports findings; informational only, does not fail the build (external link rot and rate limits are expected).
- `.pre-commit-config.yaml` — shellcheck, flake8, detect-secrets, and markdown-link-check hooks for local commit-time validation. Unlike the CI job, the local `markdown-link-check` hook blocks the commit so broken internal links are caught before they're pushed.
- `.secrets.baseline` — audited baseline of intentional lab credentials (AD pentest creds, Vagrantfile test passwords, LocalStack fake AWS key) so `detect-secrets` only flags genuinely new findings.

### Fixed
- Broken relative links in `docs/architecture/architecture.md`, `docs/workflows/WORKFLOWS.md`, `docs/guides/infrastructure/proxmox-host-setup.md`, and `labs/security/ad-pentest/README.md` left over from the docs reorganization.

### Planned
- Additional AD CS attack scenarios.
- Ansible role automation for the DevOps lab.

---

## [2.1.3] - 2026-07-08 — AD Pentest VLAN Lab

### Fixed
- Static IP configuration now uses 5-method adapter detection (target IP,
  lab subnet match, adapter name, non-NAT exclusion, and a debug fallback),
  plus disabled Duplicate Address Detection and set `SkipAsSource=false`.
- Windows Defender disabled via a registry-only approach (silent, reliable).
- AD promotion (`Install-ADDSForest`) now uses explicit named parameters.
- Domain DN and DNS A records hardcoded as literals to avoid Ruby
  interpolation edge cases.
- Silenced a harmless `Set-NetConnectionProfile` error on domain-joined VMs.
- Pinned exact box versions for `metasploitable2` and `juice-shop`.

---

## [1.10.0] - 2026-07-07 — AD Pentest Lab (Enterprise Edition)

### Changed
- Centralized all VM constants (IPs, memory, etc.) in the Vagrantfile.
- Created a reusable domain-join function, removing 300+ lines of duplication.
- Added vagrant-hostmanager integration.
- Pinned all Ubuntu box versions.
- Added health checks and debug mode.
- Reduced LLM01 RAM to 4GB (was 8GB).
- Added external config support (`config.rb`).
- Improved error handling in all PowerShell scripts.
- Added provisioning checkpoints.

### Fixed
- Static IP configuration now uses 5-method adapter detection.
- Windows Defender disabled via registry-only approach.
- AD promotion now uses explicit parameters.
- Domain DN hardcoded for correct PowerShell interpolation.
- DNS records hardcoded with IP addresses.
- Silenced a harmless `Set-NetConnectionProfile` error.

---

## [1.9.0] - 2026-07-03 — AD Pentest Lab (Enterprise Edition)

### Added
- Modern Active Directory attack vectors and expanded AD CS attack paths (ESC1–ESC9).
- Enhanced Linux, Windows, Cloud, and LLM/AI attack scenarios.

### Fixed
- CA01 vs `ca01-esc` inconsistency across the lab: only `ca01-esc` (172.28.128.25, CA name `LAB-ESC-CA`) is actually provisioned; docs, configs, and attack commands previously referenced a nonexistent `CA01` host at `.24`.
- Removed stale `/etc/hosts` entries in the Vagrantfile pointing to the phantom `CA01` host.
- Corrected resource budget calculation that double-counted a nonexistent VM (VM count 15 → 14, ~47.5GB → ~43.5GB).
- Removed unsupported `after` blocks in the Vagrantfile to restore `vagrant validate` functionality.
- Fixed the machine inventory table and network diagram in the lab README, the wrong IP in the attack guide's network map, and the ESC1/ESC8 example commands in the AD MITRE log-source playbook that referenced the wrong CA name and hostname.
- Applied additional stability, security, and provisioning fixes; improved documentation and overall lab reliability.

---

## [8.1.0] - 2026-07-03 — DevOps / DevSecOps Lab

### Added
- Automated DevSecOps attack scenarios and intentionally vulnerable deployments.
- Backdoored image build and Harbor push scenario.
- Terraform state file with intentionally leaked secrets for Infrastructure as Code (IaC) security practice.
- Indirect prompt injection (RAG) scenario for AI/LLM security testing.

---

## [2.1.2] - 2026-06-20 — AD Pentest VLAN Lab

### Fixed
- Dynamic Linux interface detection, removing hardcoded `eth1`.
- Production-grade Windows static IP configuration, preventing provisioning hangs.
- Domain join hostname rename checks to prevent duplicate joins.
- Improved DC readiness detection with a ping check before domain join.
- Windows Defender disabled via a dedicated function.
- Domain name defined as a literal in PowerShell blocks to prevent Ruby interpolation issues.
- Correct RAM calculation banner now accounts for all VMs.
- Vagrant plugin check for `vagrant-reload` now shows a clear error message.
- Libvirt default prefix cleared to prevent VM name collisions.

---

## [8.0.0] - 2026-06-19 — DevOps / DevSecOps Lab

### Added
- OpenTofu v1.8.0 installed alongside Terraform.
- Kind lab VM with a fully automated multi-node Kubernetes-in-Docker cluster: 1 control plane and 2 workers.
- K3d lab VM with a fully automated K3s-in-Docker cluster: 1 server and 2 agents.
- Interactive Harbor password prompt using `io/console`, removing hardcoded credentials.
- Environment-based password handling using `HARBOR_PASS`.
- Dynamic architecture detection for binary downloads (`amd64` / `arm64`).
- `scripts/vagrant-manager.sh` for interactive management of all VMs by group.
- `scripts/validate-lab.sh` for automated health checks across all lab services.
- Pre-configured `kubectl` aliases on Kind and K3d VMs.

### Fixed
- Argo CD CRD deletion now uses `--wait=false` to prevent finalizer hangs.
- Kyverno now uses 3 retries with full namespace cleanup between attempts.
- Docker daemon is reconfigured after Harbor install to trust the registry before seeding.
- Worker provisioner no longer uses the invalid `--flannel-backend` flag.
- Terraform download now uses dynamic architecture detection instead of hardcoded `amd64`.

---

## [2.1.1] - 2026-06-18 — AD Pentest VLAN Lab

### Added
- ZeroLogon (`CVE-2020-1472`) attack path.
- PetitPotam (`CVE-2021-36942`) NTLM relay coercion.
- NoPac (`CVE-2021-42287`) SAM account name spoofing.
- Resource-Based Constrained Delegation (`RBCD`) misconfiguration.
- Enhanced PrintNightmare (`CVE-2021-1675` / `CVE-2021-34527`).
- AD CS ESC9 — No Security Extension.
- Shadow Credentials attack path.
- Auto-generated attack cheat sheet on the Kali VM at `/root/attacks/README.txt`.

---

## [1.8.0] - 2026-06-17 — AD Pentest Lab (Flat Network)

### Added
- NoPac (`CVE-2021-42287`) SAM account name spoofing attack path.
- Resource-Based Constrained Delegation (`RBCD`) misconfiguration.
- AD CS ESC9 — No Security Extension certificate template.
- LLMNR/NBNS poisoning enabled by default for Responder practice.
- Additional Kerberoastable service accounts.
- Automated plugin check and install for `vagrant-reload` and `vagrant-libvirt`.

---

## [2.1.0] - 2026-06-16 — AD Pentest VLAN Lab

### Added
- Enterprise VLAN segmentation across 5 subnets: Management, Workstations, Servers, DMZ, and Attacker.
- 14-VM enterprise topology with Windows Server 2022 DC, CA, Exchange, SharePoint, SQL Server, and Print Server.
- LocalStack AWS attack simulation with S3, IAM, and EC2.
- 15 LLM security research endpoints for prompt injection, RAG poisoning, and token abuse.
- OWASP Juice Shop and Metasploitable2 legacy targets.
- VLAN setup and validation scripts: `setup-vlans.sh`, `test-vlans.sh`.
- Network architecture diagram in Mermaid.
- Vagrant plugin check with automatic install on first run.

### Fixed
- DC readiness detection before domain join.
- Worker node join sequencing.
- Shell variable expansion in Python heredoc blocks.

---

## [7.1.1] - 2026-06-16 — DevOps / DevSecOps Lab

### Fixed
- Python heredoc quoting updated to prevent shell variable expansion (`<<'PYEOF'`).
- Variables are now passed as environment variables into Python generation blocks.
- `registries.yaml` generation syntax errors corrected.

---

## [1.7.0] - 2026-06-15 — AD Pentest Lab (Flat Network)

### Added
- Windows Server 2022 Domain Controller with full AD CS attack paths from ESC1 to ESC9.
- Kali Linux attacker VM with automated tooling.
- Dynamic domain DN construction from `DOMAIN_NAME`.
- Memory warning banner at `vagrant up` time.
- Plugin auto-install for `vagrant-reload` and `vagrant-libvirt`.
- Service accounts, delegation paths, and intentional ACL misconfigurations.
- `LAB_CREDENTIALS.md` with full account inventory.
- `ATTACK_CHAIN.md` documenting ESC8 → NTLM relay → domain compromise path.

### Fixed
- Improved DC provisioning reliability with retry logic.
- Domain join sequencing with proper readiness checks.

---

## [7.1.0] - 2026-06-15 — DevOps / DevSecOps Lab

### Changed
- Python is now used to generate `registries.yaml` for Harbor registry configuration.

---

## [1.0.0] - 2026-06-13 — Initial Public Release

### Added
- Repository structure with `labs/`, `security/`, `sysadmin/`, and `docs/`.
- Security tooling for audit, exploitation, network, reconnaissance, and wireless.
- Sysadmin scripts for automation, monitoring, system hardening, and utilities.
- Documentation for architecture, guides, workflows, and archive.
- `requirements-dev.txt` for contributor Python dependencies.
- MIT License, Code of Conduct, Security Policy, and Contributing guidelines.

---

## [7.0.0] - 2026-05-29 — DevOps / DevSecOps Lab

### Added
- k3s Kubernetes cluster with 1 control plane and 2 workers.
- Harbor container registry with airgap image seeding of 40+ images.
- Argo CD GitOps platform v7.7.5.
- Prometheus, Grafana, and Loki observability stack.
- Falco runtime security.
- Kyverno policy enforcement.
- Cert-Manager TLS automation.
- Terraform v1.9.8 with bash completion.
- Multi-profile deployment: `minimal`, `dev`, `full`.
- Zero-cache Harbor mode (`CACHE_MODE=zero`).
- Dynamic libvirt network auto-detection.
- Linux practice nodes: Ubuntu 24.04, Rocky Linux 10, AlmaLinux 10, openSUSE Leap 15.6.
- Ansible management nodes.
- Day-2 tools: k9s, kubectx, kubens, stern.
- Idempotency markers for all provisioners to support safe re-runs.
- Per-tool installation markers for granular retry.

---

## Versioning Policy

- **MAJOR** — Incompatible changes to lab architecture or workflow.
- **MINOR** — New VMs, tools, or features added.
- **PATCH** — Bug fixes and provisioning reliability improvements.

---

## Reporting Changes

To report a bug, request a feature, or suggest improvements:

1. Check [GitHub Issues](https://github.com/solo2121/sysadmin-security-lab/issues).
2. If it is not already reported, create a new issue with reproduction steps and environment details.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing changes.

---

## License

[MIT License](https://github.com/solo2121/sysadmin-security-lab/blob/main/LICENSE)

Copyright (c) 2023–2026 Miguel A. Carlo