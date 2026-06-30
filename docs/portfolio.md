# Portfolio Index

**Status:** Active &nbsp;|&nbsp; **Last Updated:** 2026-06-26

---

## Labs

| Lab | Path | Focus |
|-----|------|-------|
| Active Directory Pentest Lab | [`labs/security/ad-pentest/`](../labs/security/ad-pentest/) | Kerberos attacks, ESC1–ESC9 chains, privilege escalation, and NTLM relay |
| VLAN Enterprise Lab | [`labs/security/ad-pentest-vlan/`](../labs/security/ad-pentest-vlan/) | Network segmentation, VLAN isolation, enterprise routing, and traffic analysis |
| DevOps Linux Lab | [`labs/infrastructure/devops-linux-lab/`](../labs/infrastructure/devops-linux-lab/) | Kubernetes (k3s, Kind, K3d), Argo CD, Harbor, Terraform, OpenTofu, and the Prometheus/Grafana/Loki stack |

---

## Security Tooling

| Component | Path | Purpose |
|-----------|------|---------|
| Audit | [`security/audit/`](../security/audit/) | LLM security scanner, validator, and Cisco switch audit tooling |
| Network | [`security/network/`](../security/network/) | Traffic analysis, firewall scanning, and topology mapping |
| Exploitation | [`security/exploitation/`](../security/exploitation/) | Educational offensive tooling and post-exploitation workflows |
| Reconnaissance | [`security/reconnaissance/`](../security/reconnaissance/) | Nmap automation, Amass OSINT, and port scanning |
| Wireless | [`security/wireless/`](../security/wireless/) | Wireless lab tooling and evil-twin experimentation |

---

## System Administration

| Component | Path | Purpose |
|-----------|------|---------|
| Automation | [`sysadmin/automation/`](../sysadmin/automation/) | Package management and update automation |
| Monitoring | [`sysadmin/monitoring/`](../sysadmin/monitoring/) | Log analysis and system/security monitoring |
| System Hardening | [`sysadmin/system-hardening/`](../sysadmin/system-hardening/) | ClamAV, rootkit scanning, and user/network audits |
| Utilities | [`sysadmin/utilities/`](../sysadmin/utilities/) | Timeshift, UFW, BIND, memory cleanup, and Git management |

---

## Key Techniques by Domain

### Active Directory
- ESC8 → NTLM relay → domain compromise.
- Kerberoasting and AS-REP roasting.
- BloodHound attack-path enumeration via LDAP.
- DCSync and credential theft.
- ACL abuse and Group Policy exploitation.
- Token impersonation.
- ZeroLogon (`CVE-2020-1472`) and PetitPotam (`CVE-2021-36942`).
- NoPac (`CVE-2021-42287`) and Resource-Based Constrained Delegation (`RBCD`).
- PrintNightmare (`CVE-2021-1675` / `CVE-2021-34527`).

### Cloud
- AWS IAM privilege escalation through LocalStack simulation.
- S3 bucket enumeration and data exfiltration.
- EC2 metadata service exploitation.

### AI / LLM Security
- Prompt injection and jailbreaking.
- RAG poisoning.
- Token bombing and denial-of-service testing.
- Function call injection.
- Chain-of-thought leakage.
- Embedding inversion.

### Detection Engineering
- MITRE ATT&CK-aligned detection rules.
- Windows Event Log and Sysmon pipeline analysis.
- Threat visibility gap analysis across simulated attack chains.

### Infrastructure & DevSecOps
- Multi-VM enterprise lab provisioning with Vagrant and KVM/QEMU.
- Kubernetes cluster deployment with k3s, Kind, and K3d.
- GitOps with Argo CD.
- Infrastructure as Code with Terraform and OpenTofu.
- Container registry management with Harbor and airgap image seeding.

---

## Documentation

| Document | Purpose |
|----------|---------|
| [`docs/guides/infrastructure/`](../docs/guides/infrastructure/) | Infrastructure and lab setup guides |
| [`docs/guides/security/`](../docs/guides/security/) | AD pentest and LLM security guides |
| [`docs/workflows/`](../docs/workflows/) | Lab deployment and operational workflows |
| [`docs/architecture/`](../docs/architecture/) | Architecture and security scope |
| [`INSTALLATION.md`](../INSTALLATION.md) | Full host setup instructions |
| [`TROUBLESHOOTING.md`](../TROUBLESHOOTING.md) | Common issues and fixes |
| [`CHANGELOG.md`](../CHANGELOG.md) | Version history |

---

## Suggested Exploration Path

1. [`labs/infrastructure/devops-linux-lab/README.md`](../labs/infrastructure/devops-linux-lab/README.md) — start with the base infrastructure.
2. [`labs/security/ad-pentest/README.md`](../labs/security/ad-pentest/README.md) — move into the core offensive security environment.
3. [`security/audit/`](../security/audit/) — explore the LLM and detection tooling layer.
4. [`docs/architecture/ARCHITECTURE.md`](../docs/architecture/ARCHITECTURE.md) — review the full system design.

---

## Skills and Role Mapping

| Role | Relevant Lab | Skills Practiced |
|------|-------------|-----------------|
| Penetration Tester | `labs/security/ad-pentest/` | AD enumeration, exploitation, privilege escalation |
| Red Team Operator | `labs/security/ad-pentest-vlan/` | Adversary emulation, lateral movement, C2 concepts |
| Security Engineer | `security/audit/` | LLM security, detection engineering, log analysis |
| Cloud Security Engineer | `labs/security/ad-pentest-vlan/` | AWS IAM abuse, S3 enumeration, EC2 metadata attacks |
| DevSecOps Engineer | `labs/infrastructure/devops-linux-lab/` | Falco, Kyverno, Cert-Manager, Argo CD, Harbor |
| Kubernetes Engineer | `labs/infrastructure/devops-linux-lab/` | k3s, Kind, K3d, Helm, GitOps workflows |
| Linux Systems Administrator | `sysadmin/` + Linux lab nodes | Hardening, monitoring, automation, troubleshooting |