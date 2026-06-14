# Portfolio Index

> Click map for engineers and recruiters. Each section links to the relevant lab, tooling, or documentation.

**Status:** Active &nbsp;|&nbsp; **Last Updated:** 2026-05-29

---

## Labs

| Lab | Path | Focus |
|---|---|---|
| AD Pentest Lab | `labs/security/ad-pentest/` | Kerberos attacks, ESC chains, privilege escalation |
| VLAN Enterprise Lab | `labs/security/ad-pentest-vlan/` | Network segmentation, VLAN isolation, traffic analysis |
| DevOps Linux Lab | `labs/infrastructure/devops-linux-lab/` | Kubernetes, Ansible, Terraform, monitoring stack |

---

## Security Tooling

| Component | Path | Purpose |
|---|---|---|
| Threat Reconnaissance | `security/threat-reconnaissance/` | Nmap automation, surface enumeration |
| Network Security Analysis | `security/network-security-analysis/` | Traffic analysis, topology mapping |
| Detection Engineering | `security/detection-engineering/` | MITRE-aligned detection rules, log pipelines |
| Security Testing Lab | `security/security-testing-lab/` | Offensive tooling and post-exploitation workflows |

---

## Key Techniques by Domain

### Active Directory
- Kerberoasting and AS-REP roasting against live domain controller
- BloodHound attack path enumeration via LDAP
- AD Certificate Services exploitation: ESC1–ESC8 chain → domain compromise
- SMB relay, lateral movement, and persistence

### Infrastructure & DevSecOps
- Vagrant + KVM/QEMU multi-VM provisioning
- Ansible configuration management and Linux hardening
- Terraform infrastructure-as-code workflows
- Prometheus + Grafana + Loki on Kubernetes

### Detection Engineering
- Detection rules mapped to MITRE ATT&CK telemetry sources
- Windows event log and Sysmon pipeline analysis
- Threat visibility gap analysis across simulated attack chains

### Network Security
- Automated Nmap scanning with structured output parsing
- Multi-subnet VLAN segmentation and inter-VLAN traffic inspection
- Enterprise network topology mapping and service fingerprinting

### AI / LLM Security
- Prompt injection testing against instrumented LLM integrations
- Context manipulation and data leakage scenario modeling
- Misconfigured AI deployment attack surface analysis

---

## Documentation

| Document | Purpose |
|---|---|
| `docs/architecture/ARCHITECTURE.md` | Full system design and component diagrams |
| `docs/guides/security/AD_MITRE_log_source_playbook.md` | AD detection playbook |
| `docs/guides/security/Windows_AD_Pentest_Guide_PJPT_Aligned.md` | AD pentest methodology |
| `docs/guides/security/llm-security-compliance-lab.md` | LLM security research notes |
| `docs/workflows/` | Automation and operational runbooks |
| `INSTALLATION.md` | Environment setup and validation |
| `TROUBLESHOOTING.md` | Common issues and fixes |

---

## Suggested Exploration Path

1. `labs/infrastructure/devops-linux-lab/README.md` — start with the base infrastructure
2. `labs/security/ad-pentest/README.md` — core offensive security environment
3. `security/detection-engineering/` — blue team and detection layer
4. `docs/architecture/ARCHITECTURE.md` — full system design