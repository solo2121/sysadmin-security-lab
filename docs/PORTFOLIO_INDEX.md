# Portfolio Index — DevSecOps & Security Engineering Lab

This document is a navigation guide for reviewers and engineers exploring this repository. Each section links directly to relevant lab components, tooling, and documentation.

**Status:** Active &nbsp;|&nbsp; **Last Updated:** 2026-05-29

---

## 1. Active Directory Security

**Focus:** Enterprise identity attacks, Windows domain exploitation, red/blue team simulation

| Component | Path |
|---|---|
| AD Pentest Lab | `labs/security/ad-pentest/` |
| Security Testing Lab | `security/security-testing-lab/` |
| MITRE Log Source Playbook | `docs/guides/security/AD_MITRE_log_source_playbook.md` |
| AD Pentest Guide (PJPT-aligned) | `docs/guides/security/Windows_AD_Pentest_Guide_PJPT_Aligned.md` |

**Demonstrated techniques:**
- Kerberoasting and AS-REP roasting against a live domain controller
- LDAP enumeration and BloodHound attack path analysis
- AD Certificate Services exploitation (ESC1–ESC8 attack chain)
- Privilege escalation from low-privileged domain user to Domain Admin

---

## 2. DevSecOps Infrastructure Engineering

**Focus:** Reproducible lab provisioning, virtualization, infrastructure automation

| Component | Path |
|---|---|
| DevOps Linux Lab | `labs/infrastructure/devops-linux-lab/` |
| Sysadmin Automation Scripts | `sysadmin/automation/` |
| Infrastructure Guides | `docs/guides/infrastructure/` |

**Demonstrated techniques:**
- Multi-VM environments provisioned with Vagrant and KVM/QEMU
- Ansible playbooks for configuration management and hardening
- Terraform workflows for infrastructure-as-code provisioning
- Prometheus + Grafana + Loki monitoring stack deployment

---

## 3. Detection Engineering & Blue Team

**Focus:** Security telemetry, log analysis, detection rule development

| Component | Path |
|---|---|
| Detection Engineering Lab | `security/detection-engineering/` |

**Demonstrated techniques:**
- Detection rule authoring based on MITRE ATT&CK telemetry sources
- Log pipeline analysis for Windows event and Sysmon data
- System auditing automation for Linux and AD environments
- Threat visibility gap analysis across simulated attack chains

---

## 4. Network Security & Reconnaissance

**Focus:** Network scanning, enumeration, attack surface analysis

| Component | Path |
|---|---|
| Threat Reconnaissance | `security/threat-reconnaissance/` |
| Network Security Analysis | `security/network-security-analysis/` |
| VLAN Enterprise Lab | `labs/security/ad-pentest-vlan/` |

**Demonstrated techniques:**
- Automated Nmap scanning pipelines with structured output parsing
- Multi-subnet VLAN segmentation and inter-VLAN traffic analysis
- Attack surface enumeration across simulated enterprise networks
- Network topology mapping and service fingerprinting

---

## 5. AI / LLM Security Research

**Focus:** Prompt injection, LLM misuse scenarios, AI attack surface analysis

| Component | Path |
|---|---|
| LLM Security Compliance Lab | `docs/guides/security/llm-security-compliance-lab.md` |

**Demonstrated techniques:**
- Prompt injection testing against instrumented LLM integrations
- Context manipulation and data leakage scenario modeling
- Misconfigured AI deployment attack surface analysis
- Security risk documentation for AI-integrated systems

---

## 6. How to Navigate This Repository

Recommended exploration path:

1. **Start here:** `labs/infrastructure/devops-linux-lab/README.md` — understand the base infrastructure
2. **Core lab:** `labs/security/ad-pentest/README.md` — the primary security environment
3. **Supporting tooling:** `security/` — reconnaissance, detection, and analysis tools
4. **Architecture:** `docs/architecture/ARCHITECTURE.md` — full system design
5. **Operational workflows:** `docs/workflows/` — automation and operational runbooks