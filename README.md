# Sysadmin Security Lab

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![Virtualization](https://img.shields.io/badge/Virtualization-KVM%2FLibvirt-orange)
![Security](https://img.shields.io/badge/Security-Enterprise%20Lab-red)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Kubernetes-purple)
[![CI](https://github.com/solo2121/sysadmin-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/solo2121/sysadmin-security-lab/actions/workflows/ci.yml)

**Enterprise cybersecurity homelab for isolated, reproducible, and secure-by-design training across Active Directory, segmented enterprise networks, and DevSecOps workflows.**

---

## Hero Overview

![Enterprise Architecture Overview](assets/architecture-overview.png)

This repository models a modern enterprise security environment through **three independent labs** built for offensive security practice, infrastructure hardening, and real-world-ready technical training.

- Isolated lab environments by design.
- Reproducible deployments with Infrastructure as Code.
- Enterprise-style attack surfaces and security boundaries.
- Practical training for red team, blue team, and platform security workflows.

---

## Lab Portfolio

### Lab 1 — Active Directory Pentest

**Path:** `labs/security/ad-pentest/`

A Windows enterprise environment for Active Directory security research, domain compromise, privilege escalation, and post-exploitation practice.

- Domain Controller and domain-joined systems.
- AD CS with multiple escalation paths.
- Kerberos, LDAP, and NTLM attack surfaces.
- Kali-based attacker workflow.
- Cloud simulation via LocalStack.
- Optional AI/LLM security testing scenarios.

**Use this lab to practice:** initial access, domain enumeration, lateral movement, and full AD attack chains.

### Lab 2 — AD Pentest with VLAN / Enterprise Segmentation

**Path:** `labs/security/ad-pentest-vlan/`

A segmented version of the AD lab that introduces enterprise-style VLAN boundaries and controlled routing between isolated network zones.

- Separate subnets and segmented trust boundaries.
- Controlled lateral movement and pivoting paths.
- Realistic enterprise network layout.
- Better simulation of detection and containment constraints.

**Use this lab to practice:** attack path analysis, segmentation-aware exploitation, and enterprise network defense concepts.

### Lab 3 — DevSecOps / DevOps

**Path:** `labs/infrastructure/devops-linux-lab/`

A cloud-native, Linux-focused environment for Kubernetes operations, CI/CD, GitOps, and infrastructure automation.

- Kubernetes clusters with k3s, Kind, and k3d.
- GitOps with Argo CD.
- Registry, observability, and runtime security tooling.
- IaC and automation with Terraform, OpenTofu, and Ansible.
- Policy and security enforcement with Kyverno and Falco.

Includes intentionally vulnerable scenarios:
- Misconfigured IaC.
- Exposed secrets.
- Backdoored containers.

**Use this lab to practice:** secure delivery pipelines, infrastructure automation, and cloud-native security operations.

---

## Design Principles

This project is built like a small enterprise security platform, not a toy lab.

- **Isolation first:** each lab is independent and can be deployed separately.
- **Reproducibility:** environments are designed to be rebuilt consistently.
- **Enterprise realism:** architecture, naming, and workflows reflect real infrastructure patterns.
- **Security by design:** labs are structured to support safe experimentation.
- **Modularity:** each lab serves a distinct training objective.

---

## Tech Stack

- **Virtualization:** KVM, Libvirt, Vagrant.
- **Operating systems:** Windows Server, Windows 10, Ubuntu, Rocky Linux, AlmaLinux, openSUSE.
- **Directory services:** Active Directory, Kerberos, LDAP, AD CS.
- **Offensive tooling:** BloodHound, Nmap, Metasploit, Hashcat.
- **Cloud simulation:** LocalStack.
- **Containers and Kubernetes:** Docker, k3s, Kind, k3d.
- **GitOps:** Argo CD.
- **IaC and automation:** Terraform, OpenTofu, Ansible.
- **Observability:** Prometheus, Grafana, Loki.
- **Security controls:** Falco, Kyverno.

---

## Architecture Goals

The labs are designed to support hands-on practice in the following areas:

- Offensive security practice in isolated environments.
- Active Directory attack and defense workflows.
- VLAN segmentation and enterprise network isolation.
- DevSecOps and DevOps delivery pipelines.
- Infrastructure as Code and reproducible builds.
- Detection engineering and security validation.
- Realistic platform engineering and cloud-native operations.

---

## Repository Layout

```text
sysadmin-security-lab/
├── labs/
│   ├── security/
│   │   ├── ad-pentest/
│   │   └── ad-pentest-vlan/
│   └── infrastructure/
│       └── devops-linux-lab/
├── docs/
├── scripts/
├── tests/
├── assets/
└── README.md
```

---

## Why This Exists

This project exists to provide a credible enterprise-style lab that supports cybersecurity training without relying on production systems. It is meant for learning, experimentation, and portfolio-grade technical work in a controlled environment.

---

## Quick Start

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab
```

### Deploy Lab 1

```bash
cd labs/security/ad-pentest
vagrant up
```

### Deploy Lab 2

```bash
cd labs/security/ad-pentest-vlan
vagrant up
```

### Deploy Lab 3

```bash
cd labs/infrastructure/devops-linux-lab
vagrant up
```

---

## Security and Ethics

This repository is intended for education, authorized testing, and defensive learning only. Do not use these techniques outside systems you own or environments where you have explicit permission.

---

## Maintainer

**Miguel A. Carlo**  
Cybersecurity | Enterprise Lab Engineering | DevSecOps

---

## License

MIT License — see [LICENSE](LICENSE) for details.