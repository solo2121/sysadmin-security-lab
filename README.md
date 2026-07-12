# Sysadmin Security Lab

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![Virtualization](https://img.shields.io/badge/Virtualization-KVM%2FLibvirt-orange)
![Security](https://img.shields.io/badge/Security-Enterprise%20Lab-red)
![DevSecOps](https://img.shields.io/badge/DevSecOps-Kubernetes-purple)
[![CI](https://github.com/solo2121/sysadmin-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/solo2121/sysadmin-security-lab/actions/workflows/ci.yml)

**Enterprise cybersecurity homelab for isolated, reproducible environments spanning Active Directory, segmented enterprise networks, and DevSecOps workflows.**

---

![Enterprise Architecture Overview](assets/architecture-overview.png)

## Overview

Sysadmin Security Lab is a modular cybersecurity homelab designed to simulate enterprise infrastructure in a controlled environment. It provides three independent labs for offensive security practice, network segmentation exercises, and modern DevSecOps workflows.

Built for reproducibility and technical depth, the project focuses on realistic attack surfaces, secure-by-design architecture, and hands-on training that maps to real enterprise environments.

---

## Lab Environments

### Lab 1 — Active Directory Pentest

**Path:** `labs/security/ad-pentest/`

A Windows enterprise lab for Active Directory enumeration, privilege escalation, and post-exploitation practice.

- Domain Controller and domain-joined systems.
- AD CS and certificate-based attack paths.
- Kerberos, LDAP, and NTLM attack surfaces.
- Kali-based attacker workflow.
- Cloud simulation with LocalStack.
- Optional AI/LLM security testing scenarios.

**Purpose:** Practice core Active Directory attack and defense workflows in an isolated environment.

### Lab 2 — AD Pentest with VLAN / Enterprise Segmentation

**Path:** `labs/security/ad-pentest-vlan/`

A segmented extension of the AD lab that introduces enterprise-style VLAN boundaries and controlled routing between network zones.

- Separate subnets and trust boundaries.
- Controlled lateral movement and pivoting paths.
- Realistic enterprise network layout.
- Better simulation of containment and detection constraints.

**Purpose:** Study how segmentation affects attack paths, access control, and lateral movement.

### Lab 3 — DevSecOps / DevOps

**Path:** `labs/infrastructure/devops-linux-lab/`

A cloud-native Linux environment for Kubernetes operations, automation, and secure delivery workflows.

- Kubernetes clusters with k3s, Kind, and k3d.
- GitOps with Argo CD.
- Registry, observability, and runtime security tooling.
- Infrastructure as Code with Terraform, OpenTofu, and Ansible.
- Policy and security enforcement with Kyverno and Falco.

Includes intentionally vulnerable scenarios for security practice:
- Misconfigured IaC.
- Exposed secrets.
- Backdoored containers.

**Purpose:** Practice secure DevOps and DevSecOps workflows in a realistic platform environment.

---

## Why This Project Exists

This repository is intended to feel like a real enterprise security platform rather than a personal demo. It is structured to support cybersecurity learning, technical portfolio development, and repeatable lab work without relying on production systems.

The focus is on practical experience with isolated environments, reproducible builds, and security engineering fundamentals.

---

## Design Principles

- **Isolation first:** Each lab is independent and can be deployed separately.
- **Reproducibility:** Environments are designed to be rebuilt consistently.
- **Enterprise realism:** Architecture, naming, and workflows mirror real infrastructure patterns.
- **Security by design:** Labs are built for safe experimentation and structured practice.
- **Modularity:** Each lab serves a distinct technical objective.

---

## Tech Stack

- **Virtualization:** KVM, Libvirt, Vagrant.
- **Operating systems:** Windows Server, Windows 10, Ubuntu, Rocky Linux, AlmaLinux, openSUSE.
- **Identity and directory services:** Active Directory, Kerberos, LDAP, AD CS.
- **Offensive tooling:** BloodHound, Nmap, Metasploit, Hashcat.
- **Cloud simulation:** LocalStack.
- **Containers and orchestration:** Docker, k3s, Kind, k3d.
- **GitOps:** Argo CD.
- **Infrastructure as Code:** Terraform, OpenTofu, Ansible.
- **Observability:** Prometheus, Grafana, Loki.
- **Security controls:** Falco, Kyverno.

---

## Architecture Goals

This project is designed to support hands-on practice in the following areas:

- Offensive security in isolated environments.
- Active Directory attack and defense workflows.
- VLAN segmentation and enterprise network isolation.
- DevSecOps and DevOps delivery pipelines.
- Infrastructure as Code and reproducible provisioning.
- Detection engineering and security validation.
- Cloud-native platform engineering.

---

## Repository Layout

```text
sysadmin-security-lab/
├── assets/
│   └── architecture-overview.png
├── docs/
├── labs/
│   ├── security/
│   │   ├── ad-pentest/
│   │   └── ad-pentest-vlan/
│   └── infrastructure/
│       └── devops-linux-lab/
├── scripts/
├── tests/
└── README.md
```

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

This repository is intended for education, authorized testing, and defensive learning only. Use these environments only on systems you own or where you have explicit permission.

---

## Maintainer

**Miguel A. Carlo**  
Cybersecurity | Enterprise Lab Engineering | DevSecOps

---

## License

MIT License — see [LICENSE](LICENSE) for details.