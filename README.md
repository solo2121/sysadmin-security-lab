# Sysadmin Security Lab

A modular Sysadmin, Security, DevOps, and DevSecOps laboratory environment for building, testing, automating, and securing enterprise infrastructure.

This repository contains independent but complementary lab environments for Active Directory security research, detection engineering, infrastructure automation, monitoring, observability, and DevSecOps experimentation.

---

## Overview

The Sysadmin Security Lab is a collection of reproducible environments designed for hands-on learning, research, and portfolio development across multiple disciplines.

It enables:

- Active Directory attack simulation and defense
- Detection engineering aligned with MITRE ATT&CK
- Infrastructure automation using Infrastructure as Code (IaC)
- DevOps and DevSecOps workflow experimentation
- Security monitoring and observability
- Virtualized enterprise infrastructure deployment
- Security validation in isolated environments

**Maintained by:** solo2121  
**Status:** Active  
**Last Updated:** 2026-06-15  

---

## Core Domains

### Security Engineering

- Active Directory security
- Kerberos and LDAP fundamentals
- Attack path simulation
- Detection engineering
- Threat research and analysis
- MITRE ATT&CK mapping

### DevOps & DevSecOps

- CI/CD concepts
- Infrastructure as Code
- Automation workflows
- Security automation
- Configuration management
- Secure deployment practices

### Sysadmin & Infrastructure

- Linux administration
- Virtualization with KVM/QEMU
- Vagrant and libvirt
- Network segmentation
- System hardening
- Enterprise lab design

### Monitoring & Observability

- Grafana
- Prometheus
- Loki
- Log aggregation
- Telemetry collection
- Infrastructure monitoring

---

## Architecture Overview

```text
                         Sysadmin Security Lab

┌──────────────────────────────────────────────────────────────┐
│                                                              │
│                   Virtualized Lab Ecosystem                  │
│                                                              │
├──────────────────────────┬───────────────────────────────────┤
│                          │                                   │
│     AD / Pentest Lab     │      DevOps / DevSecOps Lab       │
│                          │                                   │
│ • Domain Controller      │ • CI/CD Workflows                 │
│ • Member Servers         │ • Infrastructure as Code          │
│ • Kerberos & LDAP        │ • Automation Pipelines            │
│ • Attack Simulation      │ • Security Testing                │
│ • Detection Validation   │ • Monitoring Stack Integration    │
│                          │                                   │
└───────────────┬──────────┴───────────────┬───────────────────┘
                │                          │
                ▼                          ▼

      Security Engineering      Monitoring & Observability

      • Detection Engineering   • Grafana
      • MITRE ATT&CK Mapping    • Prometheus
      • Threat Research         • Loki
      • Log Analysis            • Centralized Telemetry
````

---

## Key Capabilities

* End-to-end Active Directory attack simulation
* Detection engineering and threat validation
* Reproducible infrastructure deployment using Vagrant and libvirt
* DevOps and DevSecOps experimentation
* Infrastructure automation and provisioning
* Centralized logging and observability
* Secure, isolated network environments
* Security research and portfolio development

---

## Skills Demonstrated

### Security

* Active Directory exploitation and defense
* Detection engineering
* Security monitoring
* Threat analysis
* Attack simulation

### DevOps & DevSecOps

* Infrastructure as Code
* CI/CD workflows
* Automation pipelines
* Secure infrastructure deployment
* Configuration management

### Systems Administration

* Linux administration
* Virtualization (KVM/QEMU)
* Network architecture
* System hardening
* Infrastructure operations

---

## Quick Start

### Requirements

* Linux host with KVM support
* 16–32 GB RAM recommended
* Vagrant
* libvirt
* QEMU/KVM

---

### Installation

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git

cd sysadmin-security-lab

sudo apt update

sudo apt install -y \
qemu-kvm \
libvirt-daemon-system \
virt-manager \
vagrant

vagrant plugin install \
vagrant-libvirt \
vagrant-reload \
vagrant-winrm
```

---

## Launch Lab Environments

### Active Directory / Pentest Lab

```bash
cd labs/security/ad-pentest
vagrant up
vagrant status
```

### DevOps / DevSecOps Lab

```bash
cd labs/devops/devsecops-lab
vagrant up
vagrant status
```

---

## Repository Structure

```
docs/
├── architecture/
├── portfolio/
├── detection-engineering/

labs/
├── security/
│   └── ad-pentest/
├── devops/
│   └── devsecops-lab/

security/
├── detections/
├── attack-simulations/
├── research/

sysadmin/
├── automation/
├── hardening/
├── scripts/

assets/
```

---

## Documentation Hub

* [Portfolio Overview](docs/PORTFOLIO.md)
* [Architecture](docs/architecture/ARCHITECTURE.md)
* [Security Scope](docs/architecture/SECURITY-SCOPE.md)
* [Installation Guide](INSTALLATION.md)
* [Changelog](CHANGELOG.md)

---

## Security & Ethics

This project is intended exclusively for educational purposes, authorized security research, and professional skill development.

All testing must be performed only within environments you own or are explicitly authorized to use.

Unauthorized testing against third-party systems is strictly prohibited.

---

## License

MIT License
Author: Miguel A. Carlo

```