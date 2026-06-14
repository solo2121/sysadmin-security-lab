<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB.svg?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/Bash-5.x-4EAA25.svg?style=for-the-badge&logo=gnubash&logoColor=white">
  <img src="https://img.shields.io/badge/Vagrant-Libvirt-1563FF.svg?style=for-the-badge&logo=vagrant&logoColor=white">
  <img src="https://img.shields.io/badge/KVM_QEMU-FF6600.svg?style=for-the-badge&logo=qemu&logoColor=white">
  <img src="https://img.shields.io/badge/Security-Pentesting-red.svg?style=for-the-badge">
  <img src="https://img.shields.io/badge/AD-Lab-FF8C00.svg?style=for-the-badge">
  <img src="https://img.shields.io/badge/LLM-Security-8A2BE2.svg?style=for-the-badge">
</p>

<h1 align="center">Sysadmin Security Lab</h1>

<p align="center">
  A modular DevSecOps and security engineering lab simulating enterprise-grade infrastructure<br>
  for offensive security, detection engineering, and infrastructure automation practice.
</p>

<p align="center">
  <strong>Maintained by:</strong> solo2121 &nbsp;|&nbsp; <strong>Status:</strong> Active &nbsp;|&nbsp; <strong>Last Updated:</strong> 2026-05-29
</p>

---

## What This Is

A hands-on lab platform built to replicate real enterprise environments. It covers the full stack: infrastructure provisioning, Active Directory attack chains, detection engineering, network segmentation, and AI/LLM security research — all in reproducible, isolated environments.

**Core domains:**

- Active Directory attack and defense (Kerberos, AD CS, LDAP)
- DevSecOps infrastructure (Vagrant, KVM/QEMU, Ansible, Terraform)
- Detection engineering and security monitoring
- Network security and VLAN-based enterprise simulation
- AI / LLM security research

---

## Highlights

- Chained ESC8 → NTLM relay → domain compromise in isolated AD lab
- Multi-VM enterprise environments provisioned with Vagrant and KVM/QEMU
- Detection rules authored from MITRE ATT&CK telemetry across simulated attack chains
- Full network segmentation lab with VLAN isolation and traffic analysis
- Prometheus + Grafana + Loki monitoring stack deployed on Kubernetes

---

## Quick Start

**Requirements:** Linux host with KVM support, 16 GB+ RAM recommended

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab
sudo apt update && sudo apt install -y qemu-kvm libvirt-daemon-system virt-manager vagrant
vagrant up && vagrant status
```

---

## Navigate This Repo

→ → **[PORTFOLIO.md](docs/PORTFOLIO.md)** — full lab index, techniques, and documentation map

---

## License & Disclaimer

Licensed under the [MIT License](LICENSE). All testing must be performed in isolated environments you own and control. Do not use any tooling from this project against systems without explicit written authorization.