# 🛡️ Security & Linux System Administration Scripts

> Practical, production-oriented automation scripts for Linux system administration, security operations, and infrastructure hardening.

[![License](https://img.shields.io/badge/License-MIT-blue.svg?logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Stars](https://img.shields.io/github/stars/solo2121/sysadmin-security-scripts?logo=github&color=yellow)](https://github.com/solo2121/sysadmin-security-scripts/stargazers)
[![PRs](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg?logo=git&logoColor=white)](CONTRIBUTING.md)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-2ea44f?logo=githubactions&logoColor=white)](https://github.com/solo2121/sysadmin-security-scripts/commits/main)

---

## 📌 Overview

This repository contains **real-world automation scripts** developed for:

- Linux system administration
- Infrastructure hardening
- Security monitoring and incident response
- Network reconnaissance and validation tasks

The focus is on **clarity, safety, and maintainability**, making the scripts suitable for:

- Remote Linux administration
- Security operations (Blue Team / IR)
- Controlled Red Team testing
- Learning and training environments

### Design Principles

All scripts are built to be:

- ✔️ POSIX-compliant where possible
- ✔️ Safe for **non-interactive execution**
- ✔️ Minimal in external dependencies
- ✔️ Readable, commented, and auditable
- ✔️ Tested on real Linux systems

---

## 🎯 Intended Audience

This repository is designed for:

- Linux System Administrators (on-prem & remote)
- Infrastructure / Platform Engineers
- Security Operations & Incident Response teams
- SREs supporting Linux-based systems

The scripts emphasize:

- Safe execution in remote environments
- Clear logging and predictable output
- Minimal dependencies
- Easy auditing and rollback

---

## 🧩 Repository Structure

scripts/
├── recon/ # Network discovery and validation
├── hardening/ # System and service hardening
├── monitoring/ # Logs, alerts, and health checks
├── incident/ # Incident response helpers
└── maintenance/ # Backup, cleanup, and admin tasks

Each directory contains scripts focused on a specific operational task. See per-directory sections below.

---

## ✨ Capabilities

### 🔍 Offensive / Validation Tasks

Used for **authorized security testing and validation**:

- Network discovery and service enumeration
- Privilege escalation checks
- Host and network data collection
- Baseline security validation

### 🛡️ Defensive Security

Focused on **detection, response, and hardening**:

- Log inspection and filtering
- CIS-style configuration checks
- Incident response helpers
- Patch and update automation

### ⚙️ Linux System Administration

Day-to-day operational tooling:

- System health and resource monitoring
- Backup and recovery helpers
- Maintenance automation
- Compliance and audit support

---

## 🚀 Quick Start

### 1️⃣ Clone the repository

```bash
git clone https://github.com/solo2121/sysadmin-security-scripts.git
cd sysadmin-security-scripts

2️⃣ Review scripts before execution

less scripts/recon/quick-nmap.sh

3️⃣ Run an example (authorized environments only)

./scripts/recon/quick-nmap.sh 192.168.1.0/24 --output scan_report.xml

    💡 Most scripts include comments and can be adapted easily to your environment.

⚠️ Legal & Ethical Notice

    IMPORTANT

    These tools are intended for authorized use only.

        Use only on systems you own or have explicit permission to test

        Follow applicable laws and organizational policies

        Review scripts carefully before running in production

        No warranty is provided — use at your own risk

🤝 Contributing

Contributions are welcome and encouraged.

You can help by:

    🐛 Reporting bugs

    💡 Suggesting improvements

    🔄 Submitting pull requests

Contribution Guidelines

    Keep scripts readable and well-commented

    Prefer POSIX-compatible shell

    Avoid hard-coded secrets

    Test changes on at least one Linux distribution

See CONTRIBUTING.md
for details.
📄 License

This project is licensed under the MIT License.
See the LICENSE
file for details.
⭐ Why This Repo Exists

This repository reflects hands-on experience in:

    Linux administration

    Security operations

    Network troubleshooting

    Teaching and documenting complex topics clearly

It is actively maintained and evolves as real operational needs change.
📁 Per-Directory Mini-README Examples
scripts/recon/

# Reconnaissance Scripts
Scripts in this directory support **authorized network discovery and validation**.

## Purpose
- Identify live hosts and open services
- Validate firewall and network configurations
- Assist with troubleshooting and baseline assessments

## Example
./quick-nmap.sh 192.168.1.0/24 --output scan.xml

scripts/hardening/

# System Hardening Scripts
Scripts focused on **improving Linux system security posture**.

## Purpose
- Enforce baseline security settings
- Identify insecure configurations
- Assist with compliance and audits

scripts/monitoring/

# Monitoring & Observability Scripts
Lightweight monitoring helpers for Linux systems.

## Purpose
- Detect abnormal behavior
- Monitor system health and resources
- Assist in troubleshooting incidents

scripts/incident/

# Incident Response Helpers
Scripts intended to assist during **security incidents or investigations**.

## Purpose
- Rapid data collection
- Log preservation
- Triage support

scripts/maintenance/

# Maintenance & Administration Scripts
Scripts for routine Linux system administration tasks.

## Purpose
- Reduce manual work
- Improve consistency
- Support remote operations
```
