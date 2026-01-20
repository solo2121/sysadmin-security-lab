# 🛡️ Security & Linux System Administration Toolkit

> A comprehensive collection of **security**, **system administration**, and **training tools** for Linux environments — designed for clarity, safety, and hands-on learning.

[![License](https://img.shields.io/badge/License-MIT-blue.svg?logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Stars](https://img.shields.io/github/stars/solo2121/sysadmin-security-scripts?logo=github&color=yellow)](https://github.com/solo2121/sysadmin-security-scripts/stargazers)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg?logo=git&logoColor=white)](CONTRIBUTING.md)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-2ea44f?logo=githubactions&logoColor=white)](https://github.com/solo2121/sysadmin-security-scripts/commits/main)

[![Security](https://img.shields.io/badge/Security-Tools-red?logo=shield&logoColor=white)](#security-tools)  
[![Sysadmin](https://img.shields.io/badge/Sysadmin-Tools-blue?logo=linux&logoColor=white)](#system-administration)  
[![Labs](https://img.shields.io/badge/Labs-Environments-green?logo=vagrant&logoColor=white)](#lab-environments)  
[![Docs](https://img.shields.io/badge/Documentation-yellow?logo=book&logoColor=white)](#documentation)

---

## 📌 Table of Contents

1. [Overview](#overview)
2. [Design Principles](#design-principles)
3. [Repository Structure](#repository-structure)
4. [Capabilities](#capabilities-by-category)
   - [Security Tools](#security-tools)
   - [System Administration](#system-administration)
   - [Lab Environments](#lab-environments)
   - [Documentation](#documentation)
5. [Quick Start](#quick-start)
6. [Legal & Ethical Usage](#legal--ethical-usage-notice)
7. [Contributing](#contributing)
8. [License](#license)
9. [Why This Repository Exists](#why-this-repository-exists)
10. [Learning Paths](#learning-paths)
11. [Acknowledgments](#acknowledgments)

---

## 📌 Overview

This repository provides a **practical toolkit** for:

- 🔒 Security testing and auditing (authorized only)
- 🖥️ Linux system administration & automation
- 🧪 Hands-on labs for learning and practice
- 📚 In-depth documentation and tutorials

Designed for:

- Professionals performing authorized security assessments
- Linux sysadmins managing infrastructure
- Blue Team / Incident Response practitioners
- Students and security enthusiasts
- Infrastructure hardening & compliance

---

## 🎯 Design Principles

All scripts and tools follow these core principles:

- ✔️ **Readable** – clean, commented, maintainable code
- ✔️ **Safe** – built-in safeguards and warnings
- ✔️ **Modular** – single-purpose, composable tools
- ✔️ **Documented** – usage examples included
- ✔️ **Cross-distribution** – works on major Linux distros

---

## 🏗️ Repository Structure

```text
.
├── CONTRIBUTING.md
├── docs/                  # Documentation and tutorials
├── labs/                  # Training lab environments
│   └── ad-pentest-lab/
├── security/              # Security & pentest tools
│   ├── audit/
│   ├── enumeration/
│   ├── exploitation/
│   ├── network/
│   ├── post-exploitation/
│   ├── reconnaissance/
│   └── wireless/
├── sysadmin/              # Linux system administration
│   ├── automation/
│   ├── git/
│   ├── monitoring/
│   ├── security/
│   └── utilities/
├── LICENSE
└── README.md
🛠️ Capabilities by Category
🔍 Security Tools (/security)

Authorized security testing tools:

Reconnaissance: nmap_menu.py, amass-scan.py, port-scanner.py

Exploitation: sql_injection.py, exploit.py

Network Analysis: ettercap-menu.py, scapy-port-scan.py, tcpdump_wrapper.py

Wireless Security: evil-twin.py

Auditing: cisco-switch-audit.py, llm_security_validator.py

🖥️ System Administration (/sysadmin)

Linux infrastructure scripts:

Monitoring: system_monitor.sh, log_analyzer.sh, sec_monitor.sh

Automation: update.sh, pacstall-maintenance.sh, rhino-update.py

Security & Auditing: linaudit.sh, user_audit.sh, rootkit_scan.sh

Utilities: ufw-manager.sh, timeshift-manager.sh, bind-manager.sh

🧪 Lab Environments (/labs)
Active Directory Pentest Lab

Windows Server 2025 AD environment

Vagrant-based (VirtualBox/libvirt supported)

Pre-configured attacker and victim machines

cd labs/ad-pentest-lab
vagrant up


📄 Documentation: docs/Windows Server 2025 Active Directory Assessment.md

📚 Documentation (/docs)

Git & version control

KVM/QEMU & Vagrant tutorials

Pacstall / TimeShift CLI guides

Security tooling overview & AD assessments

🚀 Quick Start
1️⃣ Clone the repository
git clone https://github.com/solo2121/sysadmin-security-scripts.git
cd sysadmin-security-scripts

2️⃣ Explore Documentation
ls docs/
less "docs/Complete Git Tutorial for Linux Users.md"

3️⃣ Run a Security Tool (Authorized Only)
cd security/reconnaissance
python3 nmap_menu.py --help

4️⃣ Use Sysadmin Tools
cd sysadmin/monitoring
./system_monitor.sh

⚠️ Legal & Ethical Usage Notice

IMPORTANT: Tools are for authorized and ethical use only.

✅ Allowed

Owned systems

Systems with explicit written permission

Isolated lab environments

Educational purposes

🚫 Prohibited

Unauthorized scanning or testing

Malicious activity

Violating laws or policies

📋 Checklist

Obtain written authorization

Define testing scope

Notify stakeholders

Use isolated environment

Log activities

Review scripts before running

🤝 Contributing

🐛 Report issues

💡 Suggest improvements

🔄 Submit pull requests

📚 Improve documentation

📄 See: CONTRIBUTING.md

📄 License

MIT License – free to use, modify, distribute. No warranty. See LICENSE for details.

🌟 Why This Repository Exists

Reflects years of experience in:

Linux System Administration

Security Operations (Blue/Red Team)

Infrastructure Automation

Technical Education

🎓 Learning Paths

Beginner: Git tutorial → sysadmin utilities → labs
Intermediate: KVM/QEMU guides → security tools → contribute
Advanced: Extend security tools → build labs → share expertise

🙏 Acknowledgments

Open-source security community

Tool authors referenced in scripts

Contributors and reviewers

Ethical security researchers
```
