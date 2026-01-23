# 🛡️ Security & Linux System Administration Toolkit

> ⚠️ **DISCLAIMER**
>
> This repository is provided **solely for educational, research, and authorized security testing purposes**.
> Unauthorized use is strictly prohibited and may violate local, national, or international laws.
> The author assumes **no responsibility** for misuse, damage, or legal consequences.

---

### 🌟 Key Stats

[![Stars](https://img.shields.io/github/stars/solo2121/sysadmin-security-scripts?logo=github&color=yellow)](https://github.com/solo2121/sysadmin-security-scripts/stargazers)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg?logo=git&logoColor=white)](CONTRIBUTING.md)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-2ea44f?logo=githubactions&logoColor=white)](https://github.com/solo2121/sysadmin-security-scripts/commits/main)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?logo=opensourceinitiative&logoColor=white)](LICENSE)

[![Security](https://img.shields.io/badge/Security-Tools-red?logo=shield&logoColor=white)](#security-tools)
[![Sysadmin](https://img.shields.io/badge/Sysadmin-Tools-blue?logo=linux&logoColor=white)](#system-administration)
[![Labs](https://img.shields.io/badge/Labs-Environments-green?logo=vagrant&logoColor=white)](#lab-environments)
[![Docs](https://img.shields.io/badge/Documentation-yellow?logo=book&logoColor=white)](#documentation)

---

## 📌 Overview

This repository provides a **practical toolkit** for:

- 🔒 Authorized security testing and auditing
- 🖥️ Linux system administration & automation
- 🧪 Hands‑on labs for learning and practice
- 📚 In‑depth documentation and tutorials

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
- ✔️ **Safe** – built‑in safeguards and warnings
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

🧪 Lab Environments
Active Directory Pentest Lab (/labs/ad-pentest-lab)

Windows Server 2022/2025 AD environment

Vagrant‑based (✅ libvirt/KVM supported)

Pre‑configured attacker and victim machines

Designed for realistic enterprise AD attack chains

cd labs/ad-pentest-lab
vagrant up

🌐 Networking Model (Libvirt/KVM)
Network Segments

Management Network (NAT) – Internet access for updates and tooling

Corporate Internal Network (Isolated LAN) – Subnet 172.28.128.0/24, fully isolated, all attack traffic remains internal

⚠️ Each VM uses two NICs:
NIC 1 → NAT (management)
NIC 2 → Isolated corporate LAN
Static IPs are required for AD reliability. private_network alone is insufficient; the lab defines a libvirt network with forward_mode: none.

🚀 Quick Start

1️⃣ Clone the repository:

git clone https://github.com/solo2121/sysadmin-security-scripts.git
cd sysadmin-security-scripts


2️⃣ Explore documentation:

ls docs/
less "docs/Complete Git Tutorial for Linux Users.md"


3️⃣ Run a security tool (authorized use only):

cd security/reconnaissance
python3 nmap_menu.py --help


4️⃣ Use sysadmin tools:

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

Violating laws or organizational policies

📋 Checklist

Obtain written authorization

Define testing scope

Notify stakeholders

Use isolated environments

Log activities

Review scripts before execution

🤝 Contributing

🐛 Report issues

💡 Suggest improvements

🔄 Submit pull requests

📚 Improve documentation

See: CONTRIBUTING.md

📄 License

MIT License — free to use, modify, and distribute. No warranty provided.

🌟 Why This Repository Exists

This project reflects years of experience in:

Linux System Administration

Security Operations (Blue & Red Team)

Infrastructure Automation

Technical Education

🎓 Learning Paths

Beginner: Git tutorial → sysadmin utilities → labs

Intermediate: KVM/libvirt guides → security tools → contribute

Advanced: Extend tools → build labs → share expertise

🙏 Acknowledgments

Open‑source security community

Tool authors referenced in scripts

Contributors and reviewers

Ethical security researchers
```
