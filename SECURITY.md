# Security Policy

## Supported Environments

This repository is actively maintained and tested on:

- Ubuntu 22.04 LTS
- Ubuntu 24.04 LTS
- Debian 12

Other Debian-based systems may work but are not officially supported.

---

## Reporting a Vulnerability

If you discover a security issue in this repository — such as accidentally committed credentials, a script that could cause unintended harm, or a misconfiguration in the lab environments — please follow responsible disclosure:

1. **Do not open a public issue.**
2. Send a detailed report to: **security@solo2121.com**
   Include your name, a description of the issue, and steps to reproduce it.
3. If email is unavailable, submit a confidential [GitHub Security Advisory](https://github.com/solo2121/sysadmin-security-lab/security/advisories/new).

---

## Response Policy

- All reports will be acknowledged within **3 business days**.
- A fix or mitigation will be provided within **7 business days** where applicable.
- Reporters will be credited in release notes unless anonymity is requested.

---

## Intentional Vulnerabilities

This lab contains **intentional vulnerabilities** for educational and authorized research purposes. These are expected and by design. Do not report the following as security issues:

- Weak credentials in `LAB_CREDENTIALS.md`
- AD CS misconfigurations (ESC1–ESC9)
- Intentional ACL abuse paths
- LLM endpoints with no authentication
- LocalStack AWS with permissive IAM

---

## Security Best Practices for Users

- Run all lab environments in an **isolated VM or network** — never on production systems.
- Do not expose Vagrant lab ports to public IP addresses.
- Keep your host OS updated and follow standard security hygiene.
- Treat any credentials in this repo as lab-only — never reuse them on real systems.

---

## License

[MIT License](LICENSE) — Copyright (c) 2025 Miguel A. Carlo
