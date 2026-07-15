# Security & Authorized Use Scope

This document defines the legal and ethical scope for this repository, including who is authorized to use the labs and under what conditions.

For attack surface analysis, trust boundaries, and threat assumptions, see [`threat-model.md`](threat-model.md).

---

# Legal & Ethical Framework

This repository contains educational cybersecurity content covering both offensive and defensive security techniques.

All material is intended exclusively for learning, research, security training, and authorized security testing.

You are responsible for ensuring that every activity performed with this repository complies with applicable laws, organizational policies, and any contractual obligations.

Only use these labs in environments where you have explicit authorization.

---

# Authorized Uses

## Personal Learning

- Running labs on your own hardware or virtual machines
- Practicing offensive and defensive security techniques
- Learning Linux, networking, Active Directory, and cloud security
- Preparing for professional security certifications

Examples include:

- OSCP
- PNPT
- CRTO
- GIAC
- Security+

## Educational Use

This repository may be used by:

- Universities
- Colleges
- Cybersecurity bootcamps
- Internal corporate training
- Capture The Flag (CTF) environments

Educational deployments should ensure:

- Students understand acceptable use requirements
- Labs remain isolated from production networks
- Exercises include both offensive and defensive learning objectives

## Professional Security Work

Authorized professional uses include:

- Penetration testing with written authorization
- Internal red team engagements
- Purple team exercises
- Security assessments
- Infrastructure hardening
- Security research performed within approved scope

---

# Prohibited Uses

The following activities are strictly outside the intended scope of this repository.

## Unauthorized Access

Do not use these labs to:

- Access systems without permission
- Escalate privileges on systems you do not own
- Bypass authentication controls
- Compromise third-party infrastructure
- Access data belonging to others

## Malicious Activity

This repository must never be used for:

- Malware deployment
- Ransomware development
- Credential theft
- Data exfiltration
- Denial-of-service attacks
- Destructive payloads
- Persistent unauthorized access

## Unethical Security Testing

Prohibited activities include:

- Testing third-party systems without written authorization
- Unauthorized social engineering
- Public disclosure without responsible disclosure procedures
- Circumventing security controls outside approved engagements

---

# Lab Environment Boundaries

## Included Content

| Category | Included | Scope |
|----------|----------|-------|
| Active Directory attacks | Yes | Lab-only environments |
| Network exploitation | Yes | Isolated virtual networks |
| Credential attacks | Yes | Lab accounts only |
| Web application testing | Yes | Intentionally vulnerable applications |
| Privilege escalation | Yes | Lab virtual machines only |
| Post-exploitation | Yes | Educational environments only |
| Wireless testing | Limited | Controlled WPA/WPA2 laboratory environments |

## Excluded Content

| Category | Status | Reason |
|----------|--------|--------|
| Malware samples | Not included | Unsafe for general distribution |
| Zero-day exploits | Not included | Outside repository scope |
| Self-replicating code | Not included | Unacceptable operational risk |
| Backdoored software | Not included | Supply chain concerns |
| Spyware or keyloggers | Not included | Not appropriate for educational distribution |

---

# Lab Isolation Requirements

Before running any lab, verify the following.

## Network Isolation

- Labs run only on isolated virtual networks
- Production networks are never connected to lab environments
- Bridged networking is disabled unless explicitly required for an authorized exercise
- The host system remains protected by an active firewall

## Credential Management

- Production credentials are never stored inside the repository
- Lab credentials are disposable and used only within the lab
- Secrets are excluded using `.gitignore`
- Sensitive automation data is protected using `ansible-vault` or an equivalent secret-management solution

## Access Control

- Only authorized users have access to the lab environment
- Lab virtual machines are not exposed directly to the Internet
- SSH keys remain local and are not shared
- Sensitive lab data is encrypted when appropriate

---

# Security Notices

## Active Directory Labs

These labs demonstrate techniques commonly used during Active Directory security assessments.

Authorized use includes:

- Internal security testing
- Approved red team engagements
- Security education
- Personal laboratory environments

Do not use these techniques against:

- Production Active Directory environments without written approval
- Third-party organizations
- Systems outside your authorized scope

---

## Network Exploitation Labs

These labs include techniques involving:

- VLAN segmentation
- Layer 2 attacks
- Network reconnaissance
- Traffic manipulation

Authorized use includes:

- Security validation of networks you manage
- Research in isolated environments
- Internal security assessments

Do not perform these techniques on:

- Shared corporate infrastructure
- ISP networks
- Public networks
- Any network outside your approved scope

---

## Credential Attack Labs

These labs include demonstrations of:

- Password spraying
- Brute-force techniques
- Password auditing
- Hash cracking

Authorized use includes:

- Security assessments with written approval
- Internal password audits
- Laboratory environments

Do not perform credential attacks against:

- Production systems
- Third-party services
- Accounts you are not authorized to test

---

# Pre-Lab Checklist

Before starting any exercise, confirm the following.

- [ ] I own or have written authorization to test this environment.
- [ ] My lab is isolated from production infrastructure.
- [ ] No production credentials are stored in the repository.
- [ ] I understand the techniques demonstrated in this lab.
- [ ] Sensitive data will remain confidential.
- [ ] My organization's security team has approved this activity when required.
- [ ] I will not use these techniques outside authorized environments.

If any item cannot be confirmed, do not proceed until appropriate authorization has been obtained.

---

# Responsible Disclosure

If you discover a security issue in this repository:

1. Do not open a public issue.
2. Report the issue privately to `security@solo2121.com`.
3. Include:
   - Description of the issue
   - Reproduction steps
   - Potential impact
   - Suggested remediation
   - Contact information

Expected initial response: within three business days.

See `SECURITY.md` for the complete disclosure policy.

---

# Educational Use Guidelines

Educators using this repository should ensure the following.

## Required

- Students understand acceptable use requirements.
- Labs remain isolated from institutional networks.
- Every exercise has clearly defined learning objectives.
- Defensive concepts accompany offensive techniques.
- Activities occur under instructor supervision.

## Recommended

- Pair offensive labs with defensive exercises.
- Include threat modeling and risk assessment.
- Encourage responsible disclosure practices.
- Document participation and completion records.
- Reinforce ethical decision-making throughout the curriculum.

## Not Permitted

- Unsupervised access to laboratory environments
- Teaching offensive techniques without defensive context
- Using the repository for unauthorized testing
- Sharing lab credentials or virtual machines with unauthorized individuals

---

# References

The following industry resources provide additional guidance.

- EC-Council Code of Ethics
- Penetration Testing Execution Standard (PTES)
- OWASP Responsible Disclosure Guidance
- SANS Ethical Security Training Guidelines
- Computer Fraud and Abuse Act (CFAA)
- Applicable local cybersecurity and computer misuse laws

---

# Questions

If you are uncertain whether a planned activity is authorized:

- Contact the repository maintainer at `security@solo2121.com`.
- Consult your organization's security or legal team.
- Review applicable laws and organizational policies.

When authorization is unclear, do not proceed.

---

# Acknowledgment

By using this repository, you acknowledge that:

- You understand the security implications of the included material.
- You will use this repository only in authorized environments.
- You accept responsibility for your actions.
- You will comply with applicable laws and organizational policies.
- You will report any security issues responsibly.