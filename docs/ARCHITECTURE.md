# Repository Architecture

## Vision

**Sysadmin Security Lab** is a modular, reproducible **DevSecOps + Offensive Security + Infrastructure Lab Platform** — a monorepo that serves as both:
- 🧪 **Learning environment** for hands-on security and infrastructure skill building
- 🛠 **Operational toolkit** for system administrators and security engineers
- 📚 **Knowledge base** of industry best practices and attack/defense patterns

---

## Core Principles

1. **Separation of Concerns** — infrastructure, security tools, educational content are distinct
2. **Reproducibility** — every lab must run consistently across environments (Vagrant + IaC)
3. **Modularity** — labs are self-contained and composable
4. **Governed Scope** — clear boundaries on what this repo does (and doesn't do)
5. **Automation-First** — manual steps are documented but scripted where possible

---

## Directory Structure

```
sysadmin-security-lab/
│
├── docs/                          # Repository governance & architecture
│   ├── ARCHITECTURE.md            # This file
│   ├── CONTRIBUTING.md            # Contribution workflow (linked from root)
│   ├── SECURITY-SCOPE.md          # Authorized use boundaries
│   └── WORKFLOWS.md               # CI/CD, testing, deployment patterns
│
├── labs/                          # Hands-on environments (Vagrant + IaC)
│   ├── infrastructure/            # DevOps, Kubernetes, Linux admin labs
│   │   ├── devops-linux-lab/      # Core: Kubernetes, Terraform, Ansible, monitoring
│   │   └── README.md              # Infrastructure labs index
│   │
│   ├── security/                  # Attack/defense environment simulations
│   │   ├── ad-pentest/            # Active Directory pentest lab
│   │   ├── ad-pentest-vlan/       # VLAN + network segmentation lab
│   │   └── README.md              # Security labs index
│   │
│   └── README.md                  # Labs guide + quick start
│
├── security/                      # Standalone offensive/defensive tooling
│   ├── tools/                     # Python/Bash/Rust utilities
│   │   ├── network/               # Network scanning, reconnaissance
│   │   ├── exploitation/          # Exploit scripts, payloads
│   │   ├── post-exploitation/     # Persistence, lateral movement
│   │   └── README.md
│   │
│   ├── frameworks/                # Coordinated attack/defense workflows
│   │   └── README.md
│   │
│   └── README.md                  # Security tools index
│
├── sysadmin/                      # System administration automation
│   ├── hardening/                 # Linux hardening scripts
│   ├── automation/                # Day-2 ops, maintenance scripts
│   ├── monitoring/                # Observability, alerting configs
│   └── README.md
│
├── tutorials/                     # Educational content (documentation)
│   ├── devops/                    # Infrastructure, Kubernetes, GitOps
│   ├── security/                  # Pentest methodology, attack chains
│   ├── linux/                     # System administration, LFCS/RHCSA prep
│   ├── virtualization/            # Vagrant, KVM, networking concepts
│   └── README.md
│
├── assets/                        # Diagrams, templates, reference materials
│   ├── diagrams/                  # Architecture, network topology
│   ├── templates/                 # Vagrantfile, Terraform, Ansible templates
│   ├── images/                    # Screenshots, illustrations
│   └── README.md
│
└── Root governance files
    ├── README.md                  # Project overview & quick start
    ├── SECURITY.md                # Vulnerability reporting
    ├── LICENSE                    # MIT License
    ├── CONTRIBUTING.md            # Contribution guidelines
    ├── INSTALLATION.md            # Dependency setup
    ├── TROUBLESHOOTING.md         # Common issues & fixes
    └── .github/workflows/         # CI/CD automation (GitHub Actions)
```

---

## Core Directories Explained

### **`labs/`** — Reproducible Environments
**Purpose:** Turn theory into practice — deploy real infrastructure locally  
**Contents:** Vagrantfiles, Terraform/Ansible code, startup scripts  
**Who uses it:** Students, labs, learning paths  

**Subdirectories:**
- `infrastructure/` → DevOps, Kubernetes, Linux fundamentals
- `security/` → Attack/defense simulations, pentest environments

**Quality gate:** Every lab must have:
- ✅ Vagrantfile or equivalent provisioning
- ✅ README with setup instructions
- ✅ Architecture diagram
- ✅ Troubleshooting section
- ✅ Example outputs / expected results

---

### **`security/`** — Standalone Tooling
**Purpose:** Reusable security utilities (offensive + defensive)  
**Contents:** Python scripts, Bash utilities, frameworks  
**Who uses it:** Penetration testers, security engineers  

**NOT a lab** — this is modular code you import/use in labs or standalone  

**Subdirectories:**
- `tools/` → Individual utilities (network scanning, exploitation, etc.)
- `frameworks/` → Coordinated workflows (e.g., "AD attack chain", "network defense pipeline")

---

### **`sysadmin/`** — System Administration Automation
**Purpose:** Day-2 operations, hardening, maintenance  
**Contents:** Ansible playbooks, hardening scripts, monitoring configs  
**Who uses it:** Sysadmins, DevOps engineers  

**Subdirectories:**
- `hardening/` → CIS benchmarks, SELinux/AppArmor, firewall rules
- `automation/` → Patching, backups, user management
- `monitoring/` → Prometheus configs, alerting rules, dashboards

---

### **`tutorials/`** — Educational Documentation
**Purpose:** Knowledge transfer — concepts, walkthroughs, methodology  
**Contents:** Markdown guides, attack/defense explanations, best practices  
**Who uses it:** Learners, practitioners refreshing knowledge  

**Subdirectories:**
- `devops/` → Kubernetes, Terraform, Ansible, GitOps
- `security/` → Pentest methodology, attack chains, exploitation techniques
- `linux/` → System admin, LFCS/RHCSA, hardening
- `virtualization/` → KVM, Vagrant, networking concepts

---

### **`assets/`** — Visual & Reference Materials
**Purpose:** Diagrams, templates, checklists  
**Contents:** PNG/SVG diagrams, template files, command references  
**Who uses it:** Everyone (for understanding architecture, reusing templates)

**Subdirectories:**
- `diagrams/` → Architecture, network topology, AD forest structures
- `templates/` → Vagrantfile, Terraform, Ansible, network config templates
- `images/` → Screenshots, illustrations, logos
- `reference/` → Checklists, command reference, tool comparisons

---

## Language Conventions

| Use Case | Primary Language | Notes |
|----------|------------------|-------|
| Automation, configuration management | **Bash / YAML** | Vagrant provisioning, Ansible playbooks |
| Security tooling, scanning | **Python** | Modular, rapid prototyping |
| High-performance system tools | **Rust** | Optional; use when performance critical |
| IaC provisioning | **Terraform** | Infrastructure, not application code |

---

## Boundaries & Scope

### ✅ In Scope

- Linux system administration labs (LFCS/RHCSA level)
- Infrastructure as Code (Terraform, Ansible, Kubernetes)
- Active Directory attack/defense simulation
- Network segmentation and VLAN concepts
- Offensive security tools and techniques (in controlled lab environments)
- DevOps tooling and workflows
- Monitoring and observability

### ❌ Out of Scope

- Malware analysis tools / reverse engineering frameworks
- Zero-day exploits or unpatched vulnerability POCs
- Hosted services or cloud-based infrastructure
- Production-ready monitoring (tutorials only)
- Kernel module development
- Cryptographic algorithm implementations

### ⚠️ Special Considerations

**Authorized Use Only:**
- All offensive security content (exploits, attack chains) is **educational only**
- Use only in controlled lab environments (VMs, sandboxes)
- Never use against systems you don't own or have written permission to test
- See `docs/SECURITY-SCOPE.md` for detailed boundaries

---

## Contribution Workflow

### Adding a New Lab

1. **Choose category**: infrastructure or security?
2. **Create directory**: `labs/{category}/{lab-name}/`
3. **Include these files**:
   ```
   labs/category/my-lab/
   ├── Vagrantfile            # VM provisioning
   ├── README.md              # Setup + instructions
   ├── scripts/               # Automation (bash/python)
   ├── ansible/               # Playbooks (if using)
   ├── terraform/             # IaC (if using)
   └── docs/                  # Architecture diagram, troubleshooting
   ```
4. **Update parent README**: Add entry to `labs/{category}/README.md`
5. **Test locally**: Verify `vagrant up` works end-to-end
6. **Submit PR** with lab + documentation

### Adding a New Tool

1. **Choose subdirectory**: `security/tools/{category}/`
2. **Include**:
   ```
   security/tools/category/my-tool/
   ├── tool.py / tool.sh      # Main script
   ├── README.md              # Usage + examples
   └── requirements.txt       # Dependencies (if Python)
   ```
3. **Update parent README**: Add entry to `security/tools/README.md`
4. **Submit PR** with tool + documentation

### Adding a Tutorial

1. **Choose category**: `tutorials/{topic}/`
2. **Create Markdown file**: `tutorial-name.md`
3. **Include**:
   - Overview / learning objectives
   - Prerequisites
   - Step-by-step walkthrough
   - Examples and diagrams
   - References and further reading
4. **Update parent README**: Add entry to `tutorials/README.md`
5. **Submit PR**

---

## Quality Standards

### Documentation

- Every lab, tool, and tutorial must have a `README.md`
- Architecture diagrams required for labs
- Code comments for non-obvious logic
- Examples provided (usage, sample output)

### Testing

- Labs must provision cleanly (`vagrant up`, no manual steps)
- Scripts must be idempotent where practical
- Error handling: graceful exits with meaningful messages

### Security

- No hardcoded credentials; use `.env` or secrets management
- Minimal required permissions (don't run as root unnecessarily)
- Clear warnings on labs involving offensive techniques

---

## Future Roadmap

### Phase 1: Consolidation (Current)
- Unified architecture documentation ✅
- Organize existing content into established dirs
- Add CI/CD validation

### Phase 2: Standardization
- Unified lab launcher (`labctl` CLI tool)
- Lab metadata format (lab.yaml)
- Automated testing of labs via GitHub Actions

### Phase 3: Tooling
- `labctl start <lab-name>` — spin up any lab
- `labctl test` — validate all labs
- Lab dependency management (lab A requires lab B)

### Phase 4: Scale
- Community contributions pipeline
- Lab versioning and backward compatibility
- Multi-cloud support (AWS, GCP, Azure)

---

## See Also

- `CONTRIBUTING.md` — Detailed contribution guidelines
- `docs/SECURITY-SCOPE.md` — Authorized use boundaries
- `docs/WORKFLOWS.md` — CI/CD and testing patterns
- `TROUBLESHOOTING.md` — Common issues and fixes
- `README.md` — Project overview and quick start
