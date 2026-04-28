# Labs Directory

This directory contains hands-on learning labs covering infrastructure, security, and system administration topics. Each lab is designed to provide practical, real-world experience in specific areas.

## Available Labs

### Infrastructure Labs

**Location:** `labs/infrastructure/`

#### DevOps Linux Lab (Core Platform)
**Path:** `labs/infrastructure/devops-linux-lab/`

A comprehensive local DevOps and Kubernetes learning environment featuring:
- LFCS / RHCSA / Linux+ certification practice
- Kubernetes cluster setup with kubeadm
- Infrastructure as Code with Terraform and Ansible
- GitOps workflows using ArgoCD
- Monitoring stack with Prometheus, Grafana, and Loki
- Multi-node architecture simulation
- DevOps tooling practice (Helm, kubectl, git)

See `labs/infrastructure/devops-linux-lab/README.md` for detailed setup instructions.

### Security Labs

**Location:** `labs/security/`

#### Active Directory Pentest Lab
**Path:** `labs/security/ad-pentest/`

Simulates enterprise Active Directory environments for offensive security training:
- Active Directory enumeration techniques
- Kerberos attack chains (Kerberoasting, AS-REP roasting)
- Certificate Services exploitation (ESC attacks)
- SMB relay attacks and lateral movement
- Privilege escalation and persistence techniques
- Credential theft and pass-the-hash attacks

#### VLAN Enterprise Lab
**Path:** `labs/security/ad-pentest-vlan/`

Network-focused security lab for enterprise environment simulation:
- Network segmentation and VLAN isolation
- Multi-subnet enterprise architecture
- Network topology analysis and reconnaissance
- Cross-VLAN traffic patterns
- Network defense and detection strategies
- Includes architecture diagrams and automation scripts

## Quick Start Guide

### Prerequisites

Before running any lab, ensure you have the following installed:
- Vagrant
- Libvirt / KVM hypervisor
- QEMU
- At least 8GB RAM (16GB recommended for larger labs)
- Git
- Ansible (for infrastructure configuration)

See INSTALLATION.md for detailed setup instructions.

### Running a Lab

1. Clone the repository:
   ```bash
   git clone https://github.com/solo2121/sysadmin-security-lab.git
   cd sysadmin-security-lab
   ```

2. Navigate to your chosen lab:
   ```bash
   cd labs/infrastructure/devops-linux-lab
   ```

3. Start the lab:
   ```bash
   vagrant up
   ```

4. Access the lab environment:
   ```bash
   vagrant ssh <node-name>
   ```

### Stopping and Cleaning Up

To pause the lab:
```bash
vagrant suspend
```

To stop and destroy:
```bash
vagrant destroy -f
```

## Lab Structure

Each lab typically includes the following components:

- **Vagrantfile** - Vagrant configuration for VM provisioning
- **scripts/** - Automation scripts for setup and configuration
- **docs/** - Detailed documentation and guides
- **terraform/** - Infrastructure as Code definitions
- **ansible/** - Configuration management playbooks
- **README.md** - Lab-specific setup and usage instructions

## Learning Path

Recommended progression for getting the most from these labs:

1. Start with **Linux system administration fundamentals** using the DevOps Linux Lab
2. Practice **virtualization and networking concepts**
3. Learn **infrastructure automation** with Terraform and Ansible
4. Master **Kubernetes and container orchestration**
5. Progress to **Active Directory attack simulation**
6. Study **privilege escalation and persistence techniques**
7. Practice **network segmentation and defense**
8. Explore **AI / LLM security testing**

## Lab Management

Optional lab manager script (if available):
```bash
./scripts/lab-manager.sh
```

This tool helps manage multiple VMs and labs simultaneously.

## Troubleshooting

For common issues and solutions, see TROUBLESHOOTING.md

### Common Issues

- Lab fails to start: Check Vagrant and Libvirt installation
- Network connectivity issues: Verify KVM network configuration
- Insufficient resources: Increase allocated RAM or reduce VM count
- Ansible provisioning fails: Check playbook syntax and host connectivity

## Contributing

To contribute new labs or improvements:

1. Create a new directory under the appropriate category (infrastructure, security, etc.)
2. Include all necessary configuration files (Vagrantfile, playbooks, scripts)
3. Add comprehensive README.md documentation
4. Follow the naming conventions established in existing labs
5. Submit a pull request with your changes

See CONTRIBUTING.md for detailed guidelines.

## Support

For issues, questions, or suggestions:
- Check existing GitHub issues
- Review lab-specific documentation
- Consult TROUBLESHOOTING.md
- See SECURITY.md for security-related concerns

## License

All labs are licensed under the MIT License. See LICENSE file for details.
