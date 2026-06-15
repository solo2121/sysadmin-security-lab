# Installation and Setup Guide

This guide provides detailed instructions for installing and setting up the Sysadmin Security Lab environment.

## System Requirements

### Minimum Requirements

- CPU: 4-core processor with virtualization support (Intel VT-x or AMD-V)
- RAM: 8GB (16GB recommended)
- Disk: 50GB free space (100GB+ SSD recommended)
- OS: Ubuntu 24.04 LTS, Ubuntu 22.04 LTS, Debian 12, Rocky Linux 9, or Fedora 40+

### Recommended Specifications

- CPU: 8+ core processor
- RAM: 16GB or more
- Disk: 100GB+ NVMe SSD storage
- Network: Gigabit ethernet connection
- OS: Ubuntu 24.04 LTS

### Hardware Virtualization

Ensure your system supports hardware virtualization:

```bash
# Works for both Intel (vmx) and AMD (svm)
grep -Eoc '(vmx|svm)' /proc/cpuinfo
```

If the output is `0`, virtualization may be disabled in BIOS/UEFI. Enable it there and reboot.

---

## Prerequisites Installation

### 1. Install KVM and Libvirt

**Ubuntu 22.04 / 24.04 / Debian 12:**
```bash
sudo apt update && sudo apt install -y \
  qemu-system-x86 libvirt-daemon-system virtinst \
  libvirt-clients bridge-utils virt-manager
```

**Rocky Linux 9 / RHEL 9 / Fedora 40+:**
```bash
sudo dnf install -y @virtualization
```

Verify installation:
```bash
virsh version
```

---

### 2. Install Vagrant

Download the latest release from https://developer.hashicorp.com/vagrant/downloads

**Ubuntu/Debian (via HashiCorp APT repo — recommended):**
```bash
wget -O - https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
  https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install -y vagrant
```

**Rocky Linux 9 / RHEL 9:**
```bash
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
sudo dnf install -y vagrant
```

Verify installation:
```bash
vagrant --version
```

---

### 3. Install Vagrant Plugins

Required for KVM/libvirt and security-lab reboot provisioning:
```bash
vagrant plugin install vagrant-libvirt
vagrant plugin install vagrant-reload
```

Optional but useful:
```bash
vagrant plugin install vagrant-disksize
```

---

### 4. Install Ansible

**Ubuntu/Debian:**
```bash
sudo apt install -y software-properties-common
sudo add-apt-repository --yes --update ppa:ansible/ansible
sudo apt install -y ansible
```

**Rocky Linux 9 / RHEL 9:**
```bash
sudo dnf install -y epel-release
sudo dnf install -y ansible
```

**Fedora 40+:**
```bash
sudo dnf install -y ansible
```

Verify:
```bash
ansible --version
```

---

### 5. Install Terraform (Optional)

For infrastructure provisioning:

**Ubuntu/Debian:**
```bash
wget -O - https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
  https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install -y terraform
```

**Rocky Linux 9 / Fedora:**
```bash
sudo dnf config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
sudo dnf install -y terraform
```

Verify:
```bash
terraform -version
```

---

### 6. Install Docker (Optional)

For container-based labs:

**Ubuntu/Debian:**
```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker
```

**Rocky Linux 9 / RHEL 9:**
```bash
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

> **Note:** Docker Compose is now a CLI plugin (`docker compose`). The legacy `docker-compose` command is deprecated.

---

### 7. Install Git

**Ubuntu/Debian:**
```bash
sudo apt install -y git
```

**Rocky Linux 9 / Fedora:**
```bash
sudo dnf install -y git
```

Configure Git:
```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
```

---

## User and Permissions Setup

### Add Current User to Required Groups

```bash
sudo usermod -aG libvirt,kvm $USER
```

Apply without logging out:
```bash
newgrp libvirt
```

### Enable Libvirt Service

```bash
sudo systemctl enable --now libvirtd
```

Verify:
```bash
sudo systemctl status libvirtd
```

---

## Repository Setup

### Clone the Repository

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab
```

### Install Python Dependencies (If Applicable)

```bash
pip install -r requirements-dev.txt
```

> If `requirements-dev.txt` does not exist, dependencies are managed through Vagrant provisioning.

---

## Network Configuration

### Verify Default Network

```bash
virsh net-list --all
```

Expected output:
```
 Name      State    Autostart   Persistent
--------------------------------------------
 default   active   yes         yes
```

### Activate Default Network (If Needed)

```bash
virsh net-start default
virsh net-autostart default
```

### Create Isolated Lab Networks (Optional)

```bash
virsh net-define <network-definition.xml>
virsh net-start <network-name>
```

---

## Storage Setup

### Verify Default Storage Pool

```bash
virsh pool-list --all
```

Expected output:
```
 Name      State    Autostart
-------------------------------
 default   active   yes
```

### Create a Dedicated Lab Storage Pool (Optional)

```bash
sudo mkdir -p /var/lib/libvirt/images/lab
virsh pool-define-as lab-storage dir --target /var/lib/libvirt/images/lab
virsh pool-build lab-storage
virsh pool-start lab-storage
virsh pool-autostart lab-storage
```

---

## Vagrant Box Preparation

### Download Base Boxes

**DevOps Linux Lab:**
```bash
vagrant box add bento/ubuntu-24.04
vagrant box add bento/rocky-9
vagrant box add bento/almalinux-9
```

**AD Pentest Lab:**
```bash
vagrant box add generic/ubuntu2204
vagrant box add generic/windows2022
```

### Convert Boxes to Libvirt Format

```bash
vagrant mutate bento/ubuntu-24.04 libvirt
```

---

## Initial Lab Startup

### Test Basic Functionality

```bash
cd labs/infrastructure/devops-linux-lab
vagrant up
```

> First run may take 10–20 minutes while boxes are downloaded and provisioned.

Monitor VM status:
```bash
vagrant status
```

All VMs should show `running` once complete.

### Connect to a VM

```bash
vagrant ssh <node-name>
```

Example:
```bash
vagrant ssh k8s-cp
```

### Suspend and Destroy

```bash
# Suspend (save state)
vagrant suspend

# Full teardown
vagrant destroy -f
```

---

## Troubleshooting

### Virtualization Not Enabled

**Error:** `This platform doesn't support libvirt`

Enable VT-x / AMD-V in your BIOS/UEFI settings, then reinstall:
```bash
sudo apt remove --purge qemu-system-x86 libvirt-daemon-system
sudo apt install -y qemu-system-x86 libvirt-daemon-system
```

### Permission Denied Errors

**Error:** `Permission denied` when running Vagrant

```bash
sudo usermod -aG libvirt $USER
newgrp libvirt
```

### Insufficient Disk Space

**Error:** `No space left on device`

```bash
df -h
du -sh /var/lib/libvirt/images/*
```

Consider moving the storage pool to a larger disk or clearing old boxes:
```bash
vagrant box prune
```

### Network Connectivity Issues

**Error:** VMs cannot reach each other or the internet

```bash
virsh net-info default
ip route show
```

### Ansible Provisioning Fails

**Error:** `Failed to connect to host`

Verify SSH access manually:
```bash
vagrant ssh <node-name>
```

Also check that port 22 is not blocked by a local firewall:
```bash
sudo ufw status
```

---

## Post-Installation Verification

```bash
# Check tool versions
vagrant --version
virsh version
ansible --version
terraform -version
docker --version

# List downloaded boxes
vagrant box list

# Verify networking and storage
virsh net-list --all
virsh pool-list --all
```

---

## Performance Tuning

### Increase File Descriptors

```bash
sudo sysctl -w fs.file-max=2097152
echo "fs.file-max = 2097152" | sudo tee -a /etc/sysctl.d/99-lab.conf
```

### Optimize Swap

```bash
sudo sysctl -w vm.swappiness=10
echo "vm.swappiness = 10" | sudo tee -a /etc/sysctl.d/99-lab.conf
```

### Apply Changes

```bash
sudo sysctl --system
```

---

## Next Steps

1. Review lab-specific `README` files in the `labs/` directory
2. Read `CONTRIBUTING.md` for contribution guidelines
3. Explore `docs/guides/` for detailed walkthroughs
4. Check `TROUBLESHOOTING.md` for known issues
5. Start with the **DevOps Linux Lab** for foundational concepts

---

## Additional Resources

- [Vagrant Docs](https://developer.hashicorp.com/vagrant/docs)
- [Libvirt Docs](https://libvirt.org/docs.html)
- [Ansible Docs](https://docs.ansible.com/)
- [Terraform Docs](https://developer.hashicorp.com/terraform/docs)
- [KVM/QEMU Docs](https://www.qemu.org/documentation/)

---

## Support

1. Check `TROUBLESHOOTING.md`
2. Review lab-specific documentation
3. Consult upstream tool documentation
4. Open a GitHub issue with full error output

---

## License

This guide is licensed under the MIT License. See `LICENSE` for details.
