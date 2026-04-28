# Installation and Setup Guide

This guide provides detailed instructions for installing and setting up the Sysadmin Security Lab environment.

## System Requirements

### Minimum Requirements

- CPU: 4-core processor with virtualization support
- RAM: 8GB (16GB recommended)
- Disk: 50GB free space (100GB+ recommended)
- OS: Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, Debian, Rocky Linux, or compatible Linux distribution

### Recommended Specifications

- CPU: 8+ core processor
- RAM: 16GB or more
- Disk: 100GB+ fast SSD storage
- Network: Gigabit ethernet connection
- OS: Ubuntu 22.04 LTS

### Hardware Virtualization

Ensure your system supports hardware virtualization:

On Intel processors:
```bash
grep -o 'vmx' /proc/cpuinfo
```

On AMD processors:
```bash
grep -o 'svm' /proc/cpuinfo
```

If output is empty, virtualization may be disabled in BIOS. Enable it in your system BIOS settings.

## Prerequisites Installation

### 1. Install KVM and Libvirt

For Ubuntu/Debian:
```bash
sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system libvirt-daemon libvirt-clients bridge-utils virt-manager -y
```

For Rocky Linux/RHEL:
```bash
sudo dnf install @virtualization -y
```

Verify installation:
```bash
virsh list
```

### 2. Install Vagrant

Download from https://www.vagrantup.com/downloads

For Ubuntu/Debian:
```bash
wget https://releases.hashicorp.com/vagrant/[VERSION]/vagrant_[VERSION]_linux_amd64.zip
unzip vagrant_[VERSION]_linux_amd64.zip
sudo mv vagrant /usr/local/bin/
```

Verify installation:
```bash
vagrant --version
```

### 3. Install Vagrant Plugins

Required plugins for KVM support:
```bash
vagrant plugin install vagrant-libvirt
vagrant plugin install vagrant-mutate
```

Optional useful plugins:
```bash
vagrant plugin install vagrant-reload
vagrant plugin install vagrant-disksize
```

### 4. Install Ansible

For Ubuntu/Debian:
```bash
sudo apt install ansible -y
```

For Rocky Linux/RHEL:
```bash
sudo dnf install ansible -y
```

Verify installation:
```bash
ansible --version
```

### 5. Install Terraform (Optional)

For infrastructure provisioning:
```bash
wget https://releases.hashicorp.com/terraform/[VERSION]/terraform_[VERSION]_linux_amd64.zip
unzip terraform_[VERSION]_linux_amd64.zip
sudo mv terraform /usr/local/bin/
```

Verify installation:
```bash
terraform -version
```

### 6. Install Docker (Optional)

For container-based labs:
```bash
sudo apt install docker.io docker-compose -y
sudo usermod -aG docker $USER
```

Restart your session or run:
```bash
newgrp docker
```

### 7. Install Git

For version control:
```bash
sudo apt install git -y
```

Configure Git:
```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

## User and Permissions Setup

### Add Current User to libvirt Group

```bash
sudo usermod -a -G libvirt $USER
sudo usermod -a -G kvm $USER
```

Logout and login, or:
```bash
newgrp libvirt
newgrp kvm
```

### Enable Libvirt Service

```bash
sudo systemctl enable libvirtd
sudo systemctl start libvirtd
```

Verify:
```bash
sudo systemctl status libvirtd
```

## Repository Setup

### Clone the Repository

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab
```

### Install Python Dependencies (If Applicable)

```bash
pip install -r requirements.txt
```

If requirements.txt does not exist, dependencies are managed through Vagrant provisioning.

## Network Configuration

### Verify Default Network

```bash
virsh net-list
```

Should show:
```
Name      State    Autostart   Persistent
-----------+---------+-----------+-----------
default   active   yes         yes
```

### Configure Network (If Needed)

If default network is not active:
```bash
virsh net-start default
virsh net-autostart default
```

### Create Additional Networks (Optional)

For lab isolation, create separate networks:
```bash
virsh net-create <network-definition-file.xml>
```

## Storage Setup

### Default Storage Pool

Verify default storage pool:
```bash
virsh pool-list
```

Should show:
```
Name         State      Autostart
-----------+----------+-----------
default      active     yes
```

### Create Additional Storage Pools (Optional)

For better performance, create dedicated storage pools:
```bash
virsh pool-create-as --name lab-storage --type dir --target /var/lib/libvirt/images/lab
```

## Vagrant Box Preparation

### Download Base Boxes

For DevOps Linux Lab:
```bash
vagrant box add ubuntu/focal64
vagrant box add bento/rocky-8
vagrant box add bento/alma-8
```

For AD Pentest Lab:
```bash
vagrant box add generic/ubuntu2004
vagrant box add generic/windows2019
```

### Update Boxes to Libvirt Format

```bash
vagrant mutate ubuntu/focal64 libvirt
```

## Initial Lab Startup

### Test Basic Functionality

```bash
cd labs/infrastructure/devops-linux-lab
vagrant up
```

This may take 10-20 minutes on first run.

Monitor progress:
```bash
vagrant status
```

Once complete:
```bash
vagrant status
```

Should show all VMs as "running".

### Connect to Lab

```bash
vagrant ssh <node-name>
```

Example:
```bash
vagrant ssh k8s-cp
```

### Stop and Clean Up

After initial test:
```bash
vagrant suspend
```

To fully remove:
```bash
vagrant destroy -f
```

## Troubleshooting Installation

### Virtualization Not Supported

Error: "This platform doesn't support libvirt"

Solution: Enable virtualization in BIOS and reinstall:
```bash
sudo apt remove --purge qemu-kvm libvirt*
sudo apt install qemu-kvm libvirt-daemon-system -y
```

### Permission Denied Errors

Error: "Permission denied" when running vagrant

Solution: Add user to libvirt group and restart:
```bash
sudo usermod -a -G libvirt $USER
newgrp libvirt
```

### Insufficient Disk Space

Error: "No space left on device"

Solution: Free up disk space or configure larger storage pool:
```bash
df -h
```

### Network Connectivity Issues

Error: VMs cannot reach each other or external network

Solution: Verify network configuration:
```bash
virsh net-info default
ipaddr route
```

### Ansible Provisioning Fails

Error: "Failed to connect to host"

Solution: Verify SSH access:
```bash
vagrant ssh <node-name>
```

## Post-Installation Verification

Verify complete setup:

1. Check all prerequisites:
   ```bash
   vagrant --version
   virsh version
   ansible --version
   terraform -version
   ```

2. List available boxes:
   ```bash
   vagrant box list
   ```

3. Verify network:
   ```bash
   virsh net-list
   ```

4. Check storage:
   ```bash
   virsh pool-list
   ```

5. Test lab startup (see Initial Lab Startup section above)

## Next Steps

After successful installation:

1. Review lab-specific README files in labs/ directory
2. Read CONTRIBUTING.md for contribution guidelines
3. Check tutorials/ directory for detailed guides
4. Review TROUBLESHOOTING.md for common issues
5. Start with DevOps Linux Lab for basic concepts

## System Performance Tuning

### Increase File Descriptors

```bash
sudo sysctl -w fs.file-max=2097152
echo "fs.file-max = 2097152" | sudo tee -a /etc/sysctl.conf
```

### Enable Memory Overcommit (With Caution)

```bash
sudo sysctl -w vm.overcommit_memory=1
echo "vm.overcommit_memory = 1" | sudo tee -a /etc/sysctl.conf
```

### Optimize Swap

```bash
sudo sysctl -w vm.swappiness=10
echo "vm.swappiness = 10" | sudo tee -a /etc/sysctl.conf
```

## Additional Resources

- Vagrant Documentation: https://www.vagrantup.com/docs
- Libvirt Documentation: https://libvirt.org/docs.html
- Ansible Documentation: https://docs.ansible.com/
- Terraform Documentation: https://www.terraform.io/docs
- KVM/QEMU Documentation: https://www.qemu.org/documentation/

## Support

For installation issues:

1. Check TROUBLESHOOTING.md
2. Review lab-specific documentation
3. Consult prerequisite tool documentation
4. Open an issue on GitHub with error details

## License

This guide is licensed under the MIT License. See LICENSE file for details.
