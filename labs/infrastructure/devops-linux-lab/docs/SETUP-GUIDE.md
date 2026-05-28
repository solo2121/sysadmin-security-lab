# DevOps Linux Lab - Complete Setup Guide

## Prerequisites & System Requirements

### Minimum Hardware
- **CPU**: 8 cores (16+ recommended)
- **RAM**: 16GB (minimum 8GB, not recommended)
- **Storage**: 100GB free SSD space
- **Network**: Stable internet connection for initial image downloads

### Required Software
```bash
# Check installations
vagrant --version          # >= 2.2.0
virsh --version           # libvirt backend
ansible --version         # >= 2.9
terraform --version       # >= 1.0
kubectl version --client  # >= 1.28
helm version              # >= 3.0
```

### Linux Distribution Support
- ✅ Ubuntu 22.04 LTS
- ✅ Fedora 39+
- ✅ Debian 12
- ❌ WSL2 (supported with caveats - see troubleshooting)

---

## Installation Steps

### 1. System Dependencies (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install -y \
  vagrant \
  libvirt-daemon libvirt-daemon-system \
  qemu-system qemu-utils \
  virt-manager \
  ansible \
  terraform \
  git

# Add user to libvirt group (logout/login required)
sudo usermod -aG libvirt,kvm $USER
```

### 2. Vagrant Plugins
```bash
vagrant plugin install vagrant-libvirt
vagrant plugin install vagrant-env
vagrant plugin install vagrant-reload
```

### 3. Clone & Configure Lab
```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab/labs/infrastructure/devops-linux-lab

# Create .env file for customization
cat > .env << EOF
LAB_PROFILE=full
MEMORY_CONTROL_PLANE=4096
MEMORY_WORKER=3072
MEMORY_LINUX_LAB=2048
CPU_COUNT=2
START_VMS=devops-1,k8s-cp,k8s-w1,k8s-w2
FAST_BOOT=true
EOF
```

### 4. Launch Lab
```bash
# Validate Vagrantfile syntax
vagrant validate

# Start infrastructure
vagrant up

# Monitor progress
vagrant status
```

---

## Verification Checklist

### Network Connectivity
```bash
# Test DNS resolution
vagrant ssh devops-1 -c "ping -c 1 8.8.8.8"

# Verify inter-node communication
vagrant ssh k8s-cp -c "ping -c 1 k8s-w1"
```

### Kubernetes Status
```bash
# SSH into control plane
vagrant ssh k8s-cp

# Verify cluster health
kubectl cluster-info
kubectl get nodes
kubectl get componentstatuses
```

### Service Access
```bash
# Port forwarding from host
vagrant ssh devops-1 -- -L 3000:localhost:3000   # Grafana
vagrant ssh devops-1 -- -L 9090:localhost:9090   # Prometheus
vagrant ssh devops-1 -- -L 8081:localhost:8081   # ArgoCD
```

---

## Troubleshooting

### Issue: "libvirt connection refused"
**Solution:**
```bash
sudo systemctl start libvirtd
sudo systemctl enable libvirtd
# Verify socket permissions
ls -l /var/run/libvirt/libvirt-sock
```

### Issue: "Insufficient memory" error
**Solution:**
```bash
# Check available memory
free -h

# Reduce lab size in .env
LAB_PROFILE=minimal
MEMORY_CONTROL_PLANE=2048
MEMORY_WORKER=2048
```

### Issue: "vagrant-libvirt plugin not found"
**Solution:**
```bash
# Reinstall plugins with development headers
sudo apt-get install -y libvirt-dev

# Force reinstall
vagrant plugin uninstall vagrant-libvirt
vagrant plugin install vagrant-libvirt

# Verify
vagrant plugin list | grep libvirt
```

### Issue: "Network timeouts during provisioning"
**Solution:**
```bash
# Check host DNS
cat /etc/resolv.conf

# Restart libvirt networking
sudo virsh net-restart vagrant-libvirt
sudo virsh net-destroy vagrant-libvirt
sudo virsh net-start vagrant-libvirt
```

### Issue: "kubectl connection refused"
**Solution:**
```bash
# Ensure kubeconfig is properly set
vagrant ssh k8s-cp -c "cat /etc/kubernetes/admin.conf" > ~/.kube/config
chmod 600 ~/.kube/config

# Test connectivity
kubectl cluster-info
```

---

## Performance Tuning

### Vagrant-Libvirt Optimization
```bash
# Use caching (9p or virtio)
export VAGRANT_LIBVIRT_SYSTEM_HYPERV_NETWORK=true

# Enable nested virtualization (if available)
echo "options kvm nested=1" | sudo tee /etc/modprobe.d/kvm.conf
sudo modprobe -r kvm_intel && sudo modprobe kvm_intel
```

### VM Resource Limits
Edit `Vagrantfile`:
```ruby
config.vm.provider :libvirt do |libvirt|
  libvirt.cpus = ENV['CPU_COUNT'].to_i || 2
  libvirt.memory = ENV['MEMORY_CONTROL_PLANE'].to_i || 4096
  libvirt.cpu_mode = 'host-passthrough'  # Better performance
end
```

---

## Advanced Configuration

### Custom Networking
```bash
# View current network
sudo virsh net-dumpxml vagrant-libvirt

# Create custom network
sudo virsh net-define custom-network.xml
sudo virsh net-start custom-network
```

### Persistent Storage
```bash
# Create storage volume
sudo virsh vol-create-as vagrant-libvirt lab-storage 50G

# Attach to VM in Vagrantfile
libvirt.storage :file, :size => '50G', :type => 'qcow2'
```

### SSL/TLS for Services
```bash
# Generate certificates for Kubernetes
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout tls.key -out tls.crt

# Create Kubernetes secret
kubectl create secret tls lab-tls --cert=tls.crt --key=tls.key
```

---

## Useful Commands

```bash
# View all VMs status
vagrant status

# SSH into specific VM
vagrant ssh k8s-cp

# Provision without destroying
vagrant provision devops-1

# Stop all VMs gracefully
vagrant halt

# Suspend all VMs (faster than halt)
vagrant suspend

# Destroy entire lab
vagrant destroy -f

# Debug Vagrant
VAGRANT_LOG=debug vagrant up

# Stream logs from provisioning
vagrant up --no-provision && vagrant provision 2>&1 | tee provision.log
```

---

## Next Steps

1. **Set up GitOps**: Push Helm charts to Git repo, configure ArgoCD webhooks
2. **Enable monitoring**: Configure Prometheus scrape configs, create Grafana dashboards
3. **Security hardening**: Implement network policies, RBAC rules, pod security policies
4. **CI/CD integration**: Connect Jenkins/GitHub Actions for automated deployments
5. **Backup strategy**: Set up Velero for cluster backups

---

## Support & Community

- **Issues**: Report bugs on [GitHub Issues](https://github.com/solo2121/sysadmin-security-lab/issues)
- **Documentation**: See `docs/` directory for component-specific guides
- **Contributing**: PRs welcome for improvements and bug fixes

---

**Last Updated**: May 2026  
**Maintainer**: solo2121  
**License**: MIT
