# Complete Setup Guide with Examples

This guide provides **step-by-step examples** for setting up and running the Sysadmin Security Lab with detailed command outputs and verification steps.

---

## Table of Contents

1. [Verification Checklist](#verification-checklist)
2. [System Setup Examples](#system-setup-examples)
3. [Vagrant Configuration Examples](#vagrant-configuration-examples)
4. [Lab Deployment Examples](#lab-deployment-examples)
5. [Troubleshooting with Examples](#troubleshooting-with-examples)
6. [Common Workflows](#common-workflows)

---

## Verification Checklist

### Hardware Virtualization Support

#### Intel Processors

```bash
$ grep -o 'vmx' /proc/cpuinfo | head -1
vmx

# If empty, virtualization is disabled. Enable in BIOS.
```

#### AMD Processors

```bash
$ grep -o 'svm' /proc/cpuinfo | head -1
svm
```

### System Requirements Check

```bash
# Check CPU cores
$ nproc
16

# Check RAM
$ free -h
              total        used        free      shared  buff/cache   available
Mem:           31Gi        8.2Gi        18Gi       512Mi       4.8Gi        22Gi

# Check disk space
$ df -h /var/lib/libvirt/images 2>/dev/null || echo "Path may not exist yet"
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda2       500G  120G  380G  24%  /

# Verify kernel version
$ uname -r
6.5.0-28-generic
```

---

## System Setup Examples

### Installation Verification

#### Verify KVM Module Loading

```bash
# Before installation
$ lsmod | grep kvm
# (no output - kvm not loaded)

# After installation
$ lsmod | grep kvm
kvm_intel             356352  10
kvm                   987136  1 kvm_intel
```

#### Verify Libvirt Installation

```bash
# Check libvirt version
$ virsh version
Compiled against library: libvirt 9.0.0
Using library: libvirt 9.0.0
Running hypervisor: QEMU 7.2.0
```

#### Verify Libvirt Service

```bash
$ sudo systemctl status libvirtd
● libvirtd.service - Virtualization daemon
     Loaded: loaded (/lib/systemd/system/libvirtd.service; enabled; vendor preset: enabled)
     Active: active (running) since Thu 2026-05-30 14:22:33 UTC; 2h 15min ago
       Docs: man:libvirtd(8)
   Main PID: 1245 (libvirtd)
      Tasks: 24 (limit: 4915)
     Memory: 45.2M
        CPU: 2.5s
     CGroup: /system.slice/libvirtd.service
             ├─1245 /usr/sbin/libvirtd
             └─1289 /usr/sbin/dnsmasq --conf-file=/var/run/libvirt/qemu/default.net
```

#### Verify User Permissions

```bash
# Check group membership
$ id
uid=1000(user) gid=1000(user) groups=1000(user),27(libvirt),36(kvm),4(adm),24(cdrom),27(sudo),46(plugdev),120(lpadmin),131(sambashare)

# Test virsh access without sudo
$ virsh list
 Id   Name     State
------------------

# Success if no permission denied error
```

#### Verify Default Network

```bash
$ virsh net-list
 Name      State    Autostart   Persistent
----------------------------------------------
 default   active   yes         yes

# If not active, start it:
$ virsh net-start default
Network default started
```

---

### Vagrant Installation Example

#### Download and Install

```bash
# Create installation directory
$ mkdir -p ~/opt/vagrant
$ cd ~/opt/vagrant

# Download (check latest version at vagrantup.com)
$ wget https://releases.hashicorp.com/vagrant/2.4.1/vagrant_2.4.1_linux_amd64.zip
--2026-05-30 14:25:33--  https://releases.hashicorp.com/vagrant/2.4.1/vagrant_2.4.1_linux_amd64.zip
Resolving releases.hashicorp.com (releases.hashicorp.com)... 199.232.81.194
Connecting to releases.hashicorp.com... connected.
HTTP request sent, awaiting response... 200 OK
     saved 'vagrant_2.4.1_linux_amd64.zip' [79344562 bytes]

# Extract
$ unzip vagrant_2.4.1_linux_amd64.zip
Archive:  vagrant_2.4.1_linux_amd64.zip
  inflating: vagrant
  inflating: vagrant.exe

# Create symlink
$ sudo ln -sf ~/opt/vagrant/vagrant /usr/local/bin/vagrant

# Verify
$ vagrant --version
Vagrant 2.4.1
```

#### Install Vagrant Plugins

```bash
# Required for libvirt support
$ vagrant plugin install vagrant-libvirt
Installing the 'vagrant-libvirt' plugin...
Installed the 'vagrant-libvirt' plugin.

# Optional useful plugins
$ vagrant plugin install vagrant-reload
Installing the 'vagrant-reload' plugin...
Installed the 'vagrant-reload' plugin.

$ vagrant plugin install vagrant-disksize
Installing the 'vagrant-disksize' plugin...
Installed the 'vagrant-disksize' plugin.

# Verify installation
$ vagrant plugin list
vagrant-disksize (0.1.3, global)
vagrant-libvirt (0.17.0, global)
vagrant-reload (0.0.1, global)
```

---

### Vagrant Box Preparation

#### Add Base Boxes

```bash
# Add Ubuntu box
$ vagrant box add ubuntu/jammy64 --provider libvirt
==> box: Loading metadata for box 'ubuntu/jammy64'
==> box: URL: https://vagrantcloud.com/ubuntu/boxes/jammy64
==> box: Adding box 'ubuntu/jammy64' (v20260530.0.0) for provider: libvirt
==> box: Downloading: https://vagrantcloud.com/ubuntu/boxes/jammy64/versions/20260530.0.0/providers/libvirt.box
Progress: 20%|██        | 250.0 MB/1.2 GB [00:35<02:45, 5.8 MB/s]
...
==> box: Successfully added box 'ubuntu/jammy64' (v20260530.0.0) for provider: libvirt

# List available boxes
$ vagrant box list
ubuntu/jammy64            (libvirt, 20260530.0.0)
generic/ubuntu2004       (libvirt, 4.2.16)
```

---

## Vagrant Configuration Examples

### Basic Vagrantfile Example

```ruby
# File: Vagrantfile
Vagrant.configure("2") do |config|
  
  # Define a single VM
  config.vm.define "web" do |web|
    web.vm.box = "ubuntu/jammy64"
    web.vm.hostname = "web-server"
    
    # Network configuration
    web.vm.network "private_network", ip: "192.168.122.10"
    
    # Provider configuration
    web.vm.provider "libvirt" do |libvirt|
      libvirt.memory = 2048
      libvirt.cpus = 2
      libvirt.disk_bus = "virtio"
      libvirt.nic_model_type = "virtio"
    end
    
    # Provisioning
    web.vm.provision "shell", inline: <<-SHELL
      apt-get update
      apt-get install -y nginx
    SHELL
  end

end
```

### Multi-VM Vagrantfile Example

```ruby
# File: Vagrantfile
Vagrant.configure("2") do |config|
  
  # Define multiple VMs with loop
  vms = {
    "control" => { ip: "192.168.122.10", mem: 4096, cpu: 2 },
    "worker1" => { ip: "192.168.122.11", mem: 2048, cpu: 1 },
    "worker2" => { ip: "192.168.122.12", mem: 2048, cpu: 1 }
  }
  
  vms.each do |name, settings|
    config.vm.define name do |node|
      node.vm.box = "ubuntu/jammy64"
      node.vm.hostname = name
      node.vm.network "private_network", ip: settings[:ip]
      
      node.vm.provider "libvirt" do |libvirt|
        libvirt.memory = settings[:mem]
        libvirt.cpus = settings[:cpu]
      end
    end
  end

end
```

---

## Lab Deployment Examples

### DevOps Linux Lab Deployment

#### Step 1: Navigate to Lab Directory

```bash
$ cd sysadmin-security-lab/labs/infrastructure/devops-linux-lab
$ ls -la
total 120
drwxr-xr-x  3 user user  4096 May 30 14:20 .
drwxr-xr-x  3 user user  4096 May 30 14:20 ..
-rw-r--r--  1 user user 54979 May 30 14:20 Vagrantfile
drwxr-xr-x  2 user user  4096 May 30 14:20 scripts
drwxr-xr-x  2 user user  4096 May 30 14:20 docs
-rw-r--r--  1 user user  2150 May 30 14:20 README.md
```

#### Step 2: Pre-download Base Boxes

```bash
# Download Ubuntu box for libvirt
$ vagrant box add ubuntu/jammy64 --provider libvirt
==> box: Loading metadata for box 'ubuntu/jammy64'
==> box: URL: https://vagrantcloud.com/ubuntu/boxes/jammy64
==> box: Adding box 'ubuntu/jammy64' (v20260530.0.0) for provider: libvirt
==> box: Downloading: https://vagrantcloud.com/.../libvirt.box
Progress: 100%|██████████| 612.0 MB/612.0 MB [02:15<00:00, 4.5 MB/s]
==> box: Successfully added box 'ubuntu/jammy64' (v20260530.0.0) for provider: libvirt

# Verify box is available
$ vagrant box list
ubuntu/jammy64 (libvirt, 20260530.0.0)
```

#### Step 3: Start Lab with Status Monitoring

```bash
# Start lab (first time will take 10-20 minutes)
$ vagrant up
Bringing machine 'k3s-cp' up with 'libvirt' provider...
Bringing machine 'k3s-w1' up with 'libvirt' provider...
Bringing machine 'k3s-w2' up with 'libvirt' provider...
==> k3s-cp: Checking if box 'ubuntu/jammy64' version '20260530.0.0' is up to date...
==> k3s-cp: Machine booted and ready for SSH!
==> k3s-cp: Running provisioner: shell...
    k3s-cp: Running: inline script
==> k3s-cp: k3s installed successfully
    k3s-cp: Loaded plugins: fastestmirror
    k3s-cp: Setting up locale...
    k3s-cp: [==========] 100%
==> k3s-w1: Checking if box 'ubuntu/jammy64' version '20260530.0.0' is up to date...
==> k3s-w1: Machine booted and ready for SSH!
==> k3s-w1: Running provisioner: shell...
...

# In another terminal, monitor VMs
$ watch -n 5 'virsh list'
Every 5.0s: virsh list                 Thu May 30 14:35:10 2026

 Id   Name                             State
----------------------------------------------------
 1    sysadmin-security-lab_k3s-cp_1   running
 2    sysadmin-security-lab_k3s-w1_2   running
 3    sysadmin-security-lab_k3s-w2_3   running
```

#### Step 4: Verify Lab Status

```bash
# Check Vagrant status
$ vagrant status
Current machine states:

k3s-cp                    running (libvirt)
k3s-w1                    running (libvirt)
k3s-w2                    running (libvirt)

This environment represents multiple machines. The machines
are all currently running as described above.

# Check each node
$ vagrant ssh k3s-cp -c 'hostname && uname -a'
k3s-cp
Linux k3s-cp 5.15.0-1038-generic #48-Ubuntu SMP Thu May 30 12:00:00 UTC 2026 x86_64 GNU/Linux
```

#### Step 5: Verify Kubernetes Cluster

```bash
# SSH into control plane
$ vagrant ssh k3s-cp
ubuntu@k3s-cp:~$

# Check nodes
ubuntu@k3s-cp:~$ kubectl get nodes
NAME     STATUS   ROLES           AGE     VERSION
k3s-cp   Ready    control-plane   2m      v1.28.3+k3s1
k3s-w1   Ready    <none>          1m      v1.28.3+k3s1
k3s-w2   Ready    <none>          1m      v1.28.3+k3s1

# Check pods
ubuntu@k3s-cp:~$ kubectl get pods -A
NAMESPACE     NAME                     READY   STATUS    RESTARTS   AGE
kube-system   coredns-577f77cb97-x4z8p   1/1     Running   0          1m
kube-system   local-path-provisioner   1/1     Running   0          1m
kube-system   metrics-server-5f9b8d    1/1     Running   0          1m

# Exit
ubuntu@k3s-cp:~$ exit
$ 
```

#### Step 6: Access Lab Services

```bash
# Get IP of control plane
$ vagrant ssh k3s-cp -c 'ip addr show eth1 | grep "inet " | awk "{print \$2}" | cut -d/ -f1'
192.168.122.10

# Services are now accessible (if configured)
# - Grafana: http://192.168.122.10:3000
# - Prometheus: http://192.168.122.10:9090
```

---

### Active Directory Pentest Lab Deployment

#### Step 1: Navigate to AD Lab

```bash
$ cd sysadmin-security-lab/labs/security/ad-pentest
$ ls -la
total 280
-rw-r--r--  1 user user 89698 May 30 14:20 Vagrantfile
-rw-r--r--  1 user user 17587 May 30 14:20 README.md
drwxr-xr-x  2 user user  4096 May 30 14:20 configs
drwxr-xr-x  2 user user  4096 May 30 14:20 scripts
drwxr-xr-x  2 user user  4096 May 30 14:20 docs
```

#### Step 2: Deploy Domain Controller First

```bash
# Start only DC first
$ vagrant up dc01
Bringing machine 'dc01' up with 'libvirt' provider...
==> dc01: Box 'generic/windows-server-2022-standard' was not found. Fetching box...
==> dc01: Adding box 'generic/windows-server-2022-standard' (v4.2.16) for provider: libvirt
==> dc01: Downloading: https://vagrantcloud.com/generic/boxes/windows-server-2022-standard/versions/4.2.16/providers/libvirt.box
Progress: 18%|██        | 1.2 GB/6.8 GB [12:45<58:30, 1.5 MB/s]

# Wait for DC to be ready (can take 30+ minutes)
# Monitor in another terminal
$ watch -n 10 'virsh list | grep dc01'

# Check if DC is ready
$ vagrant ssh dc01 -c "type C:\\DC-FINAL.txt"
```

#### Step 3: Deploy Full Lab (After DC is Ready)

```bash
# Once DC is ready, deploy entire lab
$ vagrant up
Bringing machine 'dc01' up with 'libvirt' provider...
dc01 is already running.
Bringing machine 'kali' up with 'libvirt' provider...
==> kali: Box 'kalilinux/rolling' was not found. Fetching box...
==> kali: Adding box 'kalilinux/rolling' (v2026.2.0) for provider: libvirt
...

# Monitor overall progress
$ watch -n 5 'vagrant status'
Current machine states:

dc01                      running (libvirt)
kali                      running (libvirt)
win10                     running (libvirt)
llm01                     running (libvirt)
cloud-pentest             running (libvirt)
...
```

#### Step 4: Verify Lab Components

```bash
# Check DC DNS
$ nslookup dc01.corp.local 172.28.128.21
Server:     172.28.128.21
Address:    172.28.128.21#53

Non-authoritative answer:
Name:   dc01.corp.local
Address: 172.28.128.21

# SSH into Kali
$ vagrant ssh kali
kali@kali:~$

# Test AD enumeration
kali@kali:~$ nslookup -type=SRV _ldap._tcp.corp.local 172.28.128.21
_ldap._tcp.corp.local   service = 0 100 389 dc01.corp.local

# Test LLM endpoint
kali@kali:~$ curl http://172.28.128.60:8080/health
{"status": "healthy", "version": "1.0.0"}
```

---

## Troubleshooting with Examples

### Issue: "Permission denied" on Vagrant Commands

#### Example Error

```bash
$ vagrant up
/home/user/.vagrant.d/gems/2.4.1/gems/vagrant-libvirt-0.17.0/lib/vagrant-libvirt/action/create_domain.rb:163:in `block in call': Error call virsh to create domain.
error: failed to connect to /var/run/libvirt/libvirt-sock
error: Permission denied
```

#### Solution with Example

```bash
# Verify user is in libvirt group
$ id | grep libvirt
# (if empty, not in group)

# Add user to groups
$ sudo usermod -aG libvirt $USER
$ sudo usermod -aG kvm $USER

# Apply changes immediately
$ newgrp libvirt

# Verify
$ id | grep libvirt
gid=27(libvirt) gid=36(kvm)

# Test
$ virsh list
 Id   Name     State
------------------
# (should work without sudo)
```

### Issue: Network Connectivity Problems

#### Example Error

```bash
$ vagrant ssh
SSH authentication failed. This is typically caused by the
publici/private key mismatch for the machine. This can also happen
when the Vagrant machine is not booted properly.
```

#### Diagnosis with Examples

```bash
# Check if network is active
$ virsh net-list
 Name      State    Autostart   Persistent
----------------------------------------------
 default   inactive no          yes

# Check bridge
$ ip link show virbr0
# (may not exist if network inactive)

# Start network
$ virsh net-start default
Network default started

# Enable autostart
$ virsh net-autostart default
Network marked as autostarted

# Verify VM can ping gateway
$ vagrant ssh k3s-cp -c 'ping -c 1 192.168.122.1'
PING 192.168.122.1 (192.168.122.1) 56(84) bytes of data.
64 bytes from 192.168.122.1: icmp_seq=1 ttl=64 time=0.524 ms

# Success!
```

### Issue: Insufficient Disk Space

#### Example Error

```bash
==> k3s-w1: Waiting for domain to get an IP address...
==> k3s-w1: Waiting for SSH to become available...
error: Failed to create domain from /tmp/vagrant_libvirt_29384.xml
error: Requested operation is not valid: storage pool does not have enough free space
```

#### Solution with Examples

```bash
# Check disk usage
$ df -h /var/lib/libvirt/images/
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda2       200G  195G  5G   98%  /

# List all VM disks
$ ls -lh /var/lib/libvirt/images/*.qcow2
-rw-r--r-- 1 libvirt-qemu kvm 32G May 30 14:20 k3s-cp_disk0.qcow2
-rw-r--r-- 1 libvirt-qemu kvm 32G May 30 14:21 k3s-w1_disk0.qcow2
-rw-r--r-- 1 libvirt-qemu kvm 28G May 30 14:22 dc01_disk0.qcow2

# Check size of largest VM
$ du -sh /var/lib/libvirt/images/
127G    /var/lib/libvirt/images/

# Clean up old boxes
$ vagrant box prune --dry-run
The following boxes will be deleted. You may need to download
these boxes again to use them. Removing them may cause
connectivity issues if your Vagrant setup depends on them.
  ubuntu/jammy64 (libvirt, 20260530.0.0)
  
$ vagrant box prune
Cleaning up 'ubuntu/jammy64'
Cleaned up 1 old box.

# Or destroy lab and rebuild
$ vagrant destroy -f
==> k3s-cp: Removing domain...
==> k3s-w1: Removing domain...
==> k3s-w2: Removing domain...

# Free up space
$ rm -rf /var/lib/libvirt/images/*.qcow2
```

### Issue: High CPU/Memory Usage

#### Example Monitoring

```bash
# Monitor in real-time
$ virt-top

virt-top 1.0.6 (Ubuntu 22.04)
 Phys CPUs: 16          Disk: 850 MB/s
 Logical CPUs: 16       Net RX: 0 B/s
 Host memory: 31.0 GB   Net TX: 0 B/s

ID S RDRQ WRREQ RXBY TXBY %CPU %MEM TIME NAME
 1 R - - - - 85.0 12.1 15:24 k3s-cp
 2 R - - - - 45.2 8.2 08:15 k3s-w1
 3 R - - - - 42.1 8.1 07:52 k3s-w2

# High CPU usage is normal during deployment
# Wait for provisioning to complete
```

#### Optimization Example

```bash
# Reduce resource allocation
# Edit Vagrantfile before starting
libvirt.memory = 1024  # Reduce from 2048
libvirt.cpus = 1      # Reduce from 2

# Deploy only essential VMs
$ export VAGRANT_VMS="dc01,kali"
$ vagrant up

# Monitor system load
$ htop
```

---

## Common Workflows

### Workflow 1: Daily Lab Session

```bash
# 1. Resume lab (from previous suspend)
$ vagrant resume
==> k3s-cp: Resuming machine started with process id 12345
==> k3s-w1: Resuming machine started with process id 12346
==> k3s-w2: Resuming machine started with process id 12347

# 2. Verify all systems are ready
$ vagrant status
Current machine states:
k3s-cp                    running (libvirt)
k3s-w1                    running (libvirt)
k3s-w2                    running (libvirt)

# 3. Check services
$ vagrant ssh k3s-cp -c 'kubectl get nodes'
NAME     STATUS   ROLES           AGE    VERSION
k3s-cp   Ready    control-plane   1d     v1.28.3+k3s1
k3s-w1   Ready    <none>          1d     v1.28.3+k3s1
k3s-w2   Ready    <none>          1d     v1.28.3+k3s1

# 4. Work in lab
$ vagrant ssh k3s-cp

# 5. Suspend when done
$ vagrant suspend
==> k3s-cp: Suspending machine
==> k3s-w1: Suspending machine
==> k3s-w2: Suspending machine
```

### Workflow 2: Create Lab Snapshot Before Testing

```bash
# 1. Ensure all VMs are running and stable
$ vagrant status

# 2. Create snapshot
$ virsh snapshot-create-as --domain k3s-cp stable-v1 \
    --description "Before security testing"
Domain snapshot stable-v1 created

# 3. List snapshots
$ virsh snapshot-list --domain k3s-cp
 Name          Creation Time             State
-----------------------------------------------
 stable-v1     2026-05-30 14:35:12 +0000 shutoff

# 4. Do risky testing...
# 5. If something breaks, revert
$ virsh snapshot-revert --domain k3s-cp stable-v1
Reverting to snapshot stable-v1

# 6. VM restarts from snapshot
$ vagrant status
```

### Workflow 3: SSH into Multiple VMs

```bash
# Method 1: Individual SSH
$ vagrant ssh k3s-cp
ubuntu@k3s-cp:~$ 

# Method 2: Run command remotely
$ vagrant ssh k3s-cp -c 'kubectl get nodes'

# Method 3: SSH into different node
$ vagrant ssh k3s-w1 -c 'systemctl status kubelet'

# Method 4: Use tmux for multiple sessions
$ tmux new-session -d -s lab
$ tmux send-keys -t lab:0 'vagrant ssh k3s-cp' Enter
$ tmux new-window -t lab:1
$ tmux send-keys -t lab:1 'vagrant ssh k3s-w1' Enter
$ tmux select-window -t lab:0
```

### Workflow 4: Debugging Lab Issues

```bash
# 1. Enable debug logging
$ VAGRANT_LOG=debug vagrant up 2>&1 | tee debug.log

# 2. Check VM status
$ virsh list
$ virsh dominfo k3s-cp

# 3. View VM logs
$ virsh console k3s-cp

# 4. Check network
$ virsh net-info default
$ virsh net-dhcp-leases default

# 5. Review vagrant logs
$ tail -100 debug.log | grep -i error

# 6. Destroy and rebuild specific VM
$ vagrant destroy k3s-w1
$ vagrant up k3s-w1
```

---

## Summary Table: Common Commands

| Task | Command | Example |
|------|---------|---------|
| Start lab | `vagrant up` | `cd labs/infrastructure/devops-linux-lab && vagrant up` |
| Stop lab | `vagrant suspend` | `vagrant suspend` |
| Destroy lab | `vagrant destroy -f` | `vagrant destroy -f` |
| SSH to VM | `vagrant ssh <name>` | `vagrant ssh k3s-cp` |
| Run command | `vagrant ssh <name> -c 'cmd'` | `vagrant ssh k3s-cp -c 'kubectl get nodes'` |
| Check status | `vagrant status` | `vagrant status` |
| List VMs | `virsh list` | `virsh list --all` |
| Create snapshot | `virsh snapshot-create-as` | `virsh snapshot-create-as --domain k3s-cp backup1` |
| Revert snapshot | `virsh snapshot-revert` | `virsh snapshot-revert --domain k3s-cp backup1` |
| Monitor resources | `virt-top` | `virt-top` |
| Check network | `virsh net-list` | `virsh net-list --all` |

---

**Last Updated:** 2026-05-30  
**Status:** Active & Maintained
