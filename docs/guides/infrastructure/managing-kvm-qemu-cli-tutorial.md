
---

# **KVM/QEMU (CLI) - A Complete Tutorial**

KVM (Kernel-based Virtual Machine) combined with QEMU (Quick Emulator) is a powerful virtualization solution for Linux. This tutorial covers how to manage KVM/QEMU virtual machines (VMs) entirely from the command line.

---

## **Prerequisites**

* A Linux system with KVM support (check with `kvm-ok` or `lsmod | grep kvm`)
* Required packages installed:

  ```bash
  sudo apt update && sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virtinst
  ```
* Root or sudo privileges

---

## **1. Checking KVM Support**

Verify that KVM is enabled:

```bash
lsmod | grep kvm
```

If you see `kvm_intel` or `kvm_amd`, your system supports KVM.

Optional deeper check:

```bash
egrep -c '(vmx|svm)' /proc/cpuinfo
```

A value greater than 0 confirms virtualization support.

---

## **2. Managing Virtual Machines (VMs)**

### **A. Creating a New VM**

Use `virt-install` to create a VM:

```bash
sudo virt-install \
  --name ubuntu-vm \
  --ram 2048 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/ubuntu-vm.qcow2,size=20 \
  --os-variant ubuntu22.04 \
  --network network=default \
  --graphics none \
  --console pty,target_type=serial \
  --location 'http://archive.ubuntu.com/ubuntu/dists/jammy/main/installer-amd64/' \
  --extra-args 'console=ttyS0,115200n8 serial'
```

Notes:

* `--os-type` is deprecated and removed
* `--network network=default` uses NAT (more reliable than `bridge=virbr0`)
* For ISO installs, replace `--location` with `--cdrom /path/to/file.iso`

---

### **B. Listing VMs**

```bash
virsh list --all
```

---

### **C. Starting, Stopping, and Rebooting a VM**

```bash
# Start
virsh start ubuntu-vm

# Graceful shutdown
virsh shutdown ubuntu-vm

# Force stop
virsh destroy ubuntu-vm

# Reboot
virsh reboot ubuntu-vm
```

---

### **D. Accessing a VM Console**

```bash
virsh console ubuntu-vm
```

Exit with:

```
Ctrl + ]
```

---

### **E. Editing VM Configuration**

```bash
virsh dumpxml ubuntu-vm > ubuntu-vm.xml
nano ubuntu-vm.xml
virsh define ubuntu-vm.xml
```

Alternative (faster):

```bash
virsh edit ubuntu-vm
```

---

### **F. Cloning a VM**

```bash
virt-clone \
  --original ubuntu-vm \
  --name ubuntu-vm-clone \
  --file /var/lib/libvirt/images/ubuntu-vm-clone.qcow2
```

---

### **G. Deleting a VM**

```bash
virsh undefine ubuntu-vm --remove-all-storage
```

Note:

* This **will delete disks** because of `--remove-all-storage`

---

## **3. Managing Storage**

### **A. Listing Storage Pools**

```bash
virsh pool-list --all
```

---

### **B. Creating a Storage Pool**

```bash
virsh pool-define-as --name default --type dir --target /var/lib/libvirt/images
virsh pool-start default
virsh pool-autostart default
```

---

### **C. Creating a Disk Image**

```bash
qemu-img create -f qcow2 /var/lib/libvirt/images/ubuntu-disk.qcow2 20G
```

---

## **4. Managing Networks**

### **A. Listing Networks**

```bash
virsh net-list --all
```

---

### **B. Creating a Bridged Network (Netplan Example)**

Edit:

```
/etc/netplan/01-netcfg.yaml
```

Example:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp3s0:
      dhcp4: no
  bridges:
    br0:
      interfaces: [enp3s0]
      dhcp4: yes
```

Apply:

```bash
sudo netplan apply
```

---

### **C. Attaching a VM to a Bridge**

```bash
virsh edit ubuntu-vm
```

Update interface:

```xml
<interface type='bridge'>
  <source bridge='br0'/>
</interface>
```

---

## **5. Snapshots**

### **A. Creating a Snapshot**

```bash
virsh snapshot-create-as ubuntu-vm --name snap1
```

---

### **B. Listing Snapshots**

```bash
virsh snapshot-list ubuntu-vm
```

---

### **C. Restoring a Snapshot**

```bash
virsh snapshot-revert ubuntu-vm --snapshotname snap1
```

---

### **D. Deleting a Snapshot**

```bash
virsh snapshot-delete ubuntu-vm --snapshotname snap1
```

---

## **6. Monitoring and Performance**

### **A. VM Resource Usage**

```bash
virsh domstats ubuntu-vm
```

---

### **B. VM Information**

```bash
virsh dominfo ubuntu-vm
```

---

## **Conclusion**

You now know how to manage KVM/QEMU virtual machines entirely from the command line.

Core tools:

* `virsh` for VM lifecycle management
* `virt-install` for VM creation
* `qemu-img` for disk operations
* `virt-clone` for cloning

For more details, consult:

* `man virsh`
* `man qemu-img`
* [https://libvirt.org/docs.html](https://libvirt.org/docs.html)

---
