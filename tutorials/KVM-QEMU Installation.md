
---

# **How to Install and Configure KVM/QEMU on Rhino Linux**

## **Introduction**

This tutorial provides a step-by-step guide to installing and configuring Kernel-based Virtual Machine (KVM) and Quick Emulator (QEMU) on Rhino Linux. KVM/QEMU enables the creation and management of virtual machines (VMs), making it an ideal solution for virtualization.

---

## **Step 1: Verify Virtualization Support**

Before proceeding, ensure your processor supports virtualization.

Run:

```bash
lscpu | grep Virtualization
```

If the output shows:

* `VT-x` (Intel)
* `AMD-V` (AMD)

then virtualization is supported.

---

## **Step 2: Install KVM, QEMU, and Related Packages**

### Install required packages:

```bash
sudo apt update
sudo apt install -y qemu-kvm libvirt-clients libvirt-daemon-system bridge-utils virtinst libvirt-daemon virt-top libguestfs-tools libosinfo-bin qemu-system tuned
```

### Key packages:

* **qemu-kvm**: KVM integration with QEMU
* **libvirt**: Virtualization management toolkit
* **bridge-utils**: Network bridge utilities
* **virtinst**: VM creation tool
* **virt-top**: VM monitoring tool
* **libguestfs-tools**: Disk image tools
* **tuned**: Performance optimization

---

### Add your user to required groups:

```bash
sudo usermod -aG libvirt $(whoami)
sudo usermod -aG kvm $(whoami)
```

Reboot to apply:

```bash
sudo reboot
```

---

### Enable performance tuning:

```bash
sudo systemctl enable --now tuned
sudo tuned-adm profile virtual-host
sudo tuned-adm active
```

---

### Verify installation:

```bash
sudo virsh net-list --all
sudo nmcli device status
```

---

## **Step 3: Create a Bridge Network**

A bridge allows VMs to access the same network as the host.

### Create bridge:

```bash
sudo nmcli connection add type bridge con-name br0 ifname br0
```

### Add physical interface (replace `ens33` if needed):

```bash
sudo nmcli connection add type ethernet slave-type bridge con-name "KVM Bridge" ifname ens33 master br0
```

### Enable auto-connect:

```bash
sudo nmcli connection modify br0 connection.autoconnect-slaves 1
```

### Activate:

```bash
sudo nmcli connection up br0
sudo nmcli connection reload
```

### Verify:

```bash
sudo nmcli device status
ip -brief addr show dev br0
```

---

## **Step 4: Set Permissions for Image Directory**

Default path:

```
/var/lib/libvirt/images
```

### Check:

```bash
ls -ld /var/lib/libvirt/images
```

### Reset ACLs:

```bash
sudo setfacl -R -b /var/lib/libvirt/images
```

### Grant access:

```bash
sudo setfacl -R -m u:$(whoami):rwX /var/lib/libvirt/images
sudo setfacl -m d:u:$(whoami):rwx /var/lib/libvirt/images
```

---

### Optional GUI tools:

```bash
sudo apt install -y virt-manager virt-viewer
```

---

## **Step 5: Convert OVA Files to QCOW2 Format**

### 5.1 Extract OVA:

```bash
tar xf file.ova -C /tmp/ova-extract
```

---

### 5.2 Convert VMDK to QCOW2:

```bash
qemu-img convert -c -O qcow2 input.vmdk output.qcow2
```

---

### 5.3 Convert Other Formats:

```bash
# VHD
qemu-img convert -c -O qcow2 my_disk.vhd my_disk.qcow2

# VDI
qemu-img convert -c -O qcow2 my_disk.vdi my_disk.qcow2

# RAW
qemu-img convert -c -O qcow2 my_disk.raw my_disk.qcow2
```

---

### 5.4 Show Progress:

```bash
qemu-img convert -c -O qcow2 -p input.vmdk output.qcow2
```

---

### 5.5 Batch Conversion:

```bash
for file in *.vmdk; do
  qemu-img convert -c -O qcow2 -p "$file" "${file%.vmdk}.qcow2"
done
```

---

## **Step 6: Verify Conversion**

```bash
qemu-img info my_disk.qcow2
```

---

## **Step 7: Install Additional Tools**

```bash
sudo apt install -y virtinst libosinfo-bin virt-top libguestfs-tools
sudo apt install -y qemu-guest-agent
```

Ensure group membership:

```bash
groups
```

---

## **Step 8: Verify the Installation**

```bash
sudo virsh list --all
```

---