# Troubleshooting Guide

Common issues and solutions for the Sysadmin Security Lab environment.

## Installation Issues

### Vagrant Installation Problems

Problem: "command not found: vagrant"

Solution:
1. Verify installation path:
   ```bash
   which vagrant
   ```
2. If not found, reinstall Vagrant:
   ```bash
   curl https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
   sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com focal main"
   sudo apt update
   sudo apt install vagrant
   ```

Problem: "vagrant command failed with error code 1"

Solution:
1. Check Vagrant version compatibility:
   ```bash
   vagrant --version
   ```
2. Update Vagrant to latest version:
   ```bash
   sudo apt update && sudo apt upgrade vagrant
   ```

### Libvirt Installation Problems

Problem: "Error: Failed to start libvirtd service"

Solution:
1. Check for conflicts with other virtualization tools:
   ```bash
   ps aux | grep -i virtualbox
   ```
2. Uninstall conflicting tools if present
3. Reinstall and start libvirt:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart libvirtd
   sudo systemctl status libvirtd
   ```

Problem: "Permission denied" when running libvirt commands

Solution:
1. Add user to libvirt group:
   ```bash
   sudo usermod -aG libvirt $USER
   ```
2. Refresh group membership:
   ```bash
   newgrp libvirt
   ```
3. Verify:
   ```bash
   virsh list
   ```

### Ansible Installation Problems

Problem: "Python module not found"

Solution:
1. Install missing Python dependencies:
   ```bash
   sudo apt install python3-pip
   pip install --upgrade pip
   pip install ansible
   ```

Problem: "Ansible version compatibility"

Solution:
1. Check installed version:
   ```bash
   ansible --version
   ```
2. Update to compatible version:
   ```bash
   pip install --upgrade ansible
   ```

## Lab Startup Issues

### Vagrant Up Fails

Problem: "vagrant up" hangs or fails

Solution:
1. Check Vagrant logs:
   ```bash
   vagrant up --debug > vagrant.log 2>&1
   tail -f vagrant.log
   ```
2. Verify box is downloaded:
   ```bash
   vagrant box list
   ```
3. If missing, download box:
   ```bash
   vagrant box add [box-name]
   ```
4. Try again with increased timeout:
   ```bash
   VAGRANT_NO_PARALLEL=1 vagrant up --no-parallel
   ```

Problem: "No space left on device"

Solution:
1. Check available disk space:
   ```bash
   df -h
   ```
2. Free up space or clean Vagrant cache:
   ```bash
   vagrant box prune
   rm -rf ~/.vagrant.d/boxes/*/
   ```
3. Configure larger storage location if needed

Problem: "Network timeout during provisioning"

Solution:
1. Increase timeout value in Vagrantfile
2. Check internet connectivity:
   ```bash
   ping 8.8.8.8
   ```
3. Run provisioning manually:
   ```bash
   vagrant provision
   ```

### VM Boot Failures

Problem: "VM fails to boot"

Solution:
1. Check VM status:
   ```bash
   vagrant status
   virsh list
   ```
2. View VM logs:
   ```bash
   virsh console <vm-name>
   ```
3. Rebuild VM:
   ```bash
   vagrant destroy -f
   vagrant up
   ```

Problem: "VM stuck in provisioning state"

Solution:
1. Interrupt and halt:
   ```bash
   Ctrl+C
   vagrant halt
   ```
2. Check provisioner status:
   ```bash
   vagrant ssh
   sudo systemctl status provisioning
   ```
3. Resume provisioning:
   ```bash
   vagrant provision
   ```

## Network Issues

### No Network Connectivity

Problem: VMs cannot access external network

Solution:
1. Verify libvirt network:
   ```bash
   virsh net-list
   virsh net-info default
   ```
2. Check bridge interface:
   ```bash
   ip addr show
   brctl show
   ```
3. Restart network:
   ```bash
   sudo systemctl restart libvirtd
   virsh net-destroy default
   virsh net-start default
   ```
4. Verify host routing:
   ```bash
   ip route
   ```

Problem: VMs cannot reach each other

Solution:
1. Verify VM IP addresses:
   ```bash
   vagrant ssh <vm-name>
   ip addr show
   ```
2. Test connectivity:
   ```bash
   ping <other-vm-ip>
   ```
3. Check firewall:
   ```bash
   sudo ufw status
   sudo iptables -L -n
   ```
4. Verify network settings in Vagrantfile

Problem: "Cannot reach vagrant box"

Solution:
1. Check SSH connectivity:
   ```bash
   ssh -v vagrant@<vm-ip>
   ```
2. Verify private key:
   ```bash
   ls -la ~/.vagrant.d/insecure_private_key
   ```
3. Rebuild SSH key:
   ```bash
   vagrant halt
   rm -rf .vagrant/
   vagrant up
   ```

### DNS Resolution Failures

Problem: "Cannot resolve hostnames"

Solution:
1. Check VM DNS configuration:
   ```bash
   vagrant ssh
   cat /etc/resolv.conf
   ```
2. Set DNS servers:
   ```bash
   echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
   echo "nameserver 8.8.4.4" | sudo tee -a /etc/resolv.conf
   ```
3. Restart network:
   ```bash
   sudo systemctl restart systemd-resolved
   ```

## Provisioning Issues

### Ansible Provisioning Fails

Problem: "Failed to connect to host via SSH"

Solution:
1. Verify SSH keys:
   ```bash
   vagrant ssh-config > ssh_config
   ssh -F ssh_config vagrant@<vm-name>
   ```
2. Check VM boot status:
   ```bash
   vagrant status
   ```
3. Wait for VM to fully boot:
   ```bash
   vagrant reload
   ```
4. Run provisioning again:
   ```bash
   vagrant provision
   ```

Problem: "Ansible playbook syntax error"

Solution:
1. Validate playbook syntax:
   ```bash
   ansible-playbook --syntax-check <playbook>.yml
   ```
2. Run with verbose output:
   ```bash
   ansible-playbook -vv <playbook>.yml
   ```
3. Check YAML formatting

Problem: "Task timeout during provisioning"

Solution:
1. Increase timeout in playbook:
   ```yaml
   - name: Long running task
     command: long_command
     async: 600
     poll: 30
   ```
2. Run provisioning with timeout:
   ```bash
   ANSIBLE_TIMEOUT=300 vagrant provision
   ```

### Script Execution Failures

Problem: "Permission denied when running script"

Solution:
1. Make script executable:
   ```bash
   chmod +x script.sh
   ```
2. Use bash explicitly:
   ```bash
   bash script.sh
   ```

Problem: "Script fails with 'command not found'"

Solution:
1. Install missing dependencies:
   ```bash
   sudo apt update && sudo apt install <package>
   ```
2. Verify script path:
   ```bash
   which <command>
   ```
3. Check script shebang line

## Resource Issues

### Insufficient Memory

Problem: "Out of memory" errors

Solution:
1. Check available memory:
   ```bash
   free -h
   ```
2. Reduce VM memory allocation:
   - Edit Vagrantfile
   - Reduce `v.memory` value
   - Rebuild VMs: `vagrant destroy && vagrant up`
3. Add swap space:
   ```bash
   sudo fallocate -l 4G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   ```

Problem: "High CPU usage"

Solution:
1. Monitor CPU usage:
   ```bash
   top
   ```
2. Identify resource-heavy VMs:
   ```bash
   virsh dommemstat <vm-name>
   ```
3. Suspend non-essential VMs:
   ```bash
   vagrant suspend <vm-name>
   ```

### Disk Space Issues

Problem: "Disk space running out"

Solution:
1. Check disk usage:
   ```bash
   df -h
   du -sh *
   ```
2. Clean up Vagrant boxes:
   ```bash
   vagrant box prune
   ```
3. Clean up libvirt storage:
   ```bash
   virsh pool-refresh default
   virsh vol-list default
   ```
4. Remove old snapshots (if using)

## Performance Issues

### Slow Lab Performance

Problem: VMs responding slowly

Solution:
1. Check system resources:
   ```bash
   htop
   iostat
   ```
2. Optimize Vagrant synced folders:
   - Use `type: rsync` instead of NFS
   - Disable if not needed
3. Check disk I/O:
   ```bash
   iostat -x 1
   ```

Problem: Network is slow

Solution:
1. Check network bandwidth:
   ```bash
   iperf3
   ```
2. Disable unnecessary network features
3. Use faster storage for VM disks (SSD recommended)

## Debugging Techniques

### Enable Debug Logging

For Vagrant:
```bash
VAGRANT_LOG=debug vagrant up
```

For Ansible:
```bash
ansible-playbook -vvv playbook.yml
```

For Libvirt:
```bash
export LIBVIRT_LOG_OUTPUTS="1:stderr"
virsh -c qemu:///system list
```

### Check System Logs

```bash
sudo journalctl -xe
sudo dmesg | tail
sudo tail -f /var/log/syslog
```

### VM Console Access

```bash
virsh console <vm-name>
```

Exit console with: Ctrl+]

### Check VM Status

```bash
virsh dominfo <vm-name>
virsh domstate <vm-name>
```

## Getting Help

### Gather Debug Information

Create debug bundle:
```bash
vagrant --version > debug.txt
vagrant status >> debug.txt
virsh list >> debug.txt
virsh net-list >> debug.txt
df -h >> debug.txt
free -h >> debug.txt
```

### Report Issues

When reporting issues:
1. Include debug output
2. Provide error messages
3. Describe steps to reproduce
4. Include system specifications
5. Attach relevant logs

## Common Solutions

Quick fixes for common problems:

1. Something not working: Restart libvirt
   ```bash
   sudo systemctl restart libvirtd
   ```

2. VMs not responding: Halt and restart
   ```bash
   vagrant halt && vagrant up
   ```

3. Network issues: Recreate network
   ```bash
   virsh net-destroy default && virsh net-start default
   ```

4. Persistent issues: Clean rebuild
   ```bash
   vagrant destroy -f && vagrant up
   ```

## Performance Tuning

Optimize lab performance:

1. Use SSD storage
2. Allocate sufficient RAM
3. Enable KVM acceleration
4. Use rsync for synced folders
5. Disable unnecessary services
6. Tune kernel parameters

See INSTALLATION.md for tuning details.

## Additional Resources

- Vagrant Documentation: https://www.vagrantup.com/docs
- Libvirt Documentation: https://libvirt.org/
- Ansible Troubleshooting: https://docs.ansible.com/ansible/latest/user_guide/troubleshooting.html
- KVM/QEMU Documentation: https://www.qemu.org/documentation/

## Support

For additional help:
1. Check GitHub issues
2. Review tutorial documentation
3. Consult tool-specific documentation
4. Open a new GitHub issue with details

## License

This guide is licensed under the MIT License. See [LICENSE](LICENSE) for details.
