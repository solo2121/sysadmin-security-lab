# Security Labs

This directory contains enterprise-focused Active Directory penetration testing and security practice environments.

---

## Available Labs

| Lab | Path | Focus | Version | Hosts |
|-----|------|-------|---------|-------|
| Active Directory Pentest Lab | [`ad-pentest/`](ad-pentest/) | Complete AD attack chain from recon to Domain Admin; Kerberos attacks, AD CS exploits, lateral movement, cloud attacks, LLM security | v1.10 | 14 |
| VLAN Enterprise Lab | [`ad-pentest-vlan/`](ad-pentest-vlan/) | Multi-subnet enterprise topology with VLAN segmentation, routing, inter-VLAN attacks, network isolation testing | v2.1.4 | 14 |

---

## Quick Start

### AD Pentest Lab

```bash
cd ad-pentest
vagrant up
./scripts/vagrant-manager.sh
vagrant status
```

**First attack:** Kerberoasting with no credentials required
```bash
bloodhound-python -u vagrant -p Vagrant123! -d lab.local -dc 172.28.128.21 -c All -o ~/recon/
```

### VLAN Enterprise Lab

```bash
cd ad-pentest-vlan
vagrant up
./scripts/vagrant-manager.sh
vagrant status
```

**First task:** Validate VLAN routing and subnet isolation
```bash
ip route
arp-scan 172.28.128.0/24
```

---

## Lab Architecture

Both security labs share a common **14-host topology** on the `172.28.128.0/24` network:

| Host | IP | OS | Lab Use |
|------|----|----|---------|
| kali | 172.28.128.10 | Kali Linux | Attacker position |
| metasploitable2 | 172.28.128.12 | Ubuntu 8.04 | Legacy target |
| juice-shop | 172.28.128.15 | Node.js | Web app practice |
| dc01 | 172.28.128.21 | Windows Server 2022 | Domain Controller |
| db01 | 172.28.128.23 | Windows Server 2022 | SQL Server *(simulated)* |
| ca01-esc | 172.28.128.24 | Windows Server 2022 | AD CS (exploitable) |
| win10 | 172.28.128.30 | Windows 10 | Workstation |
| pnpt-internal | 172.28.128.50 | Ubuntu 22.04 | Internal server |
| llm01 | 172.28.128.60 | Ubuntu 22.04 | LLM endpoint |
| db01 | 172.28.128.23 | Windows Server 2022 | SQL Server |
| ca01-esc | 172.28.128.25 | Windows Server 2022 | AD CS (exploitable) |
| win10 | 172.28.128.30 | Windows 10 | Workstation |
| pnpt-internal | 172.28.128.50 | Ubuntu 22.04 | Internal server |
| llm01 | 172.28.128.60 | Ubuntu 22.04 | LLM endpoint |
| linux01 | 172.28.128.72 | Ubuntu 22.04 | Linux member |
| print01 | 172.28.128.73 | Windows Server 2022 | Print Server |
| cloud-pentest | 172.28.128.80 | Ubuntu 22.04 | LocalStack (AWS sim) |

---

## Key Credentials (Seeded for Learning)

| Account | Password | Type | Lab Use |
|---------|----------|------|---------|
| vagrant | Vagrant123! | Domain User | Initial access (low-priv) |
| svc_kerberoast | ServiceP@ss2 | Service Account | Kerberoasting target |
| svc_asrep | ServiceP@ss1 | Service Account | AS-REP Roasting target |
| administrator | Passw0rd! | Domain Admin | Final escalation |
| alice.brown | GPOP@ss789! | Domain User | AD CS ESC4 path |
| svc_caadmin | CaAdminP@ss1 | Service Account | CA admin access |
| svc_sql | SqlSvcPass123! | Service Account | SQL Server abuse |

See each lab's `docs/lab-credentials.md` for full credential reference.

---

## Attack Paths

### AD Pentest Lab — Recommended Chain

**Zero credentials → Domain Admin:**

1. **Recon** — nmap, SMB enumeration, DNS zone transfer
2. **BloodHound** — map AD structure and attack paths
3. **Kerberoasting** — crack service account password
4. **AD CS ESC1** — abuse certificate template, escalate to DA
5. **DCSync** — pull all domain hashes and krbtgt

**Estimated time:** 30–60 minutes

See [`ad-pentest/docs/attack-guide.md`](ad-pentest/docs/attack-guide.md) for all techniques.

### VLAN Enterprise Lab — Network Isolation

**Multi-VLAN environment with routing and segmentation:**

1. Validate VLAN segmentation (confirm isolated subnets)
2. Test inter-VLAN routing (confirm firewall rules)
3. Attempt cross-VLAN lateral movement
4. Practice network isolation troubleshooting

See [`ad-pentest-vlan/README.md`](ad-pentest-vlan/README.md) for topology details.

---

## Documentation by Lab

### AD Pentest Lab (`ad-pentest/`)

- **`README.md`** — Lab overview, setup, prerequisites
- **`docs/attack-guide.md`** — Complete attack reference (14 sections, all techniques)
- **`docs/lab-credentials.md`** — All seeded credentials and service accounts
- **`docs/network-map.md`** — Network topology and host details
- **`Vagrantfile`** — Full provisioning (v1.10)
- **`scripts/lab_attack_automation.py`** — Automated attack suite (optional)

### VLAN Enterprise Lab (`ad-pentest-vlan/`)

- **`README.md`** — Lab overview, VLAN topology, setup guide
- **`docs/attack-guide.md`** — VLAN-specific attack paths and testing
- **`docs/lab-credentials.md`** — Credentials for VLAN environment
- **`Vagrantfile`** — Provisioning with VLAN configuration (v2.1.3)

---

## Prerequisites

Before starting either lab:

- **Host:** Linux with hardware virtualization (KVM/QEMU)
- **Vagrant:** Latest version with `vagrant-libvirt` and `vagrant-reload` plugins
- **RAM:** 16 GB minimum (8 GB can run one lab, but slow)
- **Disk:** 100 GB free (each lab ~40–50 GB)
- **Tools on Kali VM inside lab:**
  - impacket, certipy-ad, bloodhound-python, netexec
  - kerbrute, responder, hashcat
  - Installed automatically during `vagrant up`

See [`../../installation.md`](../../installation.md) for full host setup.

---

## Common Workflows

### Reset a Lab

```bash
cd ad-pentest
vagrant destroy -f
vagrant up
```

### Clean Up Attack Artifacts

```bash
rm -f /tmp/*.ccache /tmp/*.pfx /tmp/*.hashes
tar -czf ~/lab_backup_$(date +%Y%m%d).tar.gz ~/lab/
```

### Run Only One VM

```bash
cd ad-pentest
vagrant up dc01
# or
vagrant up kali
```

### Access Logs and Reports

```bash
# After running attacks, find reports here:
ls -lh ~/lab/lab_report_*.{txt,json}
```

---

## Learning Progression

**Recommended order:**

1. **Start with AD Pentest Lab**
   - Run the automated attack chain (`lab_attack_automation.py`)
   - Read the output and understand each phase
   - Manually re-run one phase (e.g., Kerberoasting) with real commands

2. **Try Alternative Paths**
   - Use AD CS ESC4 instead of ESC1
   - Try NTLM Relay instead of Kerberoasting
   - Practice blueblood (DCSync) detection

3. **Move to VLAN Lab**
   - Reason about network isolation
   - Practice VLAN hopping attacks
   - Test firewall rule configurations

4. **Combine Both**
   - Set up AD and VLAN in separate labs
   - Document attack chains
   - Prepare for a mock assessment or interview

---

## Safety and Ethics

**These labs are intentionally vulnerable.** They are designed for:

- Authorized security training and skill development
- Home lab practice (your own machine)
- Corporate team training (isolated network)
- Interview/assessment preparation

**Do not:**

- Expose lab services on public networks
- Reuse lab credentials on real systems
- Run these techniques against systems you don't own

See [`../../docs/architecture/security-scope.md`](../../docs/architecture/security-scope.md) for a full security boundary discussion.

---

## Troubleshooting

### Vagrant Won't Start

```bash
vagrant validate
virsh list --all
vagrant destroy -f && vagrant up
```

### VM Networking Issues

```bash
# Check libvirt network
sudo virsh net-list
sudo virsh net-start lab_network

# From inside a VM, check connectivity
ping 172.28.128.21  # should work
```

### Out of Memory

Run only one lab at a time, or reduce VM memory in the Vagrantfile:
```ruby
config.vm.provider :libvirt do |libvirt|
  libvirt.memory = 2048  # reduce from 4096
end
```

### Kali Tools Not Installed

```bash
# SSH into kali and reinstall
vagrant ssh kali
pip3 install impacket certipy-ad bloodhound netexec
```

For more, see [`../../troubleshooting.md`](../../troubleshooting.md).

---

## Contributing

To improve a security lab:

1. Test your changes locally
2. Update the relevant `README.md` and `attack-guide.md`
3. Ensure the `Vagrantfile` passes `vagrant validate`
4. Run the full test suite (if available)
5. Submit a pull request with a clear description

See [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md) for guidelines.

---

## License

All labs and documentation are provided under the MIT License. See [`../../LICENSE`](../../LICENSE).

---

## Contact & Support

- **GitHub Issues:** Report bugs or request features
- **Discussions:** Ask questions about lab setup or attack paths
- **Pull Requests:** Contribute improvements
