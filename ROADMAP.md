# Roadmap

This roadmap is a working list of ideas I want to improve over time. It is not a promise of dates or deadlines—priorities change based on what is most useful next. I maintain these labs myself, and I share them to help others who want a place to practice. Suggestions and pull requests are welcome; see [`CONTRIBUTING.md`](CONTRIBUTING.md).

For a log of what has already been released, see [`CHANGELOG.md`](CHANGELOG.md).

## Near-term

- [ ] Add a recorded demo (asciinema or GIF) to the README showing `vagrant up` provisioning and an AD attack chain in action.
- [ ] Expand automated test coverage across more `sysadmin/` and `security/` scripts (currently: `log-analyzer.sh`, `setup-vlans.sh`, `port-scanner.py`).

## Mid-term

- [ ] Add more AD CS attack scenarios beyond the current ESC1 and ESC8 coverage.
- [ ] Create Ansible roles for more repeatable DevOps lab provisioning, instead of relying mostly on Vagrant provisioners.
- [ ] Build a Windows Server hardening lab as a defensive counterpart to the AD pentest lab.
- [ ] Expand the VLAN lab with more realistic segmentation scenarios beyond the current 5 VLANs.

## Long-term / Exploratory

- [ ] Add an optional cloud deployment path with Terraform for either lab, as an alternative to local libvirt; see [`docs/optimization/minimal-resource-deployment.md`](docs/optimization/minimal-resource-deployment.md) for now.
- [ ] Build more advanced Kubernetes security labs beyond the current Falco/Kyverno baseline, including supply-chain attack scenarios and OPA Gatekeeper policies.
- [ ] Create a cross-lab scenario that connects the AD pentest lab with the DevOps lab’s exposed services.

## Not Planned

- Multi-cloud parity (AWS/Azure/GCP simultaneously): the labs are designed around local KVM/libvirt as the core experience, and cloud support would start with one provider, not several at once.
- Windows-based host support: the tooling assumes a Linux host with Vagrant, libvirt, and KVM, so this is unlikely to change.

---

Have an idea that is not listed here? Open an issue or start a discussion — see [`CONTRIBUTING.md`](CONTRIBUTING.md).