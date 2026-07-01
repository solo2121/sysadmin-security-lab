# Roadmap

This is a working list of planned improvements, not a commitment with
dates. Priorities shift based on what's most useful to work on next.
Suggestions and PRs against any of these are welcome — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).

For a running log of what's already shipped, see
[`CHANGELOG.md`](CHANGELOG.md).

## Near-term

- [ ] Live demo recording (asciinema/GIF) embedded in the README showing
      `vagrant up` bring-up and an AD attack chain executing
- [ ] Expand automated test coverage to more of `sysadmin/` and `security/`
      scripts (currently: `log-analyzer.sh`, `setup-vlans.sh`,
      `port-scanner.py`)
- [ ] GitHub Discussions enabled for Q&A / feature requests (templates in
      `.github/DISCUSSION_TEMPLATE/`)

## Mid-term

- [ ] Additional AD CS attack scenarios beyond the current ESC1/ESC8
      coverage
- [ ] Ansible role automation for repeatable DevOps lab provisioning
      (currently manual/scripted via Vagrant provisioners)
- [ ] Windows Server hardening lab, as a defensive counterpart to the
      AD pentest lab's offensive content
- [ ] Expand the VLAN lab's segmentation scenarios (currently 5 VLANs;
      exploring more realistic enterprise zoning)

## Long-term / exploratory

- [ ] Optional cloud deployment path (Terraform module) for either lab,
      as an alternative to local libvirt — useful for people without a
      capable local host; see
      [`docs/optimization/minimal-resource-deployment.md`](docs/optimization/minimal-resource-deployment.md)
      in the meantime
- [ ] Advanced Kubernetes security labs beyond the current
      Falco/Kyverno baseline (e.g. supply-chain attack scenarios, OPA
      Gatekeeper policies)
- [ ] Cross-lab scenario: a single exercise that spans both the AD
      pentest lab and the DevOps lab's exposed services

## Not planned

- Multi-cloud parity (AWS/Azure/GCP simultaneously) — the labs are
  designed around local KVM/libvirt as the core experience; cloud
  support (if it happens) will start with one provider, not several
  at once.
- Windows-based host support — the tooling (Vagrant + libvirt + KVM)
  assumes a Linux host; this isn't likely to change.

---

Have an idea that's not listed here? Open an issue or start a
discussion — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for how.
