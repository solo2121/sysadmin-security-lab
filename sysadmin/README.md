# System Administration Tooling

This directory contains Linux administration scripts for maintenance, monitoring, hardening, Git workflow support, and general workstation/server utilities. These scripts are intended to demonstrate practical day-2 operations skills alongside the larger lab environments in this repository.

---

## Directory Map

| Directory | Contents |
|-----------|----------|
| [`automation/`](automation/) | System update, Rhino Linux, and Pacstall maintenance helpers |
| [`monitoring/`](monitoring/) | System monitor, security monitor, and log analyzer scripts |
| [`system-hardening/`](system-hardening/) | Linux audit, user audit, network audit, ClamAV, and rootkit scan helpers |
| [`utilities/`](utilities/) | Timeshift, UFW, BIND, memory cleanup, and subtitle-removal utilities |

---

## Portfolio Highlights

- Bash and Python scripts for common Linux administration workflows.
- Security-focused audit and hardening helpers.
- Monitoring scripts that show log and host-health awareness.
- Practical utilities that reflect real workstation and server maintenance tasks.

---

## Example Usage

Review scripts before running them, then execute from the repository root or the script directory as appropriate:

```bash
cd sysadmin/monitoring
./system-monitor.sh
```

```bash
cd sysadmin/system-hardening
./network_audit.sh
```

Some scripts may require elevated privileges because they inspect logs, packages, firewall state, users, or system services.

---

## Operating Guidelines

- Run audit scripts before hardening changes so you have a baseline.
- Use least privilege where possible; only use `sudo` when a script requires it.
- Read script output before applying remediation steps.
- Test changes in a VM before applying them to a production workstation or server.
- Keep backups before making firewall, user, or package-management changes.

---

## Related Documentation

- [`../INSTALLATION.md`](../INSTALLATION.md)
- [`../TROUBLESHOOTING.md`](../TROUBLESHOOTING.md)
- [`../docs/WORKFLOWS.md`](../docs/WORKFLOWS.md)
- [`../docs/SECURITY-SCOPE.md`](../docs/SECURITY-SCOPE.md)
