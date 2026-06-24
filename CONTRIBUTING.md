# Contribution Guidelines

Welcome to the Sysadmin Security Lab contribution guide.
We appreciate your interest in helping improve this project.

---

## Table of Contents

- [Ways to Contribute](#ways-to-contribute)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Pull Request Process](#pull-request-process)
- [Local Setup](#local-setup)
- [Community Guidelines](#community-guidelines)

---

## Ways to Contribute

### Issue Reporting

- **Bug Reports**
  Use the [bug report template](https://github.com/solo2121/sysadmin-security-lab/issues/new?template=bug_report.md)

- **Feature Requests**
  Use the [feature request template](https://github.com/solo2121/sysadmin-security-lab/issues/new?template=feature_request.md)

- **Documentation Improvements**
  Open a regular issue with the `[Docs]` prefix in the title.

### Code Contributions

Professional contributions must follow the Feature Branch Workflow. Direct pushes to the `main` branch are discouraged to ensure repository stability.

1. **Branch:** Create a descriptive branch from `main`:
   - `feat/feature-name` — New functionality
   - `fix/issue-description` — Bug fixes
   - `docs/update-description` — Documentation improvements
2. **Develop:** Apply changes and verify locally.
3. **Commit:** Use conventional commit messages (`type(scope): description`).
4. **Push:** Push the branch to your remote.
5. **Review:** Open a Pull Request (PR) against the `main` branch.
6. **Merge:** Once validated, merge the PR and delete the feature branch.

---

## Development Workflow

### Pre-Commit Checks

Before committing, run the following linters manually to keep code clean:

```bash
# Shell scripts
shellcheck path/to/script.sh

# Python scripts
pylint path/to/script.py

# Vagrant syntax check
vagrant validate
```

These checks ensure all scripts are clean before they reach the repository.

---

## Code Standards

### Shell Script Guidelines

```bash
#!/usr/bin/env bash
```

- Scripts must pass `shellcheck` validation.
- Include a header comment block in each script:

```bash
#!/usr/bin/env bash
#
# Script Name: example.sh
# Description: Brief description of script functionality
# Author: Your Name
# Usage: ./example.sh [options]
#
```

### Python Script Guidelines

- Scripts must pass `pylint` with no errors.
- Use type hints where practical.
- Include a module-level docstring explaining purpose, usage, and author.

### Naming Conventions

- All filenames use kebab-case: `my-script.sh`, `my-tool.py`
- No spaces in filenames
- No uppercase letters in filenames

### Dependency Management

- Limit external dependencies to 3 or fewer per script.
- Document all requirements in script headers and in a `requirements.txt` if the script is part of a lab.

---

## Pull Request Process

### PR Checklist

- [ ] All scripts pass linting (`shellcheck` for Bash, `pylint` for Python)
- [ ] Tested locally in a VM or lab environment
- [ ] Documentation updated to reflect changes
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Follows existing code style and naming conventions
- [ ] No secrets, credentials, or personal data committed

### Commit Message Format

```
type(scope): brief description

Optional body explaining changes in detail
```

**Common Types:**
`feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

**Examples:**
```
feat(ad-pentest): add ESC8 relay automation script
fix(devops-lab): correct K3s worker join token path
docs(readme): update repository structure diagram
```

---

## Local Setup

1. Clone the repository:

```bash
git clone https://github.com/solo2121/sysadmin-security-lab.git
cd sysadmin-security-lab
```

2. Install development Python dependencies:

```bash
pip install -r requirements-dev.txt  # (e.g., pylint)
```

3. Install shellcheck for shell script linting:

```bash
sudo apt install shellcheck     # Debian/Ubuntu
sudo dnf install shellcheck     # Rocky/Fedora
```

4. Validate Vagrantfiles before submitting changes:

```bash
cd labs/security/ad-pentest && vagrant validate
cd labs/security/ad-pentest-vlan && vagrant validate
cd labs/infrastructure/devops-linux-lab && vagrant validate
```

---

## Community Guidelines

Please review:

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)
- [Security Scope](docs/architecture/SECURITY-SCOPE.md)

For questions or discussions, visit our [GitHub Discussions](https://github.com/solo2121/sysadmin-security-lab/discussions).

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
