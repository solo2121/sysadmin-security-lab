````markdown
# Contribution Guidelines

Welcome to the Security & System Administration Toolkit contribution guide.  
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
  Use the [bug report template](https://github.com/solo2121/sysadmin-security-scripts/issues/new?template=bug_report.md)

- **Feature Requests**  
  Use the [feature request template](https://github.com/solo2121/sysadmin-security-scripts/issues/new?template=feature_request.md)

- **Documentation Improvements**  
  Open a regular issue with the `[Docs]` prefix in the title.

### Code Contributions

1. Fork the repository
2. Create a descriptive branch name:
   - `feat/` for new features
   - `fix/` for bug fixes
   - `docs/` for documentation updates
3. Commit your changes
4. Push to your fork
5. Open a pull request

---

## Development Workflow

### Pre-Commit Checks

We recommend setting up the pre-commit hook:

```bash
ln -sf ../../scripts/pre-commit.sh .git/hooks/pre-commit
```
````

This ensures all scripts are automatically linted before committing.

---

## Code Standards

### Shell Script Guidelines

```bash
#!/usr/bin/env bash
# [Optional] For POSIX compliance: #!/usr/bin/env sh
```

- Scripts must pass all `shellcheck` validations.
- Include detailed header comments in each script:

```bash
#!/usr/bin/env bash
#
# Script Name: example.sh
# Description: Brief description of script functionality
# Author: Your Name
# Usage: ./example.sh [options]
#
```

### Dependency Management

- Limit external dependencies to ≤3 per script.
- Document all requirements in script headers.

---

## Pull Request Process

### PR Checklist

- [ ] All scripts pass linting (`shellcheck` / `pylint` if Python)
- [ ] Tested on multiple platforms
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Follows existing code style

### Commit Message Format

```
type(scope): brief description

Optional body explaining changes in detail
```

**Common Types**:
`feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

---

## Local Setup

1. Clone the repository:

```bash
git clone https://github.com/solo2121/sysadmin-security-scripts.git
cd sysadmin-security-scripts
```

2. Install development dependencies:

```bash
./scripts/setup-dev-env.sh
```

---

## Community Guidelines

Please review:

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)

For questions or discussions, visit our [Discussions](https://github.com/solo2121/sysadmin-security-scripts/discussions).

```

```
