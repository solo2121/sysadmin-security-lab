# Complete Git Tutorial (Revised and Corrected)

*Includes .gitconfig/.gitignore management and troubleshooting*

---

## Table of Contents

1. Introduction to Git
2. Installing Git
3. Configuring Git (Updated with file management)
4. Basic Git Commands
5. Branching and Merging
6. Remote Repositories
7. Collaboration Workflows
8. Advanced Topics
9. Git Best Practices (Updated)

---

## 1. Introduction to Git

Git is a distributed version control system used to track changes in code and collaborate with others.

**Key Concepts:**

* Repository (repo)
* Commit
* Branch
* Merge
* Remote

---

## 2. Installing Git

### Linux (Debian/Ubuntu)

```bash
sudo apt update && sudo apt install git -y
```

### macOS

```bash
brew install git
```

### Windows

Download from: [https://git-scm.com/](https://git-scm.com/)

---

## 3. Configuring Git (Updated)

### A. Set Your Identity

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

**Verify:**

```bash
git config --global --list
```

---

### B. Managing Git Files

#### 1. Remove Accidental Commits (`.gitconfig`)

If `.gitconfig` was mistakenly tracked:

```bash
# Remove from Git (but keep locally):
git rm --cached .gitconfig

# Commit the change:
git commit -m "Remove .gitconfig from tracking"
```

#### 2. Prevent Future Tracking

**Option A (Shared `.gitignore`):**

```bash
echo ".gitconfig" >> .gitignore
git add .gitignore
git commit -m "Update .gitignore"
```

**Option B (Recommended – Local Only):**

```bash
echo ".gitconfig" >> .git/info/exclude
```

---

#### 3. When to Track/Ignore

| File         | Track in Repo? | Reason                          |
| ------------ | -------------- | ------------------------------- |
| `.gitconfig` | No             | Contains user-specific settings |
| `.gitignore` | Yes            | Share ignore rules with team    |

---

### C. Troubleshooting

#### Issue 1: Git Config Not Persisting

If settings disappear after reboot:

```bash
# Check if ~/.gitconfig exists:
ls -la ~/.gitconfig

# Force-set config path:
export GIT_CONFIG_GLOBAL="$HOME/.gitconfig"
git config --global user.name "Your Name"
```

Additionally, verify configuration sources:

```bash
git config --list --show-origin
```

---

#### Issue 2: Locked Config File

```bash
error: could not lock config file /path/to/.gitconfig
```

**Fix:**

```bash
# Recreate the file:
touch ~/.gitconfig

# Fix permissions:
chmod 600 ~/.gitconfig

# Ensure correct ownership:
chown $USER:$USER ~/.gitconfig
```

---

#### Issue 3: Sensitive Data Already Committed

Removing a file does not remove it from Git history.

To fully remove it:

```bash
git filter-repo
```

(or `git filter-branch` for older setups)

---

## 4. Basic Git Commands

### Initialize Repo

```bash
git init
```

### Clone Repo

```bash
git clone <repo-url>
```

### Check Status

```bash
git status
```

### Add Files

```bash
git add file.txt
git add .
```

### Commit

```bash
git commit -m "Your message"
```

### View History

```bash
git log --oneline --graph
```

---

## 5. Branching and Merging

### Create Branch

```bash
git branch feature-x
```

### Switch Branch

```bash
git checkout feature-x
```

### Create and Switch

```bash
git checkout -b feature-x
```

### Merge

```bash
git checkout main
git merge feature-x
```

---

## 6. Remote Repositories

### Add Remote

```bash
git remote add origin <url>
```

### Push

```bash
git push -u origin main
```

### Pull

```bash
git pull origin main
```

### Fetch

```bash
git fetch
```

---

## 7. Collaboration Workflows

### A. Feature Branch Workflow

1. Create branch
2. Work and commit
3. Push branch
4. Open Pull Request
5. Merge into main

---

### B. Fork Workflow

1. Fork repository
2. Clone your fork
3. Add upstream:

```bash
git remote add upstream <original-repo>
```

4. Sync changes:

```bash
git pull upstream main
```

---

## 8. Advanced Topics

### Stashing

```bash
git stash
git stash pop
```

### Rebase

```bash
git rebase main
```

### Reset

```bash
git reset --soft HEAD~1
git reset --hard HEAD~1
```

---

## 9. Git Best Practices (Updated)

### A. Never Commit

* `.gitconfig` (personal settings)
* Secrets (`.env`, `id_rsa`, `*.key`)

---

### B. Always Track

* `.gitignore` (team-wide rules)
* `README.md` (project documentation)

---

### C. Sample `.gitignore`

```gitignore
# OS files  
.DS_Store  

# IDE files  
.idea/  
.vscode/  

# Dependencies  
node_modules/  
*.class  

# Logs  
*.log  

# Environment  
.env  

# Optional personal  
.gitconfig  
```

---

### Key Updates

* Corrected handling of `.gitignore` (no longer removed from tracking)
* Clarified `.gitconfig` removal and prevention methods
* Added local exclude option for cleaner repositories
* Expanded troubleshooting with configuration debugging and permission fixes

---

### Final Notes

* Use `git rm --cached` to untrack files without deleting them locally
* Prefer `.git/info/exclude` for personal ignore rules
* Global Git config lives in `~/.gitconfig` (Linux/macOS) or `%UserProfile%\.gitconfig` (Windows)
* Git history is persistent; removing files does not erase past commits without rewriting history

---
