
---

### 1. System Architecture

**Host Machine** → Vagrant (libvirt) → **devops-1** (Ubuntu 24.04)

**Core Stack:**

| Layer                  | Component                    | Purpose |
|------------------------|------------------------------|--------|
| Build                  | Docker Engine                | Image building & testing |
| Runtime                | K3s + containerd             | Kubernetes cluster |
| CLI                    | kubectl, Helm, k9s, Trivy    | Operations & productivity |
| GitOps                 | Argo CD                      | Continuous deployment |
| Observability          | Prometheus + Grafana         | Monitoring & dashboards |
| Policy as Code         | Kyverno                      | Security & compliance |
| Runtime Security       | Falco                        | Threat detection |

**Nodes**: `devops-1` (control plane), `worker-1`, `worker-2`

---

### 2. Lab Access & Verification

```bash
vagrant ssh devops-1
source /etc/profile.d/99-kubeconfig.sh
alias k=kubectl
```

**Verification:**

```bash
k get nodes -o wide
k get pods -A
k cluster-info
k9s                    # Launch Kubernetes Terminal UI
```

---

### 3. GitOps Repository Structure (`gitops-lab`)

Use the full structure provided in previous responses (root-gitops.yaml, nginx-app.yaml, Kustomize base, etc.).

---

### 4. DevOps Examples & Practices

#### 4.1 CI/CD Simulation with GitOps

**Full Development-to-Production Workflow:**

```bash
# 1. Build new version locally
docker build -t myapp:v2.5 .

# 2. Security scan
trivy image --severity HIGH,CRITICAL myapp:v2.5

# 3. Update image tag in Git (deployment.yaml)
git add apps/base/nginx/deployment.yaml
git commit -m "feat: upgrade nginx to v2.5"
git push origin main

# 4. Argo CD automatically detects change and deploys
```

**Monitor rollout:**

```bash
k get app nginx-app -n argocd -w
k rollout status deployment/nginx -n default
k9s                    # Use k9s for visual monitoring
```

#### 4.2 Blue-Green & Canary Deployments
(Refer to previous detailed examples)

---

### 5. Configuration Management

Use **Kustomize overlays** for environment-specific configurations (dev/staging/prod).

**Example `environments/dev/kustomization.yaml`:**

```yaml
bases:
  - ../../apps/base/nginx

patches:
- patch: |-
    - op: replace
      path: /spec/replicas
      value: 3
  target:
    kind: Deployment
```

---

### 6. Helm Charts in DevOps Workflow

Helm is pre-installed with common repositories:

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Example
helm install redis bitnami/redis \
  --namespace dev \
  --create-namespace \
  -f values/redis-dev.yaml
```

**Best Practice**: Store Helm values in Git and manage releases via Argo CD.

---

### 7. Rich Offline Image Cache

The lab now includes a comprehensive set of modern DevSecOps images:

- Core: `alpine`, `nginx:alpine`, `redis`, `postgres`, `node`, `python`
- Monitoring: `prometheus`, `grafana`, `node-exporter`
- Security: `trivy`, `vault`
- GitOps: `argocd`
- Infrastructure: `registry:2`, `minio`, `rabbitmq`, `mongo`, `traefik`, `kafka`, `jenkins`, `sonarqube`

Use these for air-gap / offline exercises.

---

### 8. Developer Productivity Tools

**k9s** – Kubernetes Terminal UI (highly recommended)

```bash
k9s                    # Main interface
k9s -n argocd          # Specific namespace
```

**Useful k9s shortcuts:**
- `:` → Resource type (pods, deployments, svc, etc.)
- `ctrl+d` → Delete resource
- `l` → Logs
- `s` → Shell into pod

---

### 9. Observability & Alerting

**Access:**
- Grafana: `http://127.0.0.1:32000`
- Prometheus: `http://127.0.0.1:32001`

**Commands:**

```bash
k top nodes
k top pods -A
k get servicemonitors -A
```

---

### 10. Logging & Troubleshooting

```bash
k logs deployment/nginx -n default --tail=100
stern nginx                # Multi-pod log tailing (if stern is added later)
journalctl -u k3s -f
k get events -A --sort-by=.metadata.creationTimestamp -w
```

---

### 11. Rollback Procedures

**Kubernetes native:**

```bash
k rollout undo deployment/nginx -n default
```

**GitOps rollback:**

- Revert the commit in Git → Argo CD will automatically reconcile to the previous version.

---

### 12. Professional Debugging Workflow

```bash
# 1. Cluster Health
k get nodes
k get pods -A --field-selector=status.phase!=Running

# 2. Workload Status
k get deployments,sts,ds,svc,ing -A
k describe deployment nginx

# 3. Deep Analysis
k logs <pod-name> -c <container> --tail=200
k get events -A --sort-by=.metadata.creationTimestamp

# 4. Visual + Runtime
k9s                    # Best visual overview
sudo crictl ps -a
sudo crictl images
```

---

### 13. Common Issues & Fixes

| Issue                        | Cause                          | Solution |
|-----------------------------|--------------------------------|----------|
| localhost:8080              | Missing KUBECONFIG             | Source profile script |
| ImagePullBackOff            | Image not in containerd        | Use pre-pulled images |
| No endpoints                | Selector mismatch              | Fix labels |
| Argo CD sync failure        | Wrong repoURL / path           | Verify Git structure |

---

### 14. Production Mental Model

1. **Develop** – Local Docker builds + testing
2. **Secure** – Trivy scanning + Kyverno policies
3. **Package** – Kustomize or Helm
4. **Commit** – Git as single source of truth
5. **Deploy** – Argo CD automated reconciliation
6. **Observe** – Prometheus + Grafana + k9s
7. **Protect** – Falco runtime security
8. **Iterate** – Continuous improvement

---

