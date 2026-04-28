
## 1. Overview

This is a **complete production-style DevOps platform** combining:

- **Terraform** → Infrastructure provisioning
    
- **Ansible** → Configuration management
    
- **Kubernetes (kubeadm)** → Container orchestration
    
- **Helm** → Application packaging
    
- **ArgoCD** → GitOps continuous delivery
    
- **Prometheus + Grafana + Loki** → Observability
    

---

## 2. Architecture

```text
                ┌───────────────┐
                │   Developer   │
                └──────┬────────┘
                       │ git push
                       ▼
                ┌───────────────┐
                │    Git Repo   │
                └──────┬────────┘
                       │
                ┌──────▼────────┐
                │   ArgoCD      │
                │  (GitOps)     │
                └──────┬────────┘
                       ▼
              ┌──────────────────┐
              │  Kubernetes      │
              │  Cluster         │
              └──────────────────┘
                       ▲
                       │
            ┌──────────┴──────────┐
            │       Ansible        │
            │  Config + Setup      │
            └──────────┬──────────┘
                       ▲
                       │
                ┌──────┴───────┐
                │  Terraform   │
                │ Provisioning │
                └──────────────┘
```

---

## 3. Project Structure

```text
devops-platform/
├── terraform/
├── ansible/
├── k8s-manifests/
├── helm-charts/
├── argocd/
├── monitoring/
└── README.md
```

---

# PART 1 — TERRAFORM (Infrastructure Layer)

## 4. Terraform Goal

Provision:

- Virtual machines (or cloud instances)
    
- Networking
    
- Base infrastructure
    

---

## 5. Example: Local Libvirt (KVM) Terraform

### terraform/main.tf

```hcl
provider "libvirt" {
  uri = "qemu:///system"
}

resource "libvirt_domain" "k8s_node" {
  count  = 3
  name   = "k8s-node-${count.index}"
  memory = 2048
  vcpu   = 2

  disk {
    volume_id = libvirt_volume.node_disk[count.index].id
  }

  network_interface {
    network_name = "default"
  }
}

resource "libvirt_volume" "node_disk" {
  count  = 3
  name   = "node-${count.index}.qcow2"
  size   = 20 * 1024 * 1024 * 1024
}
```

---

## 6. Run Terraform

```bash
terraform init
terraform apply
```

---

# PART 2 — ANSIBLE (Configuration Layer)

## 7. Role Responsibilities

- Install container runtime
    
- Install Kubernetes components
    
- Configure OS
    
- Bootstrap cluster
    

---

## 8. Ansible Flow

```text
Provision → Configure → Bootstrap → Deploy
```

---

## 9. Run Ansible

```bash
ansible-playbook playbooks/site.yml
```

---

# PART 3 — KUBERNETES (Runtime Layer)

## 10. Cluster Setup Recap

- kubeadm init (control plane)
    
- kubeadm join (workers)
    
- Install CNI (Calico)
    

---

## 11. Namespaces Strategy

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: dev
```

---

# PART 4 — HELM (Application Packaging)

## 12. Helm Chart Structure

```text
helm-charts/myapp/
├── Chart.yaml
├── values.yaml
└── templates/
```

---

## 13. Example Deployment Template

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: app
          image: nginx
```

---

## 14. Install Helm Chart

```bash
helm install myapp ./helm-charts/myapp
```

---

# PART 5 — ARGOCD (GitOps Layer)

## 15. Install ArgoCD

```bash
kubectl create namespace argocd

kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

---

## 16. Access ArgoCD

```bash
kubectl port-forward svc/argocd-server -n argocd 8080:443
```

---

## 17. Create Application

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: myapp
spec:
  source:
    repoURL: https://github.com/yourrepo/app.git
    targetRevision: HEAD
    path: helm-chart
  destination:
    server: https://kubernetes.default.svc
    namespace: default
  syncPolicy:
    automated: {}
```

---

## 18. GitOps Workflow

```text
1. Developer pushes code
2. Git updates
3. ArgoCD detects change
4. Syncs automatically
5. Kubernetes updates app
```

---

# PART 6 — MONITORING STACK

## 19. Install Prometheus Stack

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts

helm install monitoring prometheus-community/kube-prometheus-stack
```

---

## 20. Components

- Prometheus → metrics collection
    
- Grafana → visualization
    
- Alertmanager → alerts
    

---

## 21. Access Grafana

```bash
kubectl port-forward svc/monitoring-grafana 3000:80
```

---

## 22. Install Loki (Logging)

```bash
helm repo add grafana https://grafana.github.io/helm-charts

helm install loki grafana/loki-stack
```

---

# PART 7 — CI/CD PIPELINE

## 23. Example GitHub Actions

```yaml
name: Deploy Platform

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Terraform Apply
        run: |
          cd terraform
          terraform init
          terraform apply -auto-approve

      - name: Run Ansible
        run: |
          cd ansible
          ansible-playbook playbooks/site.yml
```

---

# PART 8 — SECURITY

## 24. Secrets Management

- Use Kubernetes Secrets
    
- Use Ansible Vault
    
- Avoid plaintext credentials
    

---

## 25. RBAC Example

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: dev-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
```

---

# PART 9 — SCALING & PRODUCTION

## 26. Horizontal Scaling

```bash
kubectl scale deployment myapp --replicas=5
```

---

## 27. High Availability

- Multiple control planes
    
- External etcd
    
- Load balancer
    

---

## 28. Storage

- NFS
    
- Ceph
    
- Longhorn
    

---

# PART 10 — COMPLETE WORKFLOW

## 29. End-to-End Flow

```text
1. Terraform provisions infrastructure
2. Ansible configures systems
3. Kubernetes cluster initialized
4. Helm deploys applications
5. ArgoCD manages GitOps
6. Monitoring stack observes system
```

---

## 30. Final Result

You now have:

- Full Infrastructure as Code
    
- Automated configuration
    
- Production-ready Kubernetes cluster
    
- GitOps continuous delivery
    
- Observability stack
    

---

## 31. Next-Level Enhancements

- Service Mesh (Istio / Linkerd)
    
- Policy enforcement (OPA Gatekeeper)
    
- Chaos engineering (Litmus)
    
- Blue/Green deployments
    
- Multi-cluster federation
    

---

## 32. Closing Notes

This stack represents a **real-world DevOps platform** used in modern environments.  
Each layer is modular and can scale independently.

---