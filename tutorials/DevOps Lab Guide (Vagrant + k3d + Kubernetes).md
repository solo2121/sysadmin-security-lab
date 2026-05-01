

---

## Table of Contents

- [Overview](#overview)
- [Architecture Overview](#architecture-overview)
- [Resource Profiles (Scalable Execution)](#resource-profiles-scalable-execution)
- [Phase 0 — Environment Validation](#phase-0--environment-validation)
- [Phase 1 — Docker Fundamentals](#phase-1--docker-fundamentals)
- [Phase 2 — Kubernetes (k3d)](#phase-2--kubernetes-k3d)
- [Phase 3 — Helm](#phase-3--helm)
- [Phase 4 — Ansible](#phase-4--ansible)
- [Phase 5 — Terraform](#phase-5--terraform)
- [Phase 6 — DevSecOps](#phase-6--devsecops)
- [Phase 7 — Pipeline Simulation](#phase-7--pipeline-simulation)
- [Phase 8 — Kubernetes Debugging](#phase-8--kubernetes-debugging)
- [Phase 9 — Scaling and Rollouts](#phase-9--scaling-and-rollouts)
- [Phase 10 — Failure Testing (Chaos Engineering)](#phase-10--failure-testing-chaos-engineering)
- [Phase 11 — Observability (Prometheus + Grafana)](#phase-11--observability-prometheus--grafana)
- [Phase 12 — Secret Management (Sealed Secrets + SOPS)](#phase-12--secret-management-sealed-secrets--sops)
- [Phase 13 — Ingress Controller (NGINX)](#phase-13--ingress-controller-nginx)
- [Phase 14 — Backup and Restore (Velero)](#phase-14--backup-and-restore-velero)
- [Phase 15 — GitOps with ArgoCD (Bonus)](#phase-15--gitops-with-argocd-bonus)
- [Phase 16 — Full CI/CD with GitHub Actions + ArgoCD + Argo Rollouts](#phase-16--full-cicd-with-github-actions--argocd--argo-rollouts)
- [Bonus: Comprehensive Makefile](#bonus-comprehensive-makefile)
- [Full Reset / Cleanup](#full-reset--cleanup)
- [Final Best Practices & Troubleshooting](#final-best-practices--troubleshooting)

---

## Overview

This lab provides a full DevOps and DevSecOps environment using:

* Vagrant (multi-VM lab)
* Docker (container runtime)
* k3d (lightweight Kubernetes)
* kubectl (cluster management)
* Helm (application packaging)
* Ansible (configuration management)
* Terraform (infrastructure as code)
* Trivy, Checkov, Semgrep (security scanning)
* **Prometheus + Grafana (monitoring)**
* **Sealed Secrets / SOPS (secret management)**
* **Kyverno (policy enforcement)**
* **Chaos Mesh (failure testing)**

## Architecture Overview

```bash
[Vagrant VM: devops]
    ├── Docker
    ├── k3d (Kubernetes)
    │     ├── Namespaces: dev / staging / prod
    │     ├── Helm deployments
    │     ├── Ingress Controller
    │     ├── Observability (Prometheus/Grafana)
    │     ├── GitOps (ArgoCD)
    │     ├── Security (Trivy, Cosign, Kyverno)
    │     └── Chaos Engineering (Chaos Mesh)
    ├── Terraform
    └── Ansible
```

## Resource Profiles (Scalable Execution)

This lab is designed to run on different hardware setups.

**Baseline**  
* 4 CPU / 8 GB RAM  
  Run: Core Kubernetes, Docker, kubectl

**Standard**  
* 4–6 CPU / 12–16 GB RAM  
  Run: + Helm, Terraform, Ansible, DevSecOps tools

**Full Platform**  
* 8+ CPU / 16–32 GB RAM  
  Run: Full stack including Prometheus, ArgoCD, Chaos Mesh

**Recommended Workflow**  
`Core → Kubernetes → DevOps → Security → Observability → GitOps → Chaos`

---

## Phase 0 — Environment Validation

Start the lab:

```bash
vagrant up
vagrant ssh devops
```

Verify tools:

```bash
kubectl get nodes
docker ps
ansible --version
terraform version
# Additional checks for expanded lab
helm version
trivy --version
k3d version
```

Expected:

* Kubernetes node is Ready (k3d cluster named `devops-cluster`)
* Docker is running
* Ansible, Terraform, Helm, Trivy, k3d installed

**New: Create k3d cluster with registry and exposed ports**

```bash
k3d cluster create devops-cluster \
  --api-port 6443 \
  --servers 1 \
  --agents 2 \
  --port "8080:80@loadbalancer" \
  --port "8443:443@loadbalancer" \
  --k3s-arg "--disable=traefik@server:0"
```

This disables Traefik so you can install your own ingress later.

---

## Phase 1 — Docker Fundamentals

*Previous content remains.* **Add these:**

### Docker Networking

Create a custom network and attach the container:

```bash
docker network create devops-net
docker run -d --name devops-app --network devops-net -p 5000:5000 devops-app
docker network inspect devops-net
```

### Docker Volumes (Persistence)

```bash
docker volume create app-data
docker run -d --name devops-app -v app-data:/data devops-app
```

### Docker Compose (Local Stack)

Create `docker-compose.yaml`:

```yaml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - app-data:/data
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
volumes:
  app-data:
```

Start:

```bash
docker-compose up -d
docker-compose logs app
docker-compose down
```

---

## Phase 2 — Kubernetes (k3d)

*Previous imperative/declarative content remains.* **Add these:**

### Namespace Strategy

```bash
kubectl create namespace dev
kubectl create namespace staging
kubectl create namespace prod
```

### ConfigMap and Secret

```bash
# ConfigMap from literal
kubectl create configmap app-config --from-literal=APP_MODE=production -n dev

# Secret (base64 encoded - for demo only; see Phase 12 for real secrets)
kubectl create secret generic db-password --from-literal=password=supersecret -n dev
```

Consume in `deployment.yaml`:

```yaml
env:
- name: APP_MODE
  valueFrom:
    configMapKeyRef:
      name: app-config
      key: APP_MODE
- name: DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: db-password
      key: password
```

**Deployment Example**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: devops-app
  namespace: dev
spec:
  replicas: 2
  selector:
    matchLabels:
      app: devops-app
  template:
    metadata:
      labels:
        app: devops-app
    spec:
      containers:
      - name: app
        image: nginx:latest
        ports:
        - containerPort: 80
        env:
        - name: APP_MODE
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: APP_MODE
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-password
              key: password
```

Apply:

```bash
kubectl apply -f deployment.yaml
```

### Service Types Deep Dive

```bash
# ClusterIP (default)
kubectl expose deployment devops-app --type=ClusterIP --port=5000 --name=devops-clusterip

# NodePort (you already have)
kubectl expose deployment devops-app --type=NodePort --port=5000 --name=devops-nodeport

# LoadBalancer (k3d with metalLB)
kubectl expose deployment devops-app --type=LoadBalancer --port=5000 --name=devops-lb
```

For LoadBalancer to work with k3d, install MetalLB:

```bash
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.10/config/manifests/metallb-native.yaml
# Configure IP range (depends on your k3d network)
```

---

## Phase 3 — Helm

*Previous content remains.* **Add these:**

### Helm Values Overrides

Create `values-prod.yaml`:

```yaml
replicaCount: 3
image:
  tag: latest
service:
  type: LoadBalancer
ingress:
  enabled: true
  hosts:
    - devops-app.local
```

Install with override:

```bash
helm install devops-release ./mychart -f values-prod.yaml
```

### Helm Upgrade with Rollback

```bash
helm upgrade devops-release ./mychart --set replicaCount=5
helm history devops-release
helm rollback devops-release 1
```

### Helm Dependency Management

Add a dependency (e.g., PostgreSQL) to `Chart.yaml`:

```yaml
dependencies:
- name: postgresql
  version: "12.x.x"
  repository: "https://charts.bitnami.com/bitnami"
  condition: postgresql.enabled
```

Update:

```bash
helm dependency update
```

---

## Phase 4 — Ansible

*Previous inventory/ping/playbook remains.* **Add these:**

### Ansible Roles

Create a role for nginx:

```bash
ansible-galaxy role init nginx-role
```

Edit `nginx-role/tasks/main.yaml`:

```yaml
- name: Install nginx
  package:
    name: nginx
    state: present
- name: Start nginx
  service:
    name: nginx
    state: started
    enabled: yes
- name: Copy custom index.html
  copy:
    content: "Managed by Ansible on {{ ansible_hostname }}"
    dest: /usr/share/nginx/html/index.html
```

Use role in playbook:

```yaml
- hosts: web
  become: yes
  roles:
    - nginx-role
```

### Ansible Vault (Secrets)

```bash
ansible-vault create secrets.yml
# Add: db_password: "realsecret"
ansible-playbook -i inventory.ini nginx.yml --ask-vault-pass
```

### Dynamic Inventory (AWS example - optional)

```bash
ansible-inventory -i aws_ec2.yaml --list
```

---

## Phase 5 — Terraform

*Previous Docker provider example remains.* **Add these:**

### Terraform with Kubernetes Provider

```hcl
terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
  }
}

provider "kubernetes" {
  config_path = "~/.kube/config"
}

resource "kubernetes_namespace" "tf-namespace" {
  metadata {
    name = "terraform-managed"
  }
}

resource "kubernetes_deployment" "app" {
  metadata {
    name      = "terraform-app"
    namespace = kubernetes_namespace.tf-namespace.metadata[0].name
  }
  spec {
    replicas = 2
    selector {
      match_labels = {
        app = "MyApp"
      }
    }
    template {
      metadata {
        labels = {
          app = "MyApp"
        }
      }
      spec {
        container {
          image = "nginx:latest"
          name  = "nginx"
          port {
            container_port = 80
          }
        }
      }
    }
  }
}
```

Apply:

```bash
terraform plan
terraform apply -auto-approve
terraform destroy
```

### Terraform State Management (Backend)

```hcl
terraform {
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "devops-lab/terraform.tfstate"
    region = "us-east-1"
  }
}
```

---

## Phase 6 — DevSecOps

*Previous scanning (Trivy, Checkov, Semgrep) remains.* **Add these:**

### Image Signing (cosign)

Install cosign, then sign your image:

```bash
cosign generate-key-pair
cosign sign --key cosign.key devops-app:latest
cosign verify --key cosign.pub devops-app:latest
```

### Policy as Code (Kyverno)

Install Kyverno:

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno --namespace kyverno --create-namespace
```

Apply policy to require labels:

```yaml
# require-labels.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-labels
spec:
  validationFailureAction: Enforce
  rules:
  - name: require-app-label
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Label 'app' is required"
      pattern:
        metadata:
          labels:
            app: "?*"
```

Apply:

```bash
kubectl apply -f require-labels.yaml
```

Test failure:

```bash
kubectl run nginx --image=nginx  # Should be rejected
kubectl run nginx --labels app=demo --image=nginx  # Allowed
```

### Runtime Security (Falco - optional, resource heavy)

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco --namespace falco --create-namespace
```

---

## Phase 7 — Pipeline Simulation

*Previous workflow remains.* **Add these to the workflow:**

**Full CI Pipeline Script** (`pipeline.sh`):

```bash
#!/bin/bash
set -e

APP_NAME="devops-app"
VERSION=$(git rev-parse --short HEAD)

# Build
docker build -t $APP_NAME:$VERSION .

# Scan (fail on critical)
trivy image --severity CRITICAL --exit-code 1 $APP_NAME:$VERSION

# Sign
cosign sign --key cosign.key $APP_NAME:$VERSION

# Deploy to dev namespace
kubectl set image deployment/$APP_NAME app=$APP_NAME:$VERSION -n dev

# Wait for rollout
kubectl rollout status deployment/$APP_NAME -n dev --timeout=60s

# Smoke test
kubectl run test-pod --rm -i --restart=Never --image=curlimages/curl -- curl http://$APP_NAME.dev.svc.cluster.local:5000
```

---

## Phase 8 — Kubernetes Debugging

*Previous commands remain.* **Add these debugging techniques:**

### Ephemeral Debug Container

```bash
kubectl debug -it <pod> --image=busybox --target=app-container
```

### Port Forwarding for Local Access

```bash
kubectl port-forward service/devops-app 5000:5000 -n dev
curl localhost:5000
```

### Resource Usage

```bash
kubectl top pod
kubectl top node
```

### Events

```bash
kubectl get events --sort-by='.lastTimestamp'
```

---

## Phase 9 — Scaling and Rollouts

*Previous scaling/rollout remains.* **Add these:**

### HPA (Horizontal Pod Autoscaler) - requires metrics-server

Install metrics-server:

```bash
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
```

Create HPA:

```bash
kubectl autoscale deployment devops-app --cpu-percent=50 --min=2 --max=10
```

### Canary Deployment (using Flagger - optional)

```bash
helm repo add flagger https://flagger.app
helm install flagger flagger/flagger
```

---

## Phase 10 — Failure Testing (Chaos Engineering)

*Previous pod deletion remains.* **Add Chaos Mesh:**

Install Chaos Mesh:

```bash
helm repo add chaos-mesh https://charts.chaos-mesh.org
helm install chaos-mesh chaos-mesh/chaos-mesh --namespace chaos-mesh --create-namespace
```

Create a pod-kill chaos experiment:

```yaml
# pod-kill.yaml
apiVersion: chaos-mesh.org/v1alpha1
kind: PodChaos
metadata:
  name: pod-kill-example
spec:
  action: pod-kill
  mode: one
  selector:
    namespaces:
      - dev
    labelSelectors:
      app: devops
  scheduler:
    cron: "@every 5m"
```

Apply:

```bash
kubectl apply -f pod-kill.yaml
```

Watch recovery:

```bash
kubectl get pods -n dev -w
```

---

## Phase 11 — Observability (Prometheus + Grafana)

Install kube-prometheus-stack:

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace
```

Access Grafana (port-forward):

```bash
kubectl port-forward svc/prometheus-grafana 3000:80 -n monitoring
# Default login: admin/prom-operator
```

Add Prometheus datasource (if not auto-configured) and import dashboard `315` (Kubernetes cluster).

---

## Phase 12 — Secret Management (Sealed Secrets + SOPS)

Install Sealed Secrets controller:

```bash
helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
helm install sealed-secrets sealed-secrets/sealed-secrets --namespace kube-system
```

Install kubeseal CLI locally (on devops VM):

```bash
wget https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.24.5/kubeseal-0.24.5-linux-amd64.tar.gz
tar xzf kubeseal-*.tar.gz
sudo install -m 755 kubeseal /usr/local/bin/kubeseal
```

Create a secret and seal it:

```bash
kubectl create secret generic db-password --dry-run=client --from-literal=password=realprodpass -o yaml > secret.yaml
kubeseal --format yaml < secret.yaml > sealed-secret.yaml
# Now safely commit sealed-secret.yaml to git
kubectl apply -f sealed-secret.yaml
```

**SOPS Integration (Client-side Secret Management)**

Install SOPS and age:

```bash
# Install SOPS
wget https://github.com/getsops/sops/releases/download/v3.10.3/sops-v3.10.3.linux.amd64 -O sops
chmod +x sops
sudo mv sops /usr/local/bin/

# Install age (modern encryption tool)
wget https://github.com/FiloSottile/age/releases/download/v1.2.0/age-v1.2.0-linux-amd64.tar.gz
tar xzf age-v1.2.0-linux-amd64.tar.gz
sudo mv age/age /usr/local/bin/
sudo mv age/age-keygen /usr/local/bin/
```

Generate age key:

```bash
age-keygen -o ~/.config/sops/age/keys.txt
export SOPS_AGE_RECIPIENTS=$(age-keygen -y ~/.config/sops/age/keys.txt)
```

Encrypt a file with SOPS:

```bash
sops --encrypt --age $SOPS_AGE_RECIPIENTS secret.yaml > secret.enc.yaml
```

Decrypt:

```bash
sops --decrypt secret.enc.yaml
```

**When to use each:**
* **Sealed Secrets**: Best when you want the cluster to decrypt (good for ArgoCD)
* **SOPS**: Best for encrypting any file type before committing to Git (works great with Helm, Terraform, Ansible)

---

## Phase 13 — Ingress Controller (NGINX)

Install NGINX Ingress Controller:

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx \
  --create-namespace \
  --set controller.service.type=NodePort
```

Create an Ingress resource:

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: devops-ingress
  namespace: dev
spec:
  rules:
  - host: devops-app.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: devops-app
            port:
              number: 5000
```

Apply and test (add to /etc/hosts if needed):

```bash
kubectl apply -f ingress.yaml
curl -H "Host: devops-app.local" http://<node-ip>:<nodeport>
```

---

## Phase 14 — Backup and Restore (Velero)

Install Velero (requires object storage - use MinIO for lab):

```bash
velero install \
  --provider aws \
  --bucket velero-bucket \
  --secret-file ./credentials-velero \
  --backup-location-config region=us-east-1,s3ForcePathStyle="true",s3Url=http://minio.default.svc:9000 \
  --plugins velero/velero-plugin-for-aws:v1.0.0
```

Backup a namespace:

```bash
velero backup create dev-backup --include-namespaces dev
velero backup get
velero restore create --from-backup dev-backup
```

---

## Phase 15 — GitOps with ArgoCD (Bonus)

Install ArgoCD:

```bash
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

Get initial password:

```bash
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
```

Port-forward:

```bash
kubectl port-forward svc/argocd-server -n argocd 8443:443
```

Access UI at `https://localhost:8443`. Create an Application pointing to a Git repo containing your Kubernetes manifests.

---

## Phase 16 — Full CI/CD with GitHub Actions + ArgoCD + Argo Rollouts

**16.1 Repository Structure & GitHub Actions CI**  
(Use the full CI pipeline from the previous version — `.github/workflows/ci-cd.yml` with build, Trivy scan, cosign signing, and GitOps repo update using `yq`).

**Required GitHub Secrets:**
* `GITOPS_REPO`
* `GITOPS_PAT`
* `COSIGN_PRIVATE_KEY`
* `COSIGN_PASSWORD`

**16.2 ArgoCD Application Definition**  
(See previous Phase 16 for the `devops-app-dev.yaml` example)

**16.3 Advanced Deployments with Argo Rollouts (Canary / Blue-Green)**

Install Argo Rollouts:

```bash
kubectl create namespace argo-rollouts
kubectl apply -n argo-rollouts -f https://github.com/argoproj/argo-rollouts/releases/latest/download/install.yaml
```

Install Argo Rollouts Kubectl plugin:

```bash
curl -LO https://github.com/argoproj/argo-rollouts/releases/latest/download/kubectl-argo-rollouts_linux_amd64
chmod +x kubectl-argo-rollouts_linux_amd64
sudo mv kubectl-argo-rollouts_linux_amd64 /usr/local/bin/kubectl-argo-rollouts
```

Replace your Deployment with a Rollout resource in the GitOps repo (`apps/devops-app/dev/rollout.yaml`):

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: devops-app
  namespace: dev
spec:
  replicas: 5
  selector:
    matchLabels:
      app: devops-app
  template:
    metadata:
      labels:
        app: devops-app
    spec:
      containers:
      - name: app
        image: ghcr.io/yourusername/devops-app:latest
        ports:
        - containerPort: 5000
  strategy:
    canary:
      steps:
      - setWeight: 20
      - pause: { duration: 30s }
      - setWeight: 40
      - pause: { duration: 1m }
      - setWeight: 60
      - pause: { duration: 2m }
      - setWeight: 100
```

Apply the Rollout via ArgoCD and promote it:

```bash
kubectl argo rollouts get rollout devops-app -n dev --watch
kubectl argo rollouts promote devops-app -n dev
kubectl argo rollouts abort devops-app -n dev   # Emergency rollback
```

**Blue-Green Strategy Example:**

```yaml
strategy:
  blueGreen:
    activeService: devops-app-active
    previewService: devops-app-preview
    autoPromotionEnabled: false
```

**16.4 ArgoCD CLI Commands**

```bash
argocd app list
argocd app get devops-app-dev --show-params
argocd app sync devops-app-dev
argocd app history devops-app-dev
```

---

## Bonus: Comprehensive Makefile

Create `Makefile` in the root of your lab directory:

```makefile
.PHONY: help cluster up down clean validate deploy-dev deploy-staging observability chaos test ci-help

help:
	@echo "DevOps Lab Management Commands"
	@echo "=============================="
	@echo "make cluster      - Create k3d cluster"
	@echo "make up           - Start Vagrant VM"
	@echo "make deploy-dev   - Deploy app to dev namespace"
	@echo "make observability- Install Prometheus + Grafana"
	@echo "make chaos        - Run Chaos Mesh experiment"
	@echo "make clean        - Clean up resources"

cluster:
	k3d cluster create devops-cluster \
		--api-port 6443 \
		--servers 1 \
		--agents 2 \
		--port "8080:80@loadbalancer" \
		--port "8443:443@loadbalancer" \
		--k3s-arg "--disable=traefik@server:0" \
		--registry-create devops-registry:0.0.0.0:5000

up:
	vagrant up && vagrant ssh devops

down:
	k3d cluster delete devops-cluster || true
	vagrant halt

deploy-dev:
	helm upgrade --install devops-app ./mychart \
		-f values-dev.yaml \
		--namespace dev --create-namespace

deploy-staging:
	helm upgrade --install devops-app ./mychart \
		-f values-staging.yaml \
		--namespace staging --create-namespace

observability:
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
	helm install prometheus prometheus-community/kube-prometheus-stack \
		--namespace monitoring --create-namespace

chaos:
	kubectl apply -f chaos/pod-kill.yaml

validate:
	kubectl get pods -A
	kubectl get svc -A
	kubectl top nodes || echo "Metrics server not installed"

clean:
	kubectl delete ns dev staging prod monitoring ingress-nginx kyverno chaos-mesh argo-rollouts argocd --ignore-not-found=true
	helm ls --all-namespaces | tail -n +2 | awk '{print $1 " " $2}' | xargs -r -L1 helm uninstall -n

ci-help:
	@echo "Push to main branch to trigger GitHub Actions CI/CD"
	@echo "Monitor ArgoCD at https://localhost:8443"
```

Run with:

```bash
make help
make cluster
make deploy-dev
make observability
```

---

## Full Reset / Cleanup

```bash
k3d cluster delete devops-cluster || true
docker system prune -af
vagrant destroy -f
vagrant up
```

## Final Best Practices & Troubleshooting

* Apply components incrementally
* Monitor resources:

```bash
kubectl top nodes
kubectl top pods
```

* Use Sealed Secrets or SOPS for Git-safe secrets
* Enforce Kyverno policies early
* Use Argo Rollouts for controlled deployments
* Avoid running all heavy components simultaneously unless resources allow

---
