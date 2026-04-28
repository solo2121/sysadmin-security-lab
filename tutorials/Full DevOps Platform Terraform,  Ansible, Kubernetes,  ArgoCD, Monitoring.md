
---

# Full DevOps Platform: Vagrant/KVM + Terraform + Ansible + Kubernetes + ArgoCD + Monitoring

---

## 1. Overview

This is a **complete production-style DevOps platform** combining:

* **Vagrant + KVM (libvirt)** → Virtual machine infrastructure layer
* **Terraform** → Infrastructure provisioning
* **Ansible** → Configuration management
* **Kubernetes (kubeadm)** → Container orchestration
* **Helm** → Application packaging
* **ArgoCD** → GitOps continuous delivery
* **Prometheus + Grafana + Loki** → Observability

---

# 2. Architecture

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
              └──────┬───────────┘
                     │
            ┌────────▼──────────┐
            │      Ansible       │
            │ Config + Bootstrap │
            └────────┬──────────┘
                     │
            ┌────────▼──────────┐
            │  Vagrant + KVM    │
            │ VM Infrastructure │
            └────────┬──────────┘
                     │
            ┌────────▼──────────┐
            │   Terraform       │
            │ Provisioning (opt)│
            └───────────────────┘
```

---

# 3. Project Structure

```text
devops-platform/
├── vagrant/
├── terraform/
├── ansible/
├── k8s-manifests/
├── helm-charts/
├── argocd/
├── monitoring/
└── README.md
```

---

# PART 0 — VAGRANT + KVM (INFRASTRUCTURE LAYER)

## 0.1 Role

This layer creates the **base virtual infrastructure**:

* Kubernetes control plane node
* Worker nodes
* Local reproducible lab using KVM

---

## 0.2 Requirements

* KVM enabled
* libvirt installed
* Vagrant installed
* vagrant-libvirt plugin

---

## 0.3 Install Plugin

```bash
vagrant plugin install vagrant-libvirt
```

---

## 0.4 VM Topology

```text
control  → Kubernetes control plane
worker1  → Kubernetes worker node
worker2  → Kubernetes worker node
```

---

## 0.5 Vagrantfile (KVM / Libvirt)

```ruby
ENV['VAGRANT_DEFAULT_PROVIDER'] = 'libvirt'

Vagrant.configure("2") do |config|

  config.vm.box = "generic/ubuntu2204"

  nodes = {
    "control" => "192.168.121.10",
    "worker1" => "192.168.121.11",
    "worker2" => "192.168.121.12"
  }

  nodes.each do |name, ip|
    config.vm.define name do |node|
      node.vm.hostname = name

      node.vm.network :private_network,
        ip: ip,
        libvirt__network_name: "default"

      node.vm.provider :libvirt do |lv|
        lv.memory = name == "control" ? 4096 : 2048
        lv.cpus = 2
        lv.cpu_mode = "host-passthrough"
      end

      node.vm.provision "shell", inline: <<-SHELL
        apt update
        apt install -y python3 python3-pip curl
      SHELL
    end
  end
end
```

---

## 0.6 Start Infrastructure

```bash
vagrant up --provider=libvirt
```

---

# PART 1 — TERRAFORM (Infrastructure Layer)

## 4. Terraform Goal

* Virtual machines (or cloud instances)
* Networking
* Base infrastructure

---

## 5. Example (Libvirt)

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

# PART 2 — ANSIBLE (CONFIGURATION LAYER)

## 7. Role Responsibilities

* Install container runtime
* Install Kubernetes components
* Configure OS
* Bootstrap cluster

---

## 8. Flow

```text
Provision → Configure → Bootstrap → Deploy
```

---

## 9. Run Ansible

```bash
ansible-playbook playbooks/site.yml
```

---

# PART 3 — KUBERNETES (RUNTIME LAYER)

## 10. Cluster Setup

* kubeadm init (control plane)
* kubeadm join (workers)
* Install CNI (Calico)

---

## 11. Namespaces Strategy

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: dev
```

---

## 12. Scaling

```bash
kubectl scale deployment myapp --replicas=5
```

---

## 13. High Availability

* Multiple control planes
* External etcd
* Load balancer

---

## 14. Storage

* NFS
* Ceph
* Longhorn

---

# PART 4 — HELM (APPLICATION PACKAGING)

## 15. Structure

```text
helm-charts/myapp/
├── Chart.yaml
├── values.yaml
└── templates/
```

---

## 16. Install

```bash
helm install myapp ./helm-charts/myapp
```

---

## 17. Deployment Example

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

# PART 5 — ARGOCD (GITOPS LAYER)

## 18. Install

```bash
kubectl create namespace argocd

kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

---

## 19. Workflow

```text
Git Push → ArgoCD → Sync → Kubernetes Update
```

---

# PART 6 — MONITORING STACK

## 20. Prometheus + Grafana

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts

helm install monitoring prometheus-community/kube-prometheus-stack
```

---

## 21. Loki Logging

```bash
helm repo add grafana https://grafana.github.io/helm-charts

helm install loki grafana/loki-stack
```

---

# PART 7 — CI/CD PIPELINE

## 22. GitHub Actions

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

      - name: Run Ansible
        run: |
          cd ansible
          ansible-playbook playbooks/site.yml
```

---

# PART 8 — SECURITY

* Kubernetes RBAC
* Ansible Vault
* No plaintext secrets

---

## RBAC Example

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

## 23. Horizontal Scaling

```bash
kubectl scale deployment myapp --replicas=5
```

---

## 24. Storage Options

* NFS
* Ceph
* Longhorn

---

# PART 10 — COMPLETE WORKFLOW

```text
1. Vagrant creates KVM VMs
2. Terraform optionally provisions infra
3. Ansible configures nodes
4. Kubernetes cluster is initialized
5. Helm deploys applications
6. ArgoCD manages GitOps
7. Monitoring observes everything
```

---

