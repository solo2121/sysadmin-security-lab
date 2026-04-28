# DevOps Linux Lab

A complete **local DevOps + SysAdmin + Kubernetes lab** designed for:

* LFCS / RHCSA / Linux+ practice
* Kubernetes (kubeadm) hands-on learning
* DevOps tooling (Terraform, Ansible, Helm)
* GitOps workflows (ArgoCD)
* Monitoring (Prometheus, Grafana, Loki)

---

## Overview

This lab simulates a **real production-like environment** entirely locally using:

* Vagrant + Libvirt (KVM)
* Multi-node architecture
* Infrastructure as Code principles

---

## Architecture

```text
DevOps Node (Control)
│
├── Terraform
├── Ansible
├── Helm
│
└── Kubernetes Cluster
    ├── k8s-cp (Control Plane)
    ├── k8s-w1 (Worker)
    └── k8s-w2 (Worker)

Linux Study Nodes
├── Ubuntu
├── Rocky Linux
├── AlmaLinux
└── openSUSE
```

---

## Project Structure

```text
devops-linux-lab/
├── Vagrantfile
├── scripts/
├── docs/
├── terraform/
├── ansible/
├── k8s/
├── helm/
└── monitoring/
```

---

## Requirements

* Vagrant
* Libvirt / KVM
* 16GB RAM recommended (minimum 8GB)

---

## Quick Start

```bash
vagrant up
```

Optional VM manager:

```bash
../../scripts/lab-manager.sh
```

---

## Access

| Service    | URL                   |
| ---------- | --------------------- |
| Jenkins    | http://localhost:8080 |
| Grafana    | http://localhost:3000 |
| Prometheus | http://localhost:9090 |
| ArgoCD     | http://localhost:8081 |

---

## Linux Practice

Use lab nodes for certification training:

```bash
vagrant ssh rocky-lab
vagrant ssh alma-lab
vagrant ssh opensuse-lab
```

Topics:

* LVM
* SELinux
* Networking
* systemd
* users & permissions

---

## Kubernetes Setup (Manual Learning)

```bash
vagrant ssh k8s-cp
sudo kubeadm init --apiserver-advertise-address=192.168.56.11
```

Join workers using the generated token.

Install CNI:

```bash
kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml
```

---

## DevOps Workflow

1. Terraform provisions infrastructure
2. Ansible configures nodes
3. Kubernetes cluster initialized
4. Helm deploys applications
5. ArgoCD manages GitOps
6. Monitoring stack observes system

---

## Security Concepts

* RBAC
* Secrets management
* Network segmentation
* Audit tooling

---

## Learning Goals

* Build Kubernetes from scratch (no shortcuts)
* Understand Infrastructure as Code
* Practice real sysadmin tasks
* Implement GitOps workflows
* Monitor distributed systems

---

## Future Enhancements

* Full Ansible automation
* ArgoCD auto-bootstrap
* Service Mesh (Istio)
* Chaos engineering labs
* Multi-cluster federation

---

## License

MIT
