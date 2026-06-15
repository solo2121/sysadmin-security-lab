# DevOps Linux Lab

A complete **local DevOps + SysAdmin + Kubernetes lab** designed for:

* LFCS / RHCSA / Linux+ practice
* Kubernetes (k3s) hands-on learning
* DevOps tooling (Terraform, Ansible, Helm)
* GitOps workflows (ArgoCD)
* Monitoring (Prometheus, Grafana, Loki)

---

## Overview

This lab simulates a **real production-like environment** entirely locally using:

* Vagrant + Libvirt (KVM)
* Multi-node architecture
* Infrastructure as Code principles
* k3s lightweight Kubernetes distribution

---

## Architecture

```text
DevOps Node (Control)
│
├── Terraform
├── Ansible
├── Helm
│
└── k3s Kubernetes Cluster
    ├── k3s-cp (Control Plane + Server)
    ├── k3s-w1 (Worker Agent)
    └── k3s-w2 (Worker Agent)

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
├── Vagrantfile                 # Vagrant configuration for multi-node lab setup
├── scripts/                    # Lab management and utility scripts
├── docs/                       # Documentation and guides
├── terraform/                  # Infrastructure as Code (IaC)
├── ansible/                    # Configuration Management
├── k8s/                        # Kubernetes manifests
├── helm/                       # Helm charts
└── monitoring/                 # Prometheus, Grafana, Loki stack
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

| Service    | URL                   | Credentials (User/Pass) |
| ---------- | --------------------- | ----------------------- |
| Jenkins    | http://localhost:8080 | admin / admin123        |
| Grafana    | http://localhost:3000 | admin / admin           |
| Prometheus | http://localhost:9090 | N/A (Public Read)       |
| ArgoCD     | http://localhost:8081 | admin / (See `argocd initial-admin-secret`) |

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

## Kubernetes Setup (k3s)

```bash
vagrant ssh k3s-cp
# k3s server is automatically started
kubectl get nodes
```

Workers automatically join the cluster via agent token.

Verify cluster:

```bash
kubectl cluster-info
kubectl get nodes
```

---

## Monitoring Access

To verify the monitoring stack is receiving data from nodes:

```bash
curl http://localhost:9090/api/v1/targets
```

## DevOps Workflow

1. Terraform provisions infrastructure
2. Vagrant bootstraps VMs with k3s
3. Ansible configures nodes
4. Kubernetes cluster initialized
5. Helm deploys applications
6. ArgoCD manages GitOps
7. Monitoring stack observes system

---

## Troubleshooting

| Symptom | Probable Cause | Resolution |
|---------|----------------|------------|
| `vagrant up` fails | Libvirt bridge conflict | `virsh net-destroy default && virsh net-start default` |
| Nodes not joining K3s | Token mismatch | Check `/var/lib/rancher/k3s/server/node-token` on cp node |
| Storage errors | Host disk space | Ensure 50GB+ free space on host |
| Ansible fails | SSH key not shared | Run `vagrant ssh-config` to verify connectivity |

---

## Cleanup and Teardown

To stop the lab and save resources:
```bash
vagrant halt
```

To completely remove the lab and associated disks:
```bash
vagrant destroy -f
```

---

## Security Concepts

* RBAC
* Secrets management
* Network segmentation
* Audit tooling

---

## Learning Goals

* Understand Kubernetes with k3s lightweight distribution
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
