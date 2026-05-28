# DevOps Lab Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Developer Workstation                        │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           Vagrant + Libvirt/KVM (Host)                   │  │
│  │                                                           │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │  │
│  │  │  DevOps VM  │  │ Control Plane│  │ Worker Nodes  │  │  │
│  │  │             │  │ (k8s-cp)     │  │ (k8s-w1, w2)  │  │  │
│  │  │ Terraform   │  │              │  │               │  │  │
│  │  │ Ansible     │  │ kubeadm init │  │ kubeadm join  │  │  │
│  │  │ Helm        │  │ API Server   │  │ Kubelet       │  │  │
│  │  │             │  │ etcd         │  │ Container RT  │  │  │
│  │  │ Jenkins     │  │              │  │               │  │  │
│  │  │ Registry    │  │              │  │               │  │  │
│  │  └─────────────┘  └──────────────┘  └───────────────┘  │  │
│  │         │                  │                  │            │  │
│  │  ┌──────┴──────────────────┴──────────────────┴──────┐   │  │
│  │  │         Libvirt Network (192.168.121.0/24)       │   │  │
│  │  └───────────────────────────────────────────────────┘   │  │
│  │                                                           │  │
│  │  ┌──────────┐  ┌─��────────┐  ┌──────────┐               │  │
│  │  │ Ubuntu   │  │ Rocky    │  │ AlmaLinux│               │  │
│  │  │ Lab      │  │ Lab      │  │ Lab      │               │  │
│  │  └──────────┘  └──────────┘  └──────────┘               │  │
│  │                                                           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Network Topology

### IP Address Allocation
```
Network: 192.168.121.0/24 (auto-detected)

Kubernetes Cluster:
  k8s-cp (Control Plane)    192.168.121.114
  k8s-w1 (Worker 1)         192.168.121.115
  k8s-w2 (Worker 2)         192.168.121.116

DevOps Infrastructure:
  devops-1 (Primary)        192.168.121.101

Linux Labs:
  ubuntu-lab                192.168.121.200
  rocky-lab                 192.168.121.201
  alma-lab                  192.168.121.202
  opensuse-lab              192.168.121.203
```

### Network Policies
```
┌────────────────┐
│  K8s Cluster   │
├────────────────┤
│ Default Deny   │  ← All ingress/egress blocked by default
└────────────────┘
       │
       ├── Allow intra-namespace communication
       ├── Allow DNS (CoreDNS)
       ├── Allow API server access
       └── Allow external ingress (via Ingress controller)
```

## Component Architecture

### Infrastructure as Code (Terraform)
```
terraform/
├── main.tf           # Provider + resource definitions
├── variables.tf      # Input variables
├── outputs.tf        # Output values
└── network.tf        # Network resources

Flow:
1. Define provider (libvirt)
2. Create networks
3. Define VM resources with disk, memory, CPU
4. Configure provisioners (scripts/cloud-init)
```

### Configuration Management (Ansible)
```
ansible/
├── playbooks/
│   ├── setup-devops.yml      # Install DevOps tools
│   ├── setup-k8s-master.yml  # Prepare control plane
│   ├── setup-k8s-worker.yml  # Prepare workers
│   └── setup-monitoring.yml  # Prometheus/Grafana
├── roles/
│   ├── kubernetes/
│   ├── docker/
│   ├── prometheus/
│   └── ...
└── inventory/
    ├── hosts.ini             # Target nodes
    └── group_vars/           # Per-group variables

Execution Order:
1. Provision base OS
2. Install container runtime (Docker/containerd)
3. Install kubeadm, kubelet, kubectl
4. Configure networking
5. Deploy monitoring stack
```

### Kubernetes Cluster
```
k8s-cp (Control Plane)
├── kube-apiserver         (Port 6443)
│   ├── Authentication
│   ├── Authorization (RBAC)
│   └── API validation
├── etcd                   (Port 2379)
│   └── Cluster state storage
├── kube-controller-manager
│   ├── Node controller
│   ├── Replication controller
│   └── Service account controller
├── kube-scheduler
│   └── Pod placement logic
└── kubelet               (Port 10250)

k8s-w1, k8s-w2 (Workers)
├── kubelet               (Port 10250)
│   ├── Pod management
│   └── Volume management
├── Container Runtime     (Docker/containerd)
│   └── Container execution
└── kube-proxy           (Port 10249)
    └── Service networking

Pod Network:
├── CNI Plugin (Calico)
├── Pod CIDR: 10.244.0.0/16
└── Service CIDR: 10.96.0.0/12
```

### DevOps Toolchain
```
DevOps Node (devops-1)

┌──────────────────────────────────────┐
│  Git Repository (Local)              │
│  ↓                                   │
│  Jenkins CI/CD Pipeline              │
│  ├── Build: Docker image             │
│  ├── Test: Unit/Integration tests    │
│  ├── Push: Registry (Harbor)         │
│  └── Deploy: Helm → K8s              │
│                                      │
│  ArgoCD (GitOps Controller)          │
│  ├── Watch Git repo for changes      │
│  ├── Sync with Kubernetes cluster    │
│  └── Continuous deployment           │
│                                      │
│  Helm Package Manager                │
│  ├── Manage Kubernetes charts        │
│  └── Release versioning              │
└──────────────────────────────────────┘
```

## Data Flow

### Deployment Pipeline
```
1. Developer pushes code → Git
2. Git webhook triggers → Jenkins
3. Jenkins builds Docker image
4. Jenkins pushes image → Harbor Registry
5. Jenkins creates/updates Helm chart
6. ArgoCD detects changes
7. ArgoCD syncs with K8s cluster
8. Kubernetes deploys pods
9. Prometheus scrapes metrics
10. Grafana displays dashboards
```

### Networking Flow
```
External Request
    ↓
Ingress Controller (nginx)
    ↓
Service (ClusterIP)
    ↓
Endpoint (Pod IP)
    ↓
Container (Port mapping)

DNS Resolution:
kubernetes.default.svc.cluster.local
    ↓
Service IP (10.96.x.x)
    ↓
Pod IP (10.244.x.x)
```

## Storage Architecture

### Kubernetes Storage
```
Volumes:
├── emptyDir         (Temp pod data)
├── hostPath         (Node filesystem)
├── configMap        (Configuration)
├── secret           (Sensitive data)
└── persistentVolume (Persistent data)

PersistentVolume Claims:
└── Requested by pods
    └── Bound to PV by controller
        └── Mounted in container

Storage Classes:
└── Define provisioner behavior
    └── Dynamic provisioning
```

## Security Boundaries

```
Layer 1: Host Security
├── SSH key authentication (no password)
├── SELinux/AppArmor policies
├── Host firewall rules
└── Regular patching

Layer 2: Container Security
├── Non-root container users
├── Read-only root filesystem
├── Resource limits (CPU/memory)
└── Image scanning

Layer 3: Kubernetes Security
├── Network policies (default deny)
├── RBAC (least privilege)
├── Pod security policies
├── Secret encryption at rest
└── API server audit logging

Layer 4: Application Security
├── TLS/SSL for communication
├── Secrets injection
├── Dependency scanning
└── Code analysis
```

## High Availability Considerations

### Current Setup (Development)
```
Single point of failures:
├── One control plane
├── One etcd database
└── Local storage

Production Improvements:
├── Multiple control planes (HA)
├── etcd cluster (3+ nodes)
├── Persistent storage backends
├── Load balancer for API
└── Backup/restore procedures
```

## Disaster Recovery

### Backup Strategy
```
Backup Components:
1. etcd snapshots (Kubernetes state)
   └── via Velero
2. PersistentVolumes (Data)
   └── via cloud provider snapshots
3. Application configs (Helm charts, Git)
   └── via Git repository

Restore Procedure:
1. Provision new cluster
2. Restore etcd snapshot
3. Restore PV snapshots
4. Sync from Git (ArgoCD)
```

## Monitoring & Observability

```
Prometheus
├── Scrapes metrics from:
│   ├── Kubernetes API
│   ├── Kubelet endpoints
│   ├── Node exporters
│   └── Application endpoints
├── 15-second scrape interval
└── 15-day retention

Grafana
├── Queries Prometheus
├── Visualizes metrics
├── Creates dashboards
└── Alerts on thresholds

Log Aggregation:
├── Loki (log storage)
├── Promtail (log shipper)
└── Explored via Grafana

Alerts:
├── PrometheusRules define conditions
├── AlertManager routes alerts
└── Webhooks to external systems
```

## Version Matrix

| Component | Version | Purpose |
|-----------|---------|---------|
| Kubernetes | 1.28+ | Container orchestration |
| Docker | 27.3.1 | Container runtime |
| Terraform | 1.0+ | Infrastructure provisioning |
| Ansible | 2.9+ | Configuration management |
| Helm | 3.0+ | Kubernetes package manager |
| Prometheus | 2.40+ | Metrics collection |
| Grafana | 9.0+ | Metrics visualization |
| ArgoCD | 2.0+ | GitOps controller |

---

**Last Updated**: May 2026
