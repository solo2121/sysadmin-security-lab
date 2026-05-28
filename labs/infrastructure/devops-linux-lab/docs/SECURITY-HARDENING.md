# Security Hardening Guide

## Kubernetes RBAC (Role-Based Access Control)

### Create Service Accounts
```bash
# Create namespace
kubectl create namespace lab-apps

# Create service account for deployments
kubectl create serviceaccount lab-deployer -n lab-apps

# Create role with limited permissions
kubectl create role lab-deployer \
  --verb=get,list,watch,create,update,patch \
  --resource=pods,deployments,services \
  -n lab-apps

# Bind role to service account
kubectl create rolebinding lab-deployer \
  --clusterrole=lab-deployer \
  --serviceaccount=lab-apps:lab-deployer \
  -n lab-apps
```

### Default Deny Network Policy
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: lab-apps
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
# Allow traffic from same namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-intra-ns
  namespace: lab-apps
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}
```

## Pod Security Standards

### Enforce Restricted Policy
```yaml
apiVersion: policy/v1alpha1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
  - ALL
  volumes:
  - 'configMap'
  - 'emptyDir'
  - 'projected'
  - 'secret'
  - 'downwardAPI'
  - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: false
```

## Kubernetes Audit Logging

### Enable Audit Logs
```bash
# Create audit policy on control plane
sudo tee /etc/kubernetes/audit-policy.yaml << EOF
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# Log all requests at metadata level
- level: Metadata
  omitStages:
  - RequestReceived
EOF

# Update kube-apiserver manifest
sudo nano /etc/kubernetes/manifests/kube-apiserver.yaml
# Add under spec.containers[0].command:
#   - --audit-log-path=/var/log/kubernetes/audit.log
#   - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
```

### View Audit Logs
```bash
# On control plane
sudo tail -f /var/log/kubernetes/audit.log | jq .
```

## Secrets Management

### Use Encrypted Secrets
```bash
# Generate encryption key
head -c 32 /dev/urandom | base64

# Configure EncryptionConfig
sudo tee /etc/kubernetes/encryption-config.yaml << EOF
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - aescbc:
      keys:
      - name: key1
        secret: <BASE64-ENCODED-KEY>
  - identity: {}
EOF
```

### Create & Access Secrets
```bash
# Create secret
kubectl create secret generic db-password \
  --from-literal=password=secure-passphrase \
  -n lab-apps

# Use in deployment
kubectl set env deployment/app --from=secret/db-password -n lab-apps

# View (careful - shows plaintext!)
kubectl get secret db-password -o jsonpath='{.data.password}' | base64 -d
```

## TLS/SSL Configuration

### Generate Self-Signed Certificates
```bash
# Create certificate authority
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.crt

# Create server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# Create Kubernetes secret
kubectl create secret tls lab-tls \
  --cert=server.crt --key=server.key \
  -n lab-apps
```

### Ingress with TLS
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-ingress
  namespace: lab-apps
spec:
  tls:
  - hosts:
    - app.lab.local
    secretName: lab-tls
  rules:
  - host: app.lab.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-service
            port:
              number: 443
```

## Image Security

### Container Image Scanning
```bash
# Use Trivy to scan images
trivy image nginx:latest

# Scan before pushing to registry
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image docker://myapp:latest
```

### Image Pull Policies
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
  - name: app
    image: myregistry.azurecr.io/app:v1.0.0
    imagePullPolicy: Always  # Always verify image
  imagePullSecrets:
  - name: registry-credentials
```

## Host-Level Security

### SELinux Configuration (RHEL-based)
```bash
# Check current state
getenforce

# Set to enforcing
sudo setenforce 1

# Persist across reboots
sudo nano /etc/selinux/config
# SELINUX=enforcing
```

### Firewall Rules
```bash
# Enable UFW (Ubuntu)
sudo ufw enable

# Allow Kubernetes API
sudo ufw allow 6443/tcp

# Allow Kubelet
sudo ufw allow 10250/tcp

# Allow services
sudo ufw allow from any to any port 30000:32767/tcp
```

### SSH Hardening
```bash
# Disable root login and password auth
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Restrict SSH access
sudo sed -i 's/#Port 22/Port 22/' /etc/ssh/sshd_config

# Restart SSH
sudo systemctl restart sshd
```

## Monitoring & Auditing

### Enable Falco for Runtime Security
```bash
# Install Falco via Helm
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco --set falco.grpc.enabled=true

# Check Falco alerts
kubectl logs -n falco -l app=falco -f
```

### Prometheus Alerting for Security
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-alerts
spec:
  prometheus-alerts.yaml: |
    groups:
    - name: security
      rules:
      - alert: UnauthorizedAPIAccess
        expr: apiserver_audit_event_total{user_verb=~"delete|patch"} > 5
        for: 1m
```

## Compliance Checklist

- [ ] RBAC roles defined for all service accounts
- [ ] Network policies enforced (default deny)
- [ ] Pod security policies configured
- [ ] Secrets encrypted at rest
- [ ] TLS enabled for inter-pod communication
- [ ] Image scanning enabled in CI/CD
- [ ] Audit logging configured
- [ ] Host firewall rules applied
- [ ] SSH hardening applied
- [ ] Runtime monitoring (Falco) enabled

---

**Last Updated**: May 2026
