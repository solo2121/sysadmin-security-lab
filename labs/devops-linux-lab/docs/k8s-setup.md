# Kubernetes Setup (kubeadm)

## Initialize Control Plane
vagrant ssh k8s-cp

sudo kubeadm init --apiserver-advertise-address=192.168.56.11

## Configure kubectl
mkdir -p $HOME/.kube
sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

## Install CNI
kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml

## Join Workers
Run the kubeadm join command on:
- k8s-w1
- k8s-w2