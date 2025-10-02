# 🔒 Securely Exposing an AKS App with HTTPS (Ingress + TLS)

This guide provides a step-by-step process to expose an application hosted on **Azure Kubernetes Service (AKS)** to the public internet using **HTTPS**, leveraging an **NGINX Ingress Controller** and **Cert-Manager** with **Let's Encrypt** for automated TLS (SSL) certificates.

---

## ✅ Step 1: Confirm Service Type

Ensure your application's Kubernetes Service is of type `ClusterIP`. This makes it internal to the cluster, which the Ingress Controller will then expose publicly.

Your existing Service definition should include:

```yaml
type: ClusterIP
yaml```

## ✅ Step 2: Install NGINX Ingress Controller
Deploy the NGINX Ingress Controller. This will create an Azure Load Balancer with a public IP that serves as the entry point for all external traffic.

Command
Bash

```bash
kubectl apply -f [https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.9.5/deploy/static/provider/cloud/deploy.yaml](https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.9.5/deploy/static/provider/cloud/deploy.yaml)