# 🔒 Securely Exposing an AKS App with HTTPS (Ingress + TLS)

This guide provides a step-by-step process to expose an application hosted on **Azure Kubernetes Service (AKS)** to the public internet using **HTTPS**, leveraging an **NGINX Ingress Controller** and **Cert-Manager** with **Let's Encrypt** for automated TLS (SSL) certificates.

---

## ✅ Step 1: Confirm Service Type

Ensure your application's Kubernetes Service is of type `ClusterIP`. This makes it internal to the cluster, which the Ingress Controller will then expose publicly.

Your existing Service definition should include:

```yaml
type: ClusterIP