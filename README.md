To access your AKS-hosted app via browser using HTTPS, you’ll need to expose it to the internet securely. Your current configuration uses a ClusterIP service, which is internal-only — not accessible from outside the cluster.

Here's a step-by-step guide to expose it publicly with HTTPS using Ingress + TLS (SSL) in Azure Kubernetes Service (AKS):

✅ Step 1: Update Your Service to Use ClusterIP (Already Done)

You're using:

type: ClusterIP


This is correct for using Ingress, which will route traffic from a public IP to this internal service.

✅ Step 2: Install an Ingress Controller (NGINX)

You need an Ingress controller to handle external traffic. The most common is NGINX.

Run this on your machine (where kubectl is configured for your AKS cluster):

kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.9.5/deploy/static/provider/cloud/deploy.yaml


This will install the NGINX Ingress controller in your cluster.

✅ Step 3: Get the Ingress Controller’s Public IP

Wait for the LoadBalancer IP to be assigned:

kubectl get services -n ingress-nginx


Look for a service named ingress-nginx-controller, and copy its EXTERNAL-IP.

You’ll use this in your DNS later (e.g., point your domain to it).

✅ Step 4: Create a DNS Name (Optional but Recommended)

If you have a domain (like example.com), create a DNS A record pointing to the Ingress Controller’s External IP.

For testing, you can use nip.io or sslip.io, which resolve DNS automatically.
Example:

myapp.20.40.60.80.nip.io


Replace 20.40.60.80 with your Ingress IP.

✅ Step 5: Deploy a TLS Certificate Using Cert-Manager + Let's Encrypt
1. Install cert-manager:
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml


Wait until cert-manager pods are ready:

kubectl get pods --namespace cert-manager

2. Create ClusterIssuer for Let’s Encrypt:
# letsencrypt-prod.yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    email: your-email@example.com
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx


Apply it:

kubectl apply -f letsencrypt-prod.yaml

✅ Step 6: Create the Ingress Resource with TLS
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: natureapp-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - myapp.20.40.60.80.nip.io  # Replace with your domain or DNS name
    secretName: natureapp-tls
  rules:
  - host: myapp.20.40.60.80.nip.io  # Replace with your domain
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: natureapp-service
            port:
              number: 80


Apply it:

kubectl apply -f ingress.yaml

✅ Step 7: Wait for HTTPS Certificate to be Issued

Check certificate status:

kubectl describe certificate natureapp-tls


Once the certificate is Ready, you can access your app via:

https://myapp.20.40.60.80.nip.io

✅ Bonus: Monitor Everything

Ingress health:
kubectl get ingress

Nginx logs:
kubectl logs -n ingress-nginx deploy/ingress-nginx-controller

🚀 Summary
Step	Description
✅ 1	Use ClusterIP service
✅ 2	Install NGINX Ingress Controller
✅ 3	Get External IP for Ingress
✅ 4	Use a domain (real or .nip.io)
✅ 5	Install cert-manager and create ClusterIssuer
✅ 6	Deploy Ingress with TLS config
✅ 7	Access via https://your-domain