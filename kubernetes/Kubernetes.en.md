# 🧩 GubinNET — Kubernetes Deployment Guide

This guide will help you deploy **GubinNET** in a Kubernetes cluster.  
In this example, we will use:

✅ Deployment  
✅ Service  
✅ Ingress (with TLS support)  
✅ ConfigMap for configuration storage  
✅ PVC for logs  
✅ Readiness/Liveness probes  

---

## 📁 File Structure

```
k8s/
├── configmap.yaml
├── deployment.yaml
├── service.yaml
├── ingress.yaml
└── pvc.yaml
```

---

## 1️⃣ PersistentVolume and PVC – Storage for Logs

Create file `k8s/pvc.yaml`:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: gubinnet-logs
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: gubinnet-logs-pv
spec:
  capacity:
    storage: 5Gi
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  hostPath:
    path: /mnt/data/gubinnet/logs
```

> ⚠️ In production, use cloud disks instead of `hostPath`.

---

## 2️⃣ ConfigMap – Server Configuration

Create file `k8s/configmap.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: gubinnet-config
data:
  myapp.ini: |
    server_name=myapp.local
    listen_port=8080
    root_path=/var/www/html
    try_files=index.html
    use_ssl=false
    redirect_to_https=false
```

You can add additional `.ini` files for each site.

---

## 3️⃣ Deployment – Running GubinNET

Create file `k8s/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gubinnet
spec:
  replicas: 1
  selector:
    matchLabels:
      app: gubinnet
  template:
    metadata:
      labels:
        app: gubinnet
    spec:
      containers:
        - name: gubinnet
          image: your-registry/gubinnet:latest
          ports:
            - containerPort: 80
            - containerPort: 443
          readinessProbe:
            httpGet:
              path: /
              port: 80
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /
              port: 80
            initialDelaySeconds: 30
            periodSeconds: 60
          env:
            - name: ENVIRONMENT
              value: "production"
          volumeMounts:
            - name: config
              mountPath: /etc/gubinnet/config
            - name: logs
              mountPath: /etc/gubinnet/logs
      volumes:
        - name: config
          configMap:
            name: gubinnet-config
        - name: logs
          persistentVolumeClaim:
            claimName: gubinnet-logs
```

---

## 4️⃣ Service – Exposing Ports

Create file `k8s/service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: gubinnet
spec:
  type: ClusterIP
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
      name: http
    - port: 443
      targetPort: 443
      protocol: TCP
      name: https
  selector:
    app: gubinnet
```

---

## 5️⃣ Ingress – External Access

Create file `k8s/ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: gubinnet-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts:
        - myapp.local
      secretName: myapp-tls
  rules:
    - host: myapp.local
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: gubinnet
                port:
                  number: 80
```

> 🔐 To automatically issue certificates, install [cert-manager](https://cert-manager.io/) and configure a `ClusterIssuer`.

---

## 🚀 How to Apply?

Run these commands:

```bash
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
```

---

## 🧪 Verification

After applying all manifests, check the status:

```bash
kubectl get pods
kubectl get services
kubectl get ingress
```

---

## 🛠️ How to Build the Docker Image

### `Dockerfile`

```dockerfile
FROM golang:1.21 as builder
WORKDIR /app
COPY gubinnet.go .
RUN go build -o /gubinnet gubinnet.go

FROM golang:1.21
WORKDIR /root/
COPY --from=builder /gubinnet /usr/local/bin/gubinnet
CMD ["gubinnet"]
```

### Build and Push

```bash
docker build -t your-registry/gubinnet:latest .
docker push your-registry/gubinnet:latest
```

---

## 🔄 Hot Reload Configuration

To reload the config without restarting the container, send the `SIGHUP` signal:

```bash
kubectl exec -it <pod-name> -- kill -HUP 1
```

---

## 📈 Prometheus Monitoring (Optional)

To collect metrics from `/metrics`, add a `ServiceMonitor`:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: gubinnet
spec:
  selector:
    matchLabels:
      app: gubinnet
  endpoints:
    - port: http
      path: /metrics
      interval: 15s
```

--- 
