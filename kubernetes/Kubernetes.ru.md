# 🧩 GubinNET — руководство по развертыванию в Kubernetes

Этот гайд поможет вам развернуть **GubinNET** в кластере Kubernetes.  
В данном примере мы будем использовать:

✅ Deployment  
✅ Service  
✅ Ingress (с поддержкой TLS)  
✅ ConfigMap для хранения конфигурации  
✅ PVC для логов  
✅ Readiness/Liveness пробы  

---

## 📁 Структура файлов

```
k8s/
├── configmap.yaml
├── deployment.yaml
├── service.yaml
├── ingress.yaml
└── pvc.yaml
```

---

## 1️⃣ PersistentVolume и PVC – Хранилище для логов

Создайте файл `k8s/pvc.yaml`:

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

> ⚠️ В production используйте облачные диски вместо `hostPath`.

---

## 2️⃣ ConfigMap – Конфигурация сервера

Создайте файл `k8s/configmap.yaml`:

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

Вы можете добавлять дополнительные `.ini` файлы для каждого сайта.

---

## 3️⃣ Deployment – Запуск GubinNET

Создайте файл `k8s/deployment.yaml`:

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

## 4️⃣ Service – Открытие портов

Создайте файл `k8s/service.yaml`:

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

## 5️⃣ Ingress – Внешний доступ

Создайте файл `k8s/ingress.yaml`:

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

> 🔐 Для автоматической выдачи сертификатов необходимо установить [cert-manager](https://cert-manager.io/) и настроить `ClusterIssuer`.

---

## 🚀 Как применять?

Запустите команды:

```bash
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
```

---

## 🧪 Проверка

После применения всех манифестов проверьте статус:

```bash
kubectl get pods
kubectl get services
kubectl get ingress
```

---

## 🛠️ Как собрать Docker-образ

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

### Сборка и публикация

```bash
docker build -t your-registry/gubinnet:latest .
docker push your-registry/gubinnet:latest
```

---

## 🔄 Горячая перезагрузка конфигурации

Чтобы обновить конфиг без перезапуска контейнера, отправьте сигнал `SIGHUP`:

```bash
kubectl exec -it <pod-name> -- kill -HUP 1
```

---

## 📈 Prometheus Monitoring (опционально)

Для сбора метрик из `/metrics` добавьте `ServiceMonitor`:

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
