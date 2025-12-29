# 在 Signoz Collector 中使用 GKE Workload Identity 连接 Kafka

## 前提条件

1. 在 GKE 集群中已启用 Workload Identity
2. 已创建 Kubernetes Service Account (KSA) 并绑定到 GCP Service Account (SA)
3. Pod 已配置使用该 KSA

## 配置步骤

### 1. 绑定 KSA 到 GCP SA（如果还没有绑定）

```bash
# 创建 GCP Service Account
gcloud iam service-accounts create kafka-client \
    --project=YOUR_PROJECT_ID

# 绑定 KSA 到 GCP SA
gcloud iam service-accounts add-iam-policy-binding \
    --role roles/iam.workloadIdentityUser \
    --member "serviceAccount:YOUR_PROJECT_ID.svc.id.goog[NAMESPACE/KSA_NAME]" \
    kafka-client@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

### 2. 在 Deployment 中指定 KSA

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: signoz-collector
spec:
  template:
    spec:
      serviceAccountName: your-ksa-name  # 使用已绑定到 GCP SA 的 KSA
      containers:
      - name: collector
        image: signoz/otel-collector:latest
```

### 3. Collector 配置

在 Signoz collector 的配置文件中，只需要指定 `token_provider: gke_workload_identity`，其他配置会自动从 Workload Identity 获取：

```yaml
exporters:
  kafka:
    brokers:
      - kafka.example.com:9092
    protocol_version: "2.0.0"
    topic: otlp_spans
    auth:
      sasl:
        mechanism: OAUTHBEARER
        oauthbearer:
          token_provider: gke_workload_identity
      tls:
        insecure: false  # 生产环境建议设为 false 并配置证书
```

**注意**：
- 不需要填写 `service_account_email`，系统会自动使用绑定到当前 Pod KSA 的 GCP SA
- 不需要填写 `scope`，默认使用 `https://www.googleapis.com/auth/cloud-platform`
- Workload Identity 会自动处理 token 的获取和刷新

## 完整配置示例

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:
    timeout: 1s
    send_batch_size: 1024

exporters:
  kafka:
    brokers:
      - kafka.example.com:9092
    protocol_version: "2.0.0"
    topic: otlp_spans
    auth:
      sasl:
        mechanism: OAUTHBEARER
        oauthbearer:
          token_provider: gke_workload_identity
      tls:
        insecure: false
    sending_queue:
      enabled: true
      num_consumers: 10
      queue_size: 1000
    retry_on_failure:
      enabled: true
      initial_interval: 5s
      max_interval: 30s
      max_elapsed_time: 120s

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [kafka]
```

## 验证

部署后，检查 collector 日志，应该能看到成功连接到 Kafka。如果出现认证错误，请检查：

1. KSA 是否正确绑定到 GCP SA
2. Pod 是否使用了正确的 KSA
3. GCP SA 是否有访问 Kafka 所需的权限

