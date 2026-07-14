---
description: K8s集群攻击。从Pod Shell到集群控制。参考手册见 SKILL.ref.md
---

# K8s 攻击

## 触发条件
拿到 Pod Shell 或发现 kubelet/kube-apiserver/etcd 端口时触发

## 攻击链
```
1. 信息收集    → env/kubectl/serviceaccount/tiller
2. RBAC枚举    → kubectl auth can-i --list
3. SA利用      → 挂载 token → 检查权限 → 创建特权 Pod
4. etcd攻击    → etcdctl get / --prefix
5. Admission   → 修改 webhook → 拦截 Pod 创建
6. 网络绕过    → HostNetwork/DNS 重绑定
7. Service Mesh → Istio/Linkerd 配置泄露
8. 容器逃逸    → privileged/docker.sock/capabilities/cgroup
```

> 完整命令、逃逸手法见 SKILL.ref.md
