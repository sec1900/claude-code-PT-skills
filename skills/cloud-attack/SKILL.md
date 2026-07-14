---
description: 云环境攻击。覆盖AWS/阿里云/Azure。GCP需联网搜索。参考手册见 SKILL.ref.md
---

# 云环境攻击

## 触发条件
recon 发现 CDN/CVM/OSS/IMDS 端点或云厂商特征时触发

## 攻击面
```
IMDS利用    → 169.254.169.254 获取临时凭据
IAM提权     → 策略滥用/AssumeRole/PassRole
存储桶攻击  → 公开读写检测 → 敏感文件枚举
云函数劫持  → 函数代码注入 → 触发方式控制
AK/SK利用   → 源码/Git/JS/配置文件泄露
跨服务横向  → EC2→RDS→S3 信任链利用
```

## 平台特征
```
AWS:    ec2.internal / s3.amazonaws.com / *.aws
阿里云: aliyuncs.com / oss-cn-* / ecs.aliyuncs.com
Azure:  cloudapp.net / windows.net / azurewebsites.net
```

> 完整利用链、命令模板见 SKILL.ref.md
