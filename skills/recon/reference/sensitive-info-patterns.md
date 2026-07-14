# 敏感信息提取规则库

> 从源码文件、配置文件、前端打包产物、小程序源码、APP 反编译代码中提取敏感信息的正则规则集。
> 来源：DigDeep 工具反编译提取 + 补充。

## 使用场景

```
拿到源码/文件后：
  1. 前端 JS 打包文件 (app.js / main.js / vendor.js)
  2. 小程序源码包 (wxapkg 解包后)
  3. APP 反编译产物 (apktool / jadx)
  4. .git 泄露 / 备份文件 / 配置文件
  5. Web 目录遍历 + 可读文件

对所有文本类文件做正则扫描，自动跳过二进制（.dex/.apk/.so/.png/.jpg/.jar/.class/.zip/.dll/.bks）
```

---

## 一、国内云 AK/SK（高）

| 厂商 | 正则 | 说明 |
|------|------|------|
| 阿里云 | `\bLTAI[A-Za-z\d]{12,30}\b` | AccessKey ID，LTAI 前缀 |
| 腾讯云 | `\bAKID[A-Za-z\d]{13,40}\b` | SecretId，AKID 前缀 |
| 京东云 | `\bJDC_[0-9A-Z]{25,40}\b` | JDC_ 前缀 |
| 百度云 | `\bALTAK[0-9A-Za-z]{20,30}\b` | ALTAK 前缀 |
| 字节/火山引擎 | `\b(?:AKLT\|AKTP)[a-zA-Z0-9]{35,50}\b` | AKLT/AKTP 前缀 |
| 金山云 | `\bAKLT[a-zA-Z0-9-_]{16,28}\b` | AKLT 短格式 |
| 华为云 | `[A-Z0-9]{20}$` | 需结合上下文 (access_key/secret) |
| 腾讯云 API Key | `\bAPID[a-zA-Z0-9]{32,42}\b` | 腾讯地图/其他 API 密钥 |
| UCloud | `\bUC[A-Za-z0-9]{10,40}\b` | UC 前缀 |
| 青云 | `\bQY[A-Za-z0-9]{10,40}\b` | QY 前缀 |
| 联通云 | `\bLTC[A-Za-z0-9]{10,60}\b` | LTC 前缀 |
| 移动云 | `\bYD[A-Za-z0-9]{10,60}\b` | YD 前缀 |
| 电信云 | `\bCTC[A-Za-z0-9]{10,60}\b` | CTC 前缀 |
| G-Core Labs | `(gcore[A-Za-z0-9]{10,30})` | gcore 前缀 |

### 云 AK 通配模式

```
# 通用 key 字段 + 值提取（覆盖约 100 个常见 key 名）
(?i)(?:(?:access_key|secret_key|secretkey|accesskey|accessToken|access_token|
AppSecret|SecretId|AccessKeyID|AccessKey Secret|Access Key ID|Access Key Secret|
accessKeySecret|accessKeyId|admin_pass|admin_user|alicloud_access_key|
amazon_secret_access_key|api_key_secret|api_key_sid|api_secret|apikey|apiSecret|
app_id|app_key|app_secret|appkey|appkeysecret|application_key|auth_token|
authorizationToken|authsecret|aws_access_key_id|aws_key|aws_secret|aws_secret_key|
aws_token|AWSSecretKey|bluemix_api_key|browserstack_access_key|bucket_password|
client_secret|cloud_api_key|cloudflare_api_key|cloudflare_auth_key|
cloudinary_api_secret|consumer_key|consumer_secret|database_password|
datadog_api_key|datadog_app_key|OSSAccessKeyId|tmpsecretid|tmpsecretkey|
sys_token|systoken|AccessKeySecret|app_ticket|cos\.bucketName|cos\.secretKey|
bucketName|SecretAccessKey|tmp_secret_key|tmp_secret_id|temp_ak|temp_sk|
tempSecretId|tempSecretKey|SessionToken|
algolia_admin_key|algolia_api_key|ansible_vault_password|aos_key|
b2_app_key|bashrcpassword|bintray_apikey|bintray_gpg_password|bintray_key|
bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|
built_branch_deploy_key|bx_password|cache_s3_secret_key|cattle_access_key|
cattle_secret_key|certificate_password|ci_deploy_password|client_zpk_secret_key|
clojars_password|cloud_watch_aws_access_key|cloudant_password|codecov_token|
conn\.login|cypress_record_key|database_schema_test|
digitalocean_ssh_key_body|digitalocean_ssh_key_ids)\s*[:=]\s*['"]?|
[?&](?:ak|sk)=)
([A-Za-z0-9/+._-]{8,})
```

---

## 二、国际云 AK/SK（高）

| 厂商 | 正则 | 说明 |
|------|------|------|
| AWS Access Key | `\b(?:AKIA\|AGPA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA\|ASIA)[A-Z0-9]{16}\b` | 7 种 IAM key 前缀 |
| Google API Key | `\bAIza[0-9A-Za-z_\-]{35}\b` | AIza 前缀，35 字符 |
| Google OAuth Token | `ya29\.[0-9A-Za-z_-]+` | ya29 前缀 |

---

## 三、微信生态（高）

| 类型 | 正则 | 说明 |
|------|------|------|
| 公众号/小程序 AppID | `(wx[a-z0-9]{15,18})` | wx 开头 + 15-18 位 |
| 公众号原始 ID | `((gh_[a-z0-9]{11,13}))` | gh_ 前缀 |
| 小程序 AppID/Secret 关键字 | `(?i)(appid\|appsecret\|wx_applet_secret\|wx_applet_appid)` | 上下文匹配 |
| Session Key | `(?i)(session_key\|encrypted_data\|encryptedData\|signaturenonce\|wxapp_openid\|sessionId\|sessionkey\|session_key\|session_id\|"iv":)` | 微信登录凭据 |
| Webhook (企业微信) | `\bhttps://qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[a-zA-Z0-9\-]{25,50}\b` | 企微机器人 webhook |

---

## 四、企业协作（高）

| 类型 | 正则 | 说明 |
|------|------|------|
| 企业微信/钉钉 CorpID 关键字 | `(?i)(corp)(id\|secret)` | 上下文定位 |
| 钉钉 CorpID 值 | `(ding[a-zA-Z0-9]{32})` | ding + 32 位 |
| 钉钉 AppKey | `(ding[a-z0-9]{16})` | ding + 16 位（小写） |
| 钉钉机器人 Webhook | `\bhttps://oapi\.dingtalk\.com/robot/send\?access_token=[a-z0-9]{50,80}\b` | 钉钉 webhook |
| 飞书机器人 Webhook | `\bhttps://open\.feishu\.cn/open-apis/bot/v2/hook/[a-z0-9\-]{25,50}\b` | 飞书 webhook |
| Slack Webhook | `\bhttps://hooks\.slack\.com/services/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{15,24}\b` | Slack webhook |

---

## 五、通用凭据（高/中）

| 类型 | 正则 | 说明 |
|------|------|------|
| 密码字段 | `\b(?:password\|passwd\|pwd\|pass(?:word)?\|pwdhash\|userpass)\b\s*[:=]+\s*['"]?([^'"\s]+)` | 各类密码赋值 |
| 用户名字段 | `\b(username\|user_name\|user\|account)\b\s*[:=]+\s*['"]?([^'"\s]+)` | 用户名赋值 |
| 账号关键字 | `(账号\|帐户\|帐号\|账户)\s*[:：]\s*([^\s，,;]+)` | 中文账号 |
| Authorization Header | `((basic [a-z0-9=:_\+/-]{5,100})\|(bearer [a-z0-9_.=:_\+/-]{5,100}))` | HTTP 认证头 |
| JDBC 连接串 | `(jdbc:[a-z:]+://[a-z0-9\.\-_:;=/@?,&]+)` | 含数据库 IP/端口/库名 |
| JWT Token | `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\|eyJ[A-Za-z0-9_/+-]{10,}\.[A-Za-z0-9._/+-]{10,}` | JWT header.payload 特征 |
| 私钥/公钥关键字 | `\b(privateKey\|publicKey\|rsaPublic)\b` | 密钥上下文 |
| App 前端 Key | `(\b(?:VUE\|APP\|REACT)_[A-Z_0-9]{1,15}_(?:KEY\|PASS\|PASSWORD\|TOKEN\|APIKEY)['"]*[:=]"(?:[A-Za-z0-9_\-]{15,50}\|[a-z0-9/+]{50,100}==?)")` | 前端硬编码 key |
| 敏感字段通配 | `((\$\$)?('" )?([\w]{0,10})((key)\|(secret)\|(token)\|(config)\|(auth)\|(access)\|(admin)\|(ticket))([\w]{0,10})('" )?(\$\$)?(\|)(:\|=)( \|)('" )(.*? )('" )(\|,))` | 通用 key/value 赋值 |

---

## 六、云存储桶（低）

| 厂商 | 正则 | 说明 |
|------|------|------|
| 阿里 OSS | `\bhttps?://([\w-]+\.)*(oss-)?[\w-]+\.aliyuncs\.com(?:\/\|\b)` | OSS endpoint |
| 华为 OBS | `\bhttps?://([\w-]+\.)*(obs-)?[\w-]+\.(myhuaweicloud\.com\|myhwclouds\.com)(?:\/\|\b)` | OBS endpoint |
| 腾讯 COS | `\bhttps?://([\w-]+\.)*(cos-)?[\w-]+\.myqcloud\.com(?:\/\|\b)` | COS endpoint |
| AWS S3 | `\bhttps?://([\w-]+\.)*(s3-)?[\w-]+\.amazonaws\.com(?:\/\|\b)` | S3 endpoint |
| 百度 BOS | `\bhttps?://([\w-]+\.)*[\w-]+\.bcebos\.com(?:\/\|\b)` | BOS endpoint |
| Google Storage | `\bhttps?://([\w-]+\.)*storage\.googleapis\.com(?:\/\|\b)` | GCS endpoint |
| Azure Blob | `\bhttps?://([\w-]+\.)*blob\.core\.windows\.net(?:\/\|\b)` | Azure Blob endpoint |
| 京东云 OSS | `\bhttps?://([\w-]+\.)*(oss-)?[\w-]+\.(jdcloud-oss\.com\|jcloudcs\.com)(?:\/\|\b)` | JD OSS endpoint |

---

## 七、个人信息（中）

| 类型 | 正则 | 说明 |
|------|------|------|
| 手机号 | `\b1[3-9]\d{9}\b` | 国内 11 位手机号 |
| 身份证号 | `\b\d{6}(18\|19\|20)\d{2}(0[1-9]\|1[0-2])(0[1-9]\|[12]\d\|3[01])\d{3}[\dXx]\b` | 18 位身份证 |
| 邮箱 | `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b` | 标准邮箱 |
| 银行卡号 | `^((62220[0-8]\|62221[0-8]\|95588[0-9]\|622299\|622912)\d{10})\|((62270[089]\|95533[0-9]\|622280)\d{10})\|((62284[0-9]\|95599[0-9])\d{10})\|((62166[0-9]\|62276[0-3])\d{10})\|((456351\|625905)\d{11})\|((43922[56])\d{11})\|((622588\|622599\|622609)\d{10})\|((62226[0-9]\|95559[0-9])\d{8,10})\|((62252[12]\|622517\|622919)\d{7,10})\|((622622\|622602\|42186[59])\d{7,10})\|((62265[058]\|356837)\d{7,10})\|((62215[56]\|622986\|998800)\d{11})\|((622188\|622199\|940033\|622893)\d{10})$` | 国内主流银行 BIN |
| 腾讯地图 Key | `([A-Z0-9]{5}(?:-[A-Z0-9]{5}){5})` | 腾讯地图 API Key 格式 |

---

## 八、网络信息（中）

| 类型 | 正则 | 说明 |
|------|------|------|
| 内网 IP | `\b(10\.(25[0-5]\|2[0-4]\d\|[01]?\d?\d)\.){2}(25[0-5]\|2[0-4]\d\|[01]?\d?\d)\b\|\b(172\.(1[6-9]\|2[0-9]\|3[01])\.(25[0-5]\|2[0-4]\d\|[01]?\d?\d)\.)(25[0-5]\|2[0-4]\d\|[01]?\d?\d)\b\|\b(192\.168\.(25[0-5]\|2[0-4]\d\|[01]?\d?\d)\.)(25[0-5]\|2[0-4]\d\|[01]?\d?\d)\b` | 10.x + 172.16-31.x + 192.168.x |
| 公网 IP | `(((2(5[0-5]\|[0-4]\d))\|[0-1]?\d{1,2})(\.((2(5[0-5]\|[0-4]\d))\|[0-1]?\d{1,2})){3})` | 通用 IPv4 |
| MAC 地址 | `\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b` | MAC 地址 |
| URL | `https?://[^\s"'<>]{6,}` | HTTP/HTTPS URL，至少 6 字符 |

---

## 九、框架/组件指纹（低/信息）

| 类型 | 正则 | 说明 |
|------|------|------|
| Swagger UI | `(swagger-ui.html\|"swagger":\|Swagger UI\|swaggerUi\|swaggerVersion\|/swagger-ui.css\|swagger-ui-bundle.js/swagger-ui-standalone-preset.js\|swagger-ui.min.js\|swagger)` | Swagger API 文档暴露 |
| Druid Monitor | `^(?:.*/)?druid/(stat\|index\|monitor\|sql\|wall\|login\|websession)\.html$` | Druid 监控面板路径 |
| Java 反序列化 | `javax\.faces\.ViewState` | JSF ViewState |
| 文件上传 | `type="file"` | 文件上传 input |
| Source Map | `\.js\.map` | JS Source Map 文件（可还原源码） |
| Vue Router | `\$router\.push` | Vue 路由跳转 |
| 地图 API Key | `\b(map\.qq\.com\|api\.map\.baidu\.com\|restapi\.amap\.com\|webapi\.amap\.com\|places\.googleapis\.com\|www\.supermapol\.com)\b` | 地图 API 域名 |

---

## 十、漏洞参数特征（信息）

### 命令注入参数
```
(?i)(cmd=|exec=|command=|execute=|ping=|query=|jump=|code=|reg=|do=|func=|
arg=|option=|load=|process=|step=|read=|function=|feature=|exe=|module=|
payload=|run=|daemon=|upload=|dir=|download=|log=|ip=|cli=|ipaddress=|
txt=|case=|count=)
```

### SSRF 参数
```
(?i)(\?wap=|\?url=|\?link=|\?src=|\?source=|\?display=|\?sourceURL=|
\?mageURL=|\?domain=|\?Share=|\?target=|\?u=|\?3g=|\?source\[\]=|
\?imgsrc=|\?urlPath=|stream\.url=|stockApi=|path=|url=|=http|source_url=|
\?file=)
```

### JSONP/Callback 参数
```
# 回调函数名
(?i)(callback=|cb=|jsonp=|json=|call=|ca=|callBackMethod=|jsonpcallback=|fun=)

# JSONP 特征
(?i)(jsonp_[a-z0-9]+)|((_?callback|_cb|_call|_?jsonp_?)=)
```

---

## 十一、SQL 错误信息（信息）

覆盖 MySQL / PostgreSQL / MSSQL / Oracle / DB2 / SQLite / Sybase / Access 的错误消息：

```
(?i)(ORA-\d{5}|SQL syntax.*?MySQL|Unknown column|SQL syntax|
java.sql.SQLSyntaxErrorException|Error SQL:|java.sql.SQLException|
SQL Execution Error!|com.mysql.jdbc|MySQLSyntaxErrorException|
valid MySQL result|your MySQL server version|MySqlClient|MySqlException|
valid PostgreSQL result|PG::SyntaxError:|org.postgresql.jdbc|PSQLException|
Microsoft SQL Native Client error|ODBC SQL Server Driver|
SQLServer JDBC Driver|com.jnetdirect.jsql|macromedia.jdbc.sqlserver|
com.microsoft.sqlserver.jdbc|Microsoft Access|Access Database Engine|
ODBC Microsoft Access|Oracle error|DB2 SQL error|SQLite error|
Sybase message|SybSQLException|XPATH syntax|
DOUBLE value is out of range in|SqlException exception|
mysqli_num_rows|Duplicate entry .* for key 'group_key'|
Unclosed quotation mark|Microsoft OLE DB Provider for SQL Server|
different number of columns|information_schema does not exist|
mysql.jdbc.exceptions|GTID set specification|in 'where clause'|
Subquery returns more|org.postgresql.util|String SQLString|
Invalid column name|Incorrect syntax near|invalid floating point|
converting the nvarchar value|error converting expression)
```

---

## 十二、目录遍历特征（信息）

```
(Directory:|Directory listing for|Index of/|Parent Directory|folder listing)
```

---

## 十三、扫描跳过规则

```
跳过文件后缀（二进制/压缩/图片）:
  .dex, .apk, .odex, .so, .png, .jpg, .jar, .class, .zip, .dll, .bks

跳过文件（URL 白名单域名）:
  w3.org, weixin.qq.com (sitemap 声明文件)
```

---

## 实战使用方法

### 1. grep 快速扫描

```bash
# 扫描目录下所有文本文件中的 AK
grep -rnP '\bLTAI[A-Za-z\d]{12,30}\b' /path/to/source/
grep -rnP '\bAKID[A-Za-z\d]{13,40}\b' /path/to/source/
grep -rnP '\b(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b' /path/to/source/

# 扫描密码/密钥赋值
grep -rnP '\b(?:password|passwd|pwd|secret)\b\s*[:=]\s*['\''"]?[^'\''"\s]{3,}' /path/to/source/ --include="*.js" --include="*.json" --include="*.xml"

# 扫描 JWT
grep -rnP 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}' /path/to/source/
```

### 2. Python 批量脚本模板

```python
import re, os, sys

PATTERNS = {
    "阿里云 AK": r'\bLTAI[A-Za-z\d]{12,30}\b',
    "腾讯云 AK": r'\bAKID[A-Za-z\d]{13,40}\b',
    "AWS AK":   r'\b(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b',
    "JWT":      r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}',
    "Password": r'\b(?:password|passwd|pwd)\b\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
    # ... 添加所需规则
}

SKIP_EXT = {'.dex','.apk','.png','.jpg','.jar','.class','.zip','.dll','.so','.bks'}

def scan_file(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    if ext in SKIP_EXT: return
    try:
        with open(filepath, 'r', errors='ignore') as f:
            for lineno, line in enumerate(f, 1):
                for name, pattern in PATTERNS.items():
                    for m in re.finditer(pattern, line):
                        print(f"[{name}] {filepath}:{lineno}: {m.group().strip()}")
    except: pass

def scan_dir(root):
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            scan_file(os.path.join(dirpath, fn))

if __name__ == '__main__':
    scan_dir(sys.argv[1])
```

### 3. 优先级建议

```
拿到源码包后的扫描顺序:
  1. 先扫云 AK/SK — 可直接拿云控制台权限（最高价值）
  2. 再扫 JWT/Session/Token — 可实现身份伪造
  3. 再扫密码/数据库连接串 — 可横向到数据库
  4. 再扫内网 IP/URL — 发现内网拓扑
  5. 最后扫框架指纹 — 识别技术栈，辅助漏洞利用
```
