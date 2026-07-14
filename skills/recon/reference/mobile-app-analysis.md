# 移动应用分析（Android / iOS）— 红队侦察参考

> 适用场景：红队渗透 / SRC 资产整理 / APK 中挖掘硬编码凭据、API 端点、内部域名。
> 运行环境：Kali Linux（AI Agent 执行）。所有命令可直接复制使用。

---

## 1. APK 获取

### 1.1 从官方应用商店下载

```bash
# 华为应用市场（需用手机抓包或通过网页版分析）
# 小米应用商店
# OPPO 软件商店
# Vivo 应用商店
# Google Play（可用 aurora-store 匿名下载）

# aurora-store 命令行下载（无需 Google 账号）
aurora-cli --download com.example.app --path /tmp/
```

### 1.2 APK 镜像站

```bash
# apkpure
wget "https://apkpure.com/com.example.app/download" -O app.apk

# apkmirror
# apkcombo
curl -L "https://apkcombo.com/com.example.app/download/apk" -o app.apk
```

### 1.3 从设备提取（adb）

```bash
# 列出已安装包名
adb shell pm list packages | grep -i target

# 获取 APK 路径
adb shell pm path com.example.app
# 输出: package:/data/app/com.example.app-xxxxx/base.apk

# 拉取 APK
adb pull /data/app/com.example.app-xxxxx/base.apk ./target.apk

# 批量拉取所有 APK（分段应用）
adb shell pm path com.example.app | cut -d: -f2 | while read p; do
    adb pull "$p" "./apk_$(basename $(dirname $p))_$(basename $p)"
done
```

---

## 2. APK 反编译

### 2.1 apktool（smali + 资源）

```bash
# 安装
apt install apktool -y

# 反编译（smali 代码 + 解码资源）
apktool d target.apk -o apktool_output/

# 关键输出目录
# apktool_output/smali*/          — smali 字节码（按 classes.dex 拆分）
# apktool_output/res/              — 解码后的资源文件
# apktool_output/AndroidManifest.xml — 解码后的清单（可读 XML）
# apktool_output/assets/           — 原始 assets
# apktool_output/lib/              — native .so 库
```

### 2.2 jadx（Java 源码重建）

```bash
# 安装
apt install jadx -y

# 反编译为 Java 源码（推荐首选）
jadx -d jadx_output/ target.apk

# 仅反编译为 smali（速度快）
jadx --no-res --no-dex -d jadx_sources/ target.apk

# 命令行搜索（不导出全量）
jadx target.apk 2>/dev/null | grep -i "api\.example"
```

### 2.3 dex2jar + jd-gui（备选方案）

```bash
# dex 转 jar
d2j-dex2jar target.apk -o target.jar

# 用 jd-gui 浏览
jd-gui target.jar

# 或者用通用 Java 反编译器
jad target.jar
```

### 2.4 重点检查的文件

| 文件/目录 | 重要性 | 用途 |
|---|---|---|
| `AndroidManifest.xml` | **必看** | 组件声明、权限、intent-filter |
| `res/values/strings.xml` | **必看** | 硬编码字符串 |
| `resources.arsc` | **必看** | 编译后的资源（apktool 自动解码） |
| `lib/` | 高 | Native .so（含硬编码 Secret/OAuth） |
| `assets/` | **必看** | 内嵌文件、配置文件、H5 资源 |
| `META-INF/` | 中 | 签名信息、证书 |
| `smali*/**/R$string.smali` | 低 | 资源 ID 映射 |

---

## 3. 硬编码凭据提取

### 3.1 strings.xml 快速审计

```bash
cd apktool_output/

# 搜索敏感关键字
grep -rni -E "(api_key|apikey|secret|token|password|auth|private|access_key|appid|appsecret)" res/values/strings.xml

# 搜索所有显式值的字符串
grep -ro '<string name="[^"]*">[^<]*</string>' res/values/strings.xml | grep -iE "(key|secret|token|password|auth|url|host|domain|endpoint)"
```

### 3.2 源码与资源全量搜索

```bash
# 通用敏感模式（适配 Java/Kotlin/XML/JSON）
grep -rE "(api[_\s]?key|app[_\s]?key|secret[_\s]?key|access[_\s]?key|private[_\s]?key|token|auth[_\s]?token|app[_\s]?secret|client[_\s]?secret)" \
    jadx_output/ apktool_output/ --include="*.java" --include="*.xml" --include="*.json" --include="*.smali" -i -n

# 正则匹配字符串赋值模式
grep -rohP '(?:api|app|secret|key|token|password|auth|private|access|bearer)[_\s]*[=:]\s*["\x27][^"\x27]{6,}["\x27]' \
    jadx_output/ --include="*.java" | sort -u
```

### 3.3 Firebase / Google Services 凭据提取

```bash
# 搜索 google-services.json（Firebase 配置）
find apktool_output/ -name "google-services.json" -exec cat {} \;

# 提取 Firebase URL / API Key
jq -r '.project_info.project_id, .client[].api_key[].current_key' apktool_output/assets/google-services.json 2>/dev/null

# 搜索 Google API Key
grep -rohP 'AIza[0-9A-Za-z\-_]{35}' jadx_output/ apktool_output/ | sort -u

# 搜索 AWS AKID 模式
grep -rohP 'AKIA[0-9A-Z]{16}' jadx_output/ apktool_output/ | sort -u

# 阿里云 AccessKey
grep -rohP 'LTAI[0-9A-Za-z]{12,20}' jadx_output/ apktool_output/ | sort -u
```

### 3.4 Native .so 库分析

```bash
# 从 .so 中提取所有可读字符串
find apktool_output/lib/ -name "*.so" -exec strings {} \; | grep -iE "(api|secret|key|token|auth|password|http)"

# 搜索特定模式
find apktool_output/lib/ -name "*.so" | while read so; do
    echo "=== $so ==="
    strings "$so" | grep -E "(https?://|[A-Za-z0-9+/]{40,})"
done
```

---

## 4. 网络配置发现

### 4.1 AndroidManifest.xml 关键检查点

```bash
cd apktool_output/

# 导出组件（可被外部调用）
grep -A5 'android:exported="true"' AndroidManifest.xml | grep -E "(activity|service|receiver|provider)"

# Deep Link / URL Scheme
grep -E 'android:scheme' AndroidManifest.xml | head -20

# 权限声明
grep '<uses-permission' AndroidManifest.xml

# 自定义权限（可能暴露内部组件）
grep '<permission' AndroidManifest.xml
```

### 4.2 Network Security Config

```bash
# 检查网络安全配置
find apktool_output/ -path "*/res/xml/*" -name "*.xml" | while read f; do
    if grep -q "network-security-config\|domain-config\|trust-anchors\|pin-set" "$f" 2>/dev/null; then
        echo "=== $f ==="
        cat "$f"
    fi
done

# 关键关注点：
# 1. <domain-config cleartextTrafficPermitted="true"> — 明文 HTTP 允许的域名
# 2. <pin-set> / <pin digest="SHA-256"> — 证书固定（绕过需要针对性 Frida）
# 3. <trust-anchors> — 信任的 CA 来源
```

### 4.3 硬编码 URL/域名/IP 提取

```bash
# 提取所有 URL
grep -rohP 'https?://[a-zA-Z0-9._/\-?=&#%+]+' jadx_output/ apktool_output/ 2>/dev/null | sort -u | grep -v 'schemas.android.com' > extracted_urls.txt

# 提取 IP 地址
grep -rohP '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' jadx_output/ 2>/dev/null | sort -u | grep -v '0\.0\.0\.0\|127\.0\.0\.1' > extracted_ips.txt

# 提取域名
grep -rohP '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}' jadx_output/ 2>/dev/null | sort -u | grep -v '\.java$\|\.xml$\|\.png$\|\.jpg$\|\.so$' > extracted_domains.txt

# 统计去重数量
wc -l extracted_urls.txt extracted_ips.txt extracted_domains.txt
```

---

## 5. 证书固定绕过（测试用）

### 5.1 Frida SSL Pinning Bypass

```bash
# 安装 Frida 工具
pip install frida-tools objection

# 通用 SSL Pinning Bypass 脚本（ssl_bypass.js）
cat > ssl_bypass.js << 'EOF'
Java.perform(function() {
    // 绕过 OkHttp3 CertificatePinner
    try {
        var OkHttpCertPinner = Java.use("okhttp3.CertificatePinner");
        OkHttpCertPinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
            console.log("[*] OkHttp3 check bypassed: " + hostname);
            return;
        };
    } catch(e) {}
    
    // 绕过 TrustManager
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, endpoint, isEnabled) {
            console.log("[*] TrustManager verifyChain bypassed: " + host);
            return untrustedChain;
        };
    } catch(e) {}
    
    // 绕过自定义 TrustManager
    try {
        var X509TrustManagerExtensions = Java.use("android.net.http.X509TrustManagerExtensions");
        X509TrustManagerExtensions.checkServerTrusted.implementation = function(chain, authType, host) {
            console.log("[*] X509TrustManagerExtensions bypassed: " + host);
            return Java.array('java.security.cert.X509Certificate', chain);
        };
    } catch(e) {}
});
EOF

# 附加到应用
frida -U -l ssl_bypass.js -f com.example.app

# 如果应用已运行
frida -U -l ssl_bypass.js com.example.app
```

### 5.2 Objection 一键绕过

```bash
# 启动 objection
objection -g com.example.app explore

# 在 objection 控制台中
# android sslpinning disable
# android root disable
```

### 5.3 代理设置

```bash
# Burp Suite 监听（Kali 本机）
# 默认 127.0.0.1:8080

# Android 设备代理设置
# 方法1：WiFi 代理手动设置 → 指向 Kali IP:8080
# 方法2：adb 反向代理（USB 连接）
adb reverse tcp:8080 tcp:8080
# 然后 WiFi 代理指向 127.0.0.1:8080

# 安装 Burp 证书到设备
# 1. 导出 Burp CA (Der 格式) → cacert.der
# 2. Push 到设备
adb push cacert.der /sdcard/
# 3. 在设备上 设置 → 安全 → 从 SD 卡安装

# mitmproxy 替代方案
mitmweb --listen-port 8080
# 设备同样配置代理指向 Kali IP:8080
```

---

## 6. IPA（iOS）分析概述

### 6.1 IPA 获取与解密

```bash
# App Store IPA 下载工具（需 macOS + 已购记录）
# ipatool: https://github.com/majd/ipatool
ipatool download -b com.example.app --output /tmp/

# 越狱设备解密（Clutch）
# 在设备上运行
Clutch -i          # 列出已安装应用
Clutch -d 1        # 解密第1个应用

# bfdecrypt（越狱设备替代）
# 通过 Cydia 安装 bfdecrypt，在设备上对目标 App 启用解密
```

### 6.2 二进制分析

```bash
# IPA 实质是 zip，解压即可
unzip target.ipa -d ipa_extracted/

# 关键文件
# Payload/xxx.app/xxx           — Mach-O 可执行文件
# Payload/xxx.app/Info.plist    — 配置信息
# Payload/xxx.app/*.bundle/     — 资源 bundle

# 可读字符串提取
strings Payload/xxx.app/xxx | grep -iE "(api|secret|key|token|password|auth|http)"

# otool 分析
otool -L Payload/xxx.app/xxx          # 动态库依赖
otool -l Payload/xxx.app/xxx          # Mach-O 加载命令
otool -hv Payload/xxx.app/xxx         # 架构信息

# class-dump（导出 ObjC 类定义）
class-dump -H -o class_dump_output/ Payload/xxx.app/xxx
```

### 6.3 Plist 配置检查

```bash
cd ipa_extracted/

# Info.plist — 关键检查项
plutil -p Payload/xxx.app/Info.plist | grep -iE "(url|scheme|domain|query|security|transport)"
# CFBundleURLSchemes    — URL Scheme (Deep Link)
# NSAppTransportSecurity — ATS 配置（允许非 HTTPS 的域名）
# UIBackgroundModes     — 后台运行模式

# 检查 ATS 例外（允许 HTTP 明文）
plutil -p Payload/xxx.app/Info.plist | grep -A30 "NSAppTransportSecurity"

# entitlements（权限声明）
# 从 embedded.mobileprovision 或二进制中提取
codesign -d --entitlements - Payload/xxx.app/xxx 2>/dev/null
```

---

## 7. UniApp / Hybrid 混合应用分析

### 7.1 UniApp (uni-app / wap2app)

```bash
# UniApp 打包的 APK 中，业务逻辑在 assets/apps/ 或 assets/data/ 下
find apktool_output/assets/ -name "*.js" -o -name "app*.js" | head -20

# 核心 JS 文件（包含路由、API 配置）
cat apktool_output/assets/apps/__UNI__xxxxxx/www/app-service.js | head -200

# 搜索 API 端点
grep -rohP 'https?://[a-zA-Z0-9._/\-]+' apktool_output/assets/apps/ | sort -u > uni_endpoints.txt

# 搜索硬编码 Token/Secret
grep -rE "(token|secret|appid|apikey|signkey)" apktool_output/assets/apps/
```

### 7.2 Cordova / PhoneGap

```bash
# Cordova 资源在 assets/www/
cat apktool_output/assets/www/cordova.js
cat apktool_output/assets/www/cordova_plugins.js

# config.xml — Cordova 配置
cat apktool_output/assets/www/config.xml
# 关注 <access origin="*"> — 允许任意远程资源加载
# 关注 <allow-navigation> — 允许的导航域名
```

### 7.3 React Native

```bash
# React Native 打包在 assets/index.android.bundle
# 这是打包后的 JS Bundle（Hermes 或 JSC）
file apktool_output/assets/index.android.bundle

# 提取可读内容
strings apktool_output/assets/index.android.bundle | grep -iE "(api|baseUrl|endpoint|secret|token)"

# Hermes 字节码（.hbc 文件）需要专用工具反编译
# 工具: hbctool / hermes-dec
find apktool_output/ -name "*.hbc" -o -name "index.android.bundle"
```

### 7.4 Flutter

```bash
# Flutter APK 特征：lib/ 下有 libflutter.so，assets/ 下有 flutter_assets/
ls apktool_output/lib/ | grep flutter
ls apktool_output/assets/flutter_assets/ 2>/dev/null

# Flutter Dart 代码编译为 libapp.so（release 模式）
# 使用 blutter 进行逆向
# https://github.com/worawit/blutter

# 提取 libapp.so 中的 AOT 快照
find apktool_output/ -name "libapp.so" -exec ls -lh {} \;

# 字符串提取
strings apktool_output/lib/*/libapp.so | grep -iE "(api|secret|key|token|url|http)" | sort -u

# Flutter 资源文件
ls apktool_output/assets/flutter_assets/
# kernel_blob.bin     — Dart Kernel (debug 模式可用标准工具分析)
# AssetManifest.json  — 资源清单
```

---

## 8. 集成到 Recon 流程

### 8.1 输出对接

```bash
#!/bin/bash
# 将 APK 分析结果合并到 recon 输出

APK_OUT="jadx_output"
RECON_DIR="../../../recon_output"  # 根据实际项目结构调整

# 1. API 端点 → endpoints.no_auth
grep -rohP 'https?://[a-zA-Z0-9._/\-?=&#%+]+' "$APK_OUT" 2>/dev/null | \
    grep -v 'android.com\|google.com\|schemas.android' | \
    sort -u >> "$RECON_DIR/endpoints.no_auth"

# 2. 硬编码凭据 → info_leaks
grep -rE "(api_key|apikey|secret_key|app_secret|token|password|access_key|AKID|AKIA)" \
    "$APK_OUT" 2>/dev/null >> "$RECON_DIR/info_leaks"

# 3. 内部域名/IP → 新目标（手动评估后加入）
grep -rohP '[a-zA-Z0-9.-]+\.(?:internal|local|corp|dev|test|staging)(?:\.[a-zA-Z]{2,})?' \
    "$APK_OUT" 2>/dev/null | sort -u >> "$RECON_DIR/internal_domains"

# 4. Firebase 项目 → 独立追踪
find apktool_output/ -name "google-services.json" -exec cat {} \; 2>/dev/null | \
    jq '{project_id: .project_info.project_id, api_keys: [.client[].api_key[].current_key], 
         storage_bucket: .project_info.storage_bucket}' >> "$RECON_DIR/firebase_projects.json"
```

### 8.2 结果索引

```bash
# 生成分析摘要
echo "=== APK 分析摘要 ==="
echo "APK 文件: $(du -h target.apk | cut -f1)"
echo "提取 URL 数: $(cat extracted_urls.txt 2>/dev/null | wc -l)"
echo "提取 IP 数: $(cat extracted_ips.txt 2>/dev/null | wc -l)"
echo "提取域名数: $(cat extracted_domains.txt 2>/dev/null | wc -l)"
echo ""
echo "硬编码凭据发现:"
grep -rE "(AKID|AKIA|LTAI|AIza|ghp_|sk-|xox[baprs]-)" jadx_output/ 2>/dev/null | head -10
```

### 8.3 自动化批量脚本骨架

```bash
#!/bin/bash
# batch_apk_analyze.sh — 批量 APK 分析
# 用法: ./batch_apk_analyze.sh apk_dir/ output_dir/

APK_DIR="${1:-./apks}"
OUT_DIR="${2:-./apk_analysis}"

mkdir -p "$OUT_DIR"

for apk in "$APK_DIR"/*.apk; do
    name=$(basename "$apk" .apk)
    echo "[*] 分析: $name"
    
    # 反编译
    apktool d -f "$apk" -o "$OUT_DIR/${name}_apktool" 2>/dev/null
    jadx -d "$OUT_DIR/${name}_jadx" "$apk" 2>/dev/null
    
    # 快速搜索
    echo "   [URL]" && grep -rohP 'https?://[^\x27"]+' "$OUT_DIR/${name}_apktool" 2>/dev/null | sort -u > "$OUT_DIR/${name}_urls.txt"
    echo "   [KEY]" && grep -rE '(api|secret|key|token|password)[\s:=]+["\x27]' "$OUT_DIR/${name}_apktool" 2>/dev/null | head -50 > "$OUT_DIR/${name}_secrets.txt"
    
    echo "   [完成] URL:$(wc -l < "$OUT_DIR/${name}_urls.txt"), Keys:$(wc -l < "$OUT_DIR/${name}_secrets.txt")"
done

echo "[*] 全量分析完成，输出目录: $OUT_DIR"
```

---

## 附录：常见凭据模式速查

| 云平台/服务 | 模式 |
|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| AWS Secret Key | Base64 40 字符 |
| 阿里云 AccessKey | `LTAI[0-9A-Za-z]{12,20}` |
| 腾讯云 SecretId | `AKID[0-9A-Za-z]{32}` |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` |
| GitHub Token | `ghp_[0-9A-Za-z]{36}` / `github_pat_` |
| OpenAI Key | `sk-[0-9A-Za-z]{48}` / `sk-proj-` |
| Slack Token | `xox[baprs]-[0-9A-Za-z\-]+` |
| Firebase URL | `https://[a-z0-9-]+\.firebaseio\.com` |
| JWT Token | `eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*` |
| Base64 大段 | `[A-Za-z0-9+/]{40,}={0,2}` |
