# 工具生态与数据源参考

> 已下载到 `\\<HOSTNAME>\share\stcs\tools\` 的所有工具索引。

## 指纹识别类

### FLUX-Webscan (https://github.com/MY0723/FLUX-Webscan)
- **数据**: `data/fingerprints_merged_v5.json` — 33,107 条指纹 (EHole 24,945 + Veo 500 + TideFinger 8,012)
- **分类**: OA(~800), CMS(~2500), Network(~1800), Security(~700), ERP(~400), WebServer(~400), Cloud(~300), Framework(~200), DevTool(~150), Database(~120), Monitoring(~70), MessageQueue(~30), Panel(~20), Other(~25000)
- **来源**: flux_ehole(24,945), flux_veo(500), tidefinger_tide(6,470), tidefinger_cms(1,398), tidefinger_fofa(144)
- **方法**: body(~25000), header(~7000), faviconhash(~800), url(~300)
- **级别**: L1(6514 强特征), L2(18581 中特征)
- **配置**: `config/rules.yaml` — 指纹权重、特征分级、置信度阈值、互斥组
- **已集成**: 敏感规则已入 build_rules.py (78条), 差分测试方法入 web-exploit, WAF知识入 waf-bypass

### EHole (https://github.com/EdgeSecurityTeam/EHole)
- **数据**: `finger.json` — 4,792 行指纹规则 (FLUX 已合并此库)
- **方法**: keyword match (body/title/header)
- **用途**: 重点资产指纹识别 + 漏洞检测

### TideFinger (https://github.com/TideSec/TideFinger)
- **数据**: `python3/technologies.json` — 26,732 行 Wappalyzer 格式指纹 (25 类: CMS/论坛/电商/博客/WebServer/JS框架等)
- **数据**: `python3/cms_finger.db` — SQLite 双表指纹库
  - `tide` 表: 5,928 条 header/body/title 关键词规则，支持布尔逻辑 (`||` OR / `&&` AND / 嵌套 `1||2||(3&&4)`)
  - `cms` 表: 2,073 条路径指纹，3 种匹配方式 (md5/keyword/regex)，566 种 CMS
  - `fofa_back` 表: 2,118 条 FOFA 平台提取指纹
- **方法**: 三引擎融合 (tide SQLite + cms_finger SQLite + Wappalyzer JSON) → 结果合并 → 子串去重
  - 引擎 1 (Cmsscanner): 从 tide 表读规则 → header/body/title 关键词 + 布尔逻辑组合匹配
  - 引擎 2 (WhatCms): 从 cms 表读规则 → 路径请求 + md5/keyword/regex 匹配，hit 列自学习评分
  - 引擎 3 (Wappalyzer): 标准 Wappalyzer 分析 (url/html/scripts/headers/meta/implies/cookies)
  - 合并去重: `banner.sort()` + 子串包含检测 (`str(x).lower() in str(y).lower()`)
- **特色**: 多方法交叉验证, favicon hash 强特征, 162 条优先匹配 CMS 列表, 命中追踪自学习机制
- **已本地化**: ✅ 三引擎架构 + 布尔逻辑规则引擎 + 命中评分自学习方法论已分析。10,119条SQLite记录解析布尔逻辑后提取8,012条独立指纹合并入 fingerprints_merged_v5.json (33,107条)。tide表布尔逻辑(AND/OR/嵌套)拆分算法入 merge_tidefinger.py。

## WAF 检测类

### wafw00f (https://github.com/EnableSecurity/wafw00f)
- **数据**: `wafw00f/plugins/` — 182 个 WAF 检测插件
- **方法**: Header + Cookie + Content + Status + Reason 五维匹配
- **关键国产 WAF 插件**: aliyundun, anquanbao, anyu, baidu, chinacache, yundun, yunsuo, safedog, 360, tencent
- **已集成**: FLUX v5.4.1 已融合 wafw00f, 我们的 waf-bypass SKILL.md 已有专项章节
- **已本地化**: ✅ 提取 12 款 WAF 检测签名 (阿里云盾/腾讯云/安全狗/云锁/安全宝/安域/百度云加速/360网站宝/360磐云/Cloudflare/ModSecurity/ChinaCache) 植入 waf-bypass SKILL.md 的「WAF 检测签名速查」章节，包含 Header/Cookie/Content/Status 各维度的正则匹配规则 + 快速检测脚本 + 交叉验证方法论

## 敏感信息检测类

### database_scan (https://github.com/RuoJi6/database_scan)
- **功能**: Go 语言 CLI, 扫描数据库中敏感信息
- **覆盖**: MySQL/MariaDB/TiDB, MSSQL, PostgreSQL, Oracle + 多种数据库
- **检测类型**: 手机号(1[3-9]\d{9})、身份证(\d{17}[\dXx])、地址(省市区关键词)、账号([A-Za-z0-9_.@-]{3,64})、密码(.{6,})、邮箱、银行卡(\d{13,19})
- **已本地化**: ✅ detector.go 的 7 类正则 + 字段名关键词双验证方法论已分析。检测规则(手机/身份证/邮箱/银行卡/密码/地址/账号)已在 build_rules.py 有对应规则覆盖，且我们的规则更全面(87条含 Credit-001~9, Personal-001~4 等)。SQLPattern 方法(Level 分级 SQL 注入检测)可补充到 sensitive_scanner 的数据库扫描模式。

### BurpAPIFinder (https://github.com/shuanx/BurpAPIFinder)
- **数据**: `conf/finger-important.json` — 106 条 API 响应指纹规则
- **规则类型**: 敏感内容(86), 有价值信息(10), 敏感路径(7)
- **303 个独特关键词**: 覆盖账号/密码/手机/邮箱/身份证/银行卡/Token/密钥/配置文件路径
- **特色**: 结合 Content-Type: application/json 上下文降低误报

## Payload 库

### PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings)
- **内容**: 30+ 漏洞类型, 每种包含多个 payload 文件
- **目录**: SQL Injection, XSS Injection, Command Injection, File Inclusion, SSRF, SSTI, XXE, NoSQL, GraphQL, LDAP, Upload, CORS, CRLF, CSRF, Clickjacking, Race Condition, Request Smuggling 等
- **用途**: 所有 web-exploit 漏洞测试的 payload 参考源
- **已本地化**: ✅ 提取并精简核心 payload 至 `web-exploit/reference/payload-cheatsheet.md`（10 大类: MySQL注入/命令注入/SSRF/SSTI/XXE/文件包含/XSS/NoSQL/CRLF/JWT），含 WAF 绕过变体、编码技巧、OOB 外带方法、多语言模板 RCE。PAT 完整版仍在 `tools/PayloadsAllTheThings/` 作为补充参考。

## JS 分析类

### Webpack_extract (https://github.com/xz-zone/Webpack_extract)
- **功能**: Chrome 扩展, Webpack 打包文件的模块提取和 JS 分析
- **数据**: `Rules.js` — 36 条检测规则 (HaE 格式), 分 5 组
- **分组**: 指纹识别(7: Shiro/JWT/Swagger/Ueditor/Druid/PDF.js/Vite), 潜在漏洞(7: Java反序列化/Debug参数/URL注入/上传表单/DoS参数/passwd/win.ini), 基础信息(5: Email/身份证/手机/内网IP/MAC), 敏感信息(10: 云密钥/Windows路径/密码字段/用户名字段/企业微信/JDBC/Auth头/敏感字段/手机字段/用户信息链接), 其他(9: Linkfinder/SourceMap/Webpack Chunk/URL Schemes/Router Push/全URL/请求URI/302Location/OSKeys)
- **方法论**: 双向匹配(password字段检测匹配key→value和value→key两个方向)、Chrome扩展注入共享JS上下文直接从window对象读Webpack模块注册表、background.js代理绕过CORS跨域获取外部chunk
- **已本地化**: ✅ 提取 4 条独特规则入 build_rules.py (CRED-028企业微信凭据/INFO-011调试管理参数/INFO-012 Windows文件路径/FRAME-008 Vite DevMode)。36 条规则全览 + 架构分析已写入 `web-exploit/reference/webpack-extraction.md` 第7节。

### Packer-Fuzzer (https://github.com/rtcatc/Packer-Fuzzer)
- **功能**: JS 打包工具 (Webpack) 的自动化信息提取和参数 Fuzzing
- **数据**: `config.ini` — 19 条 infoTest 敏感字段规则, 7 类 blacklist 过滤规则, 5 类 vuln 测试配置
- **vuln 模块** (Lib/vuln/):
  - InfoTest: JS 响应中敏感字段检测 (REDIS_PM/APP_KEY/password/AccessKeyId/token 等 19 类)
  - CorsTest: CORS 配置错误检测 (Origin 头反射 + Access-Control-Allow-Credentials: true)
  - UnAuthTest: 未授权访问检测 (API 响应不含登录失败关键词即判定未授权)
  - UploadTest: 文件上传漏洞检测 (45+ 种后缀绕过: asp;.jpg/php::$DATA/.jsp.jpg.jsp 等 + PNG 文件头伪装)
  - BacTest: 越权访问检测 (数值型参数遍历 1-5, 响应包大小差异分析)
  - PasswordTest: 弱口令爆破 (username.dic + password.dic 字典, 支持 GET/POST/JSON 三种参数格式)
- **blacklist 规则**: 6 个 JS 文件名过滤 (jquery.js 等), 2 个域名过滤 (百度地图/阿里支付), 40+ 个 API 扩展名过滤
- **已本地化**: ✅ 19 条 infoTest 规则入 build_rules.py (CRED-PF0001~0019)。vuln 模块方法论已分析: resultFilter/unauth_not_sure/login 关键词库可复用。上传后缀绕过字典 45 条可入 path字典。

### LinkFinder (https://github.com/GerbenJavado/LinkFinder)
- **功能**: JavaScript 文件中 URL/端点提取
- **场景**: 在 JS 中自动发现 API 端点、内部路径

### FindSomething (https://github.com/momosecurity/FindSomething)
- **功能**: 浏览器插件, 被动提取页面中的信息
- **数据**: `background.js` — 725 条 JS regex 规则 (nuclei_regex 数组)
- **规则分类**: api_key(208), password(120), secret(89), token(72), client_id(45), access_token(38), client_secret(35), database(28), ssh_key(22), cloud(18), url(15), email(12), webhook(8), crypto(6), payment(5), git(5), ftp(3), license(3), username(2), other(1)
- **方法**: 正则匹配 JS 变量赋值模式 (`key["']?\s*[=:]\s*["']?value["']?`), 从变量名推断凭据类型
- **已本地化**: ✅ 提取 705 条独特规则入 build_rules.py (CRED-FS0001~0705), 0 条重复。提取脚本: `extract_findsomething.py`

### JSFinder (https://github.com/Threezh1/JSFinder)
- **功能**: JS 文件中的 URL 和域名提取
- **数据**: 核心正则 (LinkFinder 同源) — 4 类 URL 匹配模式
- **模式**: (1) 绝对 URL `(?:[a-zA-Z]{1,10}://|//)` (2) 相对路径 `/(?:/|\.\./|\./)` (3) 扩展名路径 `\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)` (4) 文件名+特定扩展名
- **方法**: BeautifulSoup 解析 HTML → 提取 `<script>` 标签 → 正则提取 URL → 域名过滤 → 子域名发现
- **已本地化**: ✅ URL 提取正则已分析, 与 LinkFinder 同源的 4 类模式可作为 JS 端点提取规则参考。

### URLFinder (https://github.com/pingc0y/URLFinder)
- **功能**: 网页中 URL 的快速提取和分类
- **数据**: `config/config.go` — 3 条 JS 发现正则, 5 条 URL 发现正则, 5 类敏感信息正则
- **敏感信息**: Phone(`1[3-9]\d{9}`), Email(RFC 5322), IDcard(18位+校验), JWT(`eyJ...`), Other(access key/密码/账号/加密/解密/password/username)
- **JsFuzzPath**: 11 个常见 JS 文件名 (login.js/app.js/main.js/config.js/admin.js/info.js/open.js/user.js/input.js/list.js/upload.js)
- **Risks 关键词**: remove/delete/insert/update/logout (危险操作参数)
- **过滤规则**: JsFiler(2条域名过滤), UrlFiler(2条正则过滤静态资源+扩展名)
- **已本地化**: ✅ 敏感信息正则已在 build_rules.py 有对应覆盖。11 个 JsFuzzPath 可入 JS 字典。Risks 危险操作关键词可入参数 Fuzzing 字典。

## 路径/子域名扫描类

### 7kbscan-WebPathBrute (https://github.com/7kbstorm/7kbscan-WebPathBrute)
- **功能**: 高性能 Web 路径爆破
- **数据**: ZIP 内嵌 `Dic/` 目录 — 14 个字典文件
- **字典文件**: custom.txt(141,672), 备份文件.txt(46,441), weblogic.txt(529), tomcat.txt(355), spring.txt(283), thinkphp.txt(224), struts2.txt(201), php.txt(156), apache.txt(127), jetty.txt(96), jboss.txt(40), 压缩文件后缀.txt(31), jdk.txt(22), 各CMS集成测试环境.txt(7)
- **已本地化**: ✅ 14 个字典文件全部解压，路径合并入 `dict_merged_paths.json` (212,921 条)

### dirsearch (https://github.com/maurosoria/dirsearch)
- **功能**: 经典的 Web 路径扫描器
- **数据**: `db/dicc.txt` — 9,680 条常规路径字典
- **特点**: 多线程、递归扫描、自定义状态码过滤
- **已本地化**: ✅ dicc.txt 路径合并入 `dict_merged_paths.json`

### BBScan (https://github.com/lijiejie/BBScan)
- **功能**: 批量扫描大量目标的敏感路径
- **数据**: `rules/` — 18 个规则文件 (346 条规则, 339 条去重路径)
- **规则格式**: `/path {status=CODE} {tag="keyword"} {type="mimetype"} {type_no="..."} {root_only}` — 含条件匹配
- **规则分类**: compressed_backup_files(135条), java_web_config(58条), sensitive_url(47条), config_file(24条), source_code_disclosure(13条), directory_traversal(11条), test_page(10条), shell_script(9条), ssh_sensitive(8条), web_editors(7条), phpinfo(6条), change_log(5条), git_and_svn(4条), phpmyadmin(4条), go_pprof(2条), tomcat(1条), graphite_ssrf(1条), jsf(1条)
- **black.list**: 21 条 404/403/错误页面过滤规则 (正则匹配，减少误报)
- **已本地化**: ✅ 339 条独特路径 + 条件匹配格式完整提取到 `data/bbscan_paths.json`。路径合并入 `dict_merged_paths.json` (+310 新路径)

### OneForAll (https://github.com/shmilylty/OneForAll)
- **功能**: 综合性子域名收集工具 (6 个 API 模块 + 字典爆破)
- **数据**: `data/` 目录
  - `subnames.txt` (95,266) — 基础子域名字典
  - `subnames_medium.txt` (880,196) — 中等规模字典 (最大单文件)
  - `subnames_next.txt` (1,722) — 新一代字典
  - `altdns_wordlist.txt` (222) — 变更排列字典
  - `fingerprints.json` (48) — 子域名接管指纹 (CNAME + Response 匹配)
  - `cdn_cname_keywords.json` (209) — CDN CNAME 关键词 (Akamai/CloudFlare/阿里云/腾讯云/ChinaCache...)
  - `srv_prefixes.json` (100) — SRV 记录前缀 (_ldap._tcp, _kerberos._tcp, _sip._tcp...)
  - `common_js_library.json` (625) — 常见 JS 库文件名 (vue.js/react.js/jquery.js/webpack.js...)
  - `cdn_header_keys.json` (48) — CDN 响应头关键词
- **已本地化**: ✅ 4 个字典文件合并入 `dict_merged_subdomains.json` (882,331 条)。48 条接管指纹 + 209 条 CDN 特征 + 100 条 SRV 前缀 + 625 条 JS 库列表提取到 `data/oneforall_data.json`。

### Sublist3r (https://github.com/aboul3la/Sublist3r)
- **功能**: 子域名枚举 (多搜索引擎 + 字典爆破)
- **数据**: `subbrute/names.txt` — 129,406 条子域名字典
- **搜索引擎**: Google, Yahoo, Bing, Baidu, Ask, Netcraft, DNSdumpster, ThreatCrowd, SSL Certificates, PassiveDNS
- **subbrute 模块**: 多级 DNS 解析爆破 (names.txt + resolvers.txt)
- **已本地化**: ✅ names.txt 合并入 `dict_merged_subdomains.json` (+1 新条目, 99.999% 已被 OneForAll 覆盖)

### subDomainsBrute (https://github.com/lijiejie/subDomainsBrute)
- **功能**: 高性能子域名爆破 (Python 多线程 + DNS 解析)
- **数据**: `dict/` — 6 个字典文件: next_sub_full.txt(60,089), next_sub.txt(6,252), sld.txt(3,244), subnames.txt(5,984), next_large_1.txt(536), next_large_2.txt(14)
- **已本地化**: ✅ 6 个字典文件合并入 `dict_merged_subdomains.json`

## 网络扫描类

### masscan (https://github.com/robertdavidgraham/masscan)
- **功能**: 超快速端口扫描 (C 源码, 异步无状态 SYN 扫描)
- **特点**: 互联网级速度 (6 分钟扫全网), 无字典需要提取
- **已本地化**: ✅ 工具可用，无额外数据需提取 (C 源码无字典/规则库)

## 反序列化类

### phpggc (https://github.com/ambionics/phpggc)
- **功能**: PHP 反序列化 gadget 生成库
- **数据**: `gadgetchains/` — 45 个框架/库, 149+ 条利用链
- **利用类型**: RCE(远程代码执行), FD(文件删除), FR(文件读取), FW(文件写入), SQLI(SQL注入), SSRF, XXE, AT(任意表操作), INFO(信息泄露), PsySH(交互Shell)
- **TOP 框架**: Laravel(23链: FD+22RCE), Symfony(19链: FD+2FW+16RCE), Monolog(10链: FW+9RCE), CodeIgniter4(9链), Drupal(7链), SwiftMailer(7链), ThinkPHP(6链)
- **已本地化**: ✅ 149 条链的框架/类型/版本/向量元数据已提取并保存到 `data/phpggc_chains.json`。可作为 PHP 反序列化漏洞利用的速查表: 按目标框架查找可用链。

## 源代码泄露利用

### GitHack (https://github.com/lijiejie/GitHack)
- **功能**: .git 源码泄露利用 (Python 2/3)
- **方法**: 请求 `/.git/index` → 解析 entries (sha1 + name) → 下载 `/.git/objects/{sha1[:2]}/{sha1[2:]}` → zlib 解压 → 还原源码
- **检测路径**: `/.git/index`, `/.git/config`, `/.git/HEAD`, `/.git/objects/xx/*`
- **已本地化**: ✅ 利用链已分析。.git 泄露检测路径已在 BBScan git_and_svn.txt 规则文件中覆盖 (合并入 `bbscan_paths.json`)

### SvnHack (https://github.com/callmefeifei/SvnHack)
- **功能**: .svn 源码泄露利用 (Python 2)
- **方法**: 请求 `/.svn/entries` → 正则 `\n(.*?)\ndir` 解析目录 / `\n(.*?)\nfile` 解析文件 → 递归遍历子目录 → 下载 `/.svn/text-base/{file}.svn-base` → 还原文件
- **检测路径**: `/.svn/entries`, `/.svn/text-base/*.svn-base`
- **已本地化**: ✅ 利用链已分析。.svn 泄露检测路径已在 BBScan git_and_svn.txt 规则文件中覆盖 (合并入 `bbscan_paths.json`)

### DigDeep (https://github.com/shine798/DigDeep)
- **功能**: Java JAR 敏感信息深度挖掘工具
- **规则**: ~100 条敏感信息检测规则（编译在 JAR 内，源码不可直接提取）
- **覆盖类型**: 云 AK/SK、密码/密钥、JWT Token、Webhook URL、手机号、身份证、邮箱、IP/MAC 地址、Swagger/Druid 路径、SQL 错误信息、SSRF 参数、JSONP callback、Source Map 文件
- **方法**: 正则匹配 + 文件名扫描 + HTTP 响应内容检测
- **已本地化**: ✅ README 方法论已分析。检测规则在 build_rules.py 已有大量覆盖。经 815 条规则合并后，DigDeep 覆盖的类型全部已纳入。

## Header Fuzzing 参考

### headers.txt (z1sec/Testing)
- **数据**: 331 个 HTTP 头, 覆盖标准 RFC、CORS、CDN/缓存、AWS/Azure/GCP、浏览器指纹、APM、安全框架
- **已保存**: `\\<HOSTNAME>\share\stcs\tools\headers.txt`
- **用法**: 参数 Fuzzing 时的 Header 字典, 敏感 Header 检测 (如 X-Sina-Safe-* 系列)

## 合并统计 (2026-05-27)

| 数据类型 | 来源 | 数量 |
|---------|------|------|
| **敏感规则** (build_rules.py) | 原生 + yakit + flux + burpapifinder + webpack + webpack_extract + findsomething + packer-fuzzer | **815 条** |
| **指纹规则** (fingerprints_merged_v5.json) | flux_ehole + flux_veo + tidefinger_tide + tidefinger_cms + tidefinger_fofa | **33,107 条** |
| **合并路径字典** (dict_merged_paths.json) | dirsearch + 7kbscan(14文件) + BBScan(339规则) | **212,921 条** |
| **合并子域名字典** (dict_merged_subdomains.json) | subDomainsBrute(6文件) + OneForAll(4文件) + Sublist3r | **882,331 条** |
| **合并关键词字典** (dict_merged_keywords.json) | Packer-Fuzzer(auth/success/risky) + URLFinder(regex) | **75 条关键词 + 22 上传后缀** |
| **BBScan 路径规则** (bbscan_paths.json) | BBScan rules/ (18文件, 346规则) | **339 条去重路径** |
| **OneForAll 综合数据** (oneforall_data.json) | 指纹 + CDN + SRV + JS库 | **982 条** |
| **phpggc 利用链** (phpggc_chains.json) | phpggc gadgetchains/ (42框架) | **152 条链** |
| **上传后缀字典** (dict_upload_extensions.json) | Packer-Fuzzer UploadTest | **45 条** |
| **JS FuzzPath** (dict_js_fuzzpath.json) | URLFinder JsFuzzPath | **11 条** |
| **Risky 参数** (dict_risky_params.json) | URLFinder Risks | **5 条** |
| **URLFinder 正则** (dict_sensitive_regex_urlfinder.json) | URLFinder config | **5 条** |

| 来源覆盖度分析 | |
|---|---|
| Sublist3r vs OneForAll 子域名覆盖率 | 99.999% 重叠 (129,406 条中仅 1 条新) |
| BBScan vs dirsearch+7kbscan 路径覆盖率 | 91.4% 重叠 (339 条中 310 条新) |
| 7kbscan custom.txt 单文件 | 141,672 条路径 (最大单来源) |

| 敏感规则分类 | 数量 | 级别分布 |
|------------|------|---------|
| 凭据泄露 | 686 | critical:18, high:598, medium:54, low:16 |
| 信息泄露 | 78 | high:30, medium:15, low:33 |
| 框架资产发现 | 19 | high:19 |
| AI基础设施暴露 | 9 | high:9 |
| API响应敏感字段 | 9 | high:9 |
| 基础设施识别 | 8 | high:9, info:6 |
| 基础设施暴露 | 5 | high:5 |
| 异常暴露 | 1 | high:1 |

| 已本地化工具 (23/23) | 状态 |
|------------|------|
| FLUX-Webscan (指纹) | 33,107 条合并 |
| EHole (指纹) | FLUX 已合并 |
| TideFinger (指纹) | 8,012 条合并 |
| wafw00f (WAF 检测) | 12 款 WAF 签名 |
| database_scan (敏感信息) | 方法论已分析 |
| BurpAPIFinder (API指纹) | 9 条规则 |
| Webpack_extract (JS规则) | 4 条规则 |
| Packer-Fuzzer (信息+漏洞) | 19 条规则 + vuln方法论 + 字典 |
| FindSomething (JS凭据) | 705 条规则 |
| BBScan (路径扫描) | 339 条路径 + 规则格式 |
| JSFinder (JS URL提取) | 4 类正则 |
| URLFinder (URL+敏感) | 完整字典提取 |
| phpggc (反序列化链) | 152 条链 |
| PayloadsAllTheThings | 核心 payloads |
| DigDeep (Java敏感信息) | 方法论已分析 |
| headers.txt | 331 HTTP headers |
| 7kbscan-WebPathBrute | 14 字典文件合并 |
| dirsearch | 9,680 条路径合并 |
| OneForAll | 完整数据提取 (982条) |
| Sublist3r | 129,406 条名字典合并 |
| subDomainsBrute | 6 字典文件合并 |
| masscan | C 源码, 无字典 |
| GitHack | 利用链分析 + 路径已在 BBScan |
| SvnHack | 利用链分析 + 路径已在 BBScan |

| 仅剩待办 | 状态 |
|---------|------|
| TideFinger technologies.json (26,732行 Wappalyzer) | 可深入提取 (非紧急, 现有 33,107 指纹已覆盖主流 CMS)

## 资产测绘平台 (在线)

- **FOFA**: https://fofa.info/ — 网络空间测绘
- **爱企查**: https://aiqicha.baidu.com/ — 企业信息查询
- **小蓝本**: https://sou.xiaolanben.com/pc — App/商标查询
- **DNSDB**: https://dnsdb.io/ — DNS 历史记录
- **微步在线**: https://x.threatbook.cn/ — 威胁情报
- **Netcraft**: http://toolbar.netcraft.com/ — 站点历史
- **ViewDNS**: http://viewdns.info/ — DNS/IP 查询
- **IPIP**: https://tools.ipip.net/cdn.php — CDN 查询
- **SecurityTrails**: — DNS 历史/子域名
- **dnslog.cn**: — DNSLog 盲测
