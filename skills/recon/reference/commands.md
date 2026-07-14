# Recon 命令参考

本文件包含 recon/SKILL.md 中引用的详细命令。仅在执行对应步骤时读取，不需要一次性加载。

---

## 子域名枚举命令（步骤 4）

### Tier 1（两种模式都执行）

```bash
# A: subfinder
subfinder -d $DOMAIN -all -o /tmp/subs_subfinder.txt 2>/dev/null

# B: crt.sh（下载到文件再解析，避免大JSON截断）
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" --connect-timeout 15 -m 300 \
  -o /tmp/crtsh_$DOMAIN.json 2>/dev/null
cat << 'CRTPARSE' | python3
import json, sys
try:
    with open(f"/tmp/crtsh_{sys.argv[1] if len(sys.argv)>1 else 'domain'}.json", "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8", errors="replace")
    if not text.rstrip().endswith("]"):
        last_brace = text.rfind("}")
        if last_brace > 0:
            text = text[:last_brace+1] + "]"
    data = json.loads(text)
    subs = set()
    for e in data:
        for name in e.get("name_value","").split("\n"):
            name = name.strip().lstrip("*.")
            if name and " " not in name:
                subs.add(name.lower())
    for s in sorted(subs): print(s)
except Exception as ex:
    print(f"crt.sh parse error: {ex}", file=sys.stderr)
CRTPARSE

# C: DNS 爆破常用前缀
for sub in www mail api admin test staging dev oa hr crm erp bbs wiki git svn jenkins jira zabbix grafana kibana es vpn sslvpn cloud cdn img static; do
  r=$(dig +short $sub.$DOMAIN A 2>/dev/null)
  [ -n "$r" ] && echo "$sub.$DOMAIN"
done > /tmp/subs_bruteforce.txt
```

### Tier 2（SRC 额外执行）

```bash
# D: amass
amass enum -passive -d $DOMAIN -o /tmp/subs_amass.txt 2>/dev/null

# E: FOFA API
if [ -n "$FOFA_EMAIL" ] && [ -n "$FOFA_KEY" ]; then
  QUERY=$(echo -n "domain=\"$DOMAIN\"" | base64)
  curl -s "https://fofa.info/api/v1/search/all?email=$FOFA_EMAIL&key=$FOFA_KEY&qbase64=$QUERY&size=10000&fields=host,ip,port,title,server" \
    -o /tmp/fofa_results.json 2>/dev/null
  python3 -c "
import json
try:
    data = json.load(open('/tmp/fofa_results.json'))
    for r in data.get('results',[]):
        host = r[0] if isinstance(r, list) else r.get('host','')
        if host: print(host.split('//')[1] if '://' in host else host)
except: pass
" | sort -u > /tmp/subs_fofa.txt
fi

# F: Hunter API
if [ -n "$HUNTER_KEY" ]; then
  QUERY=$(echo -n "domain.suffix=\"$DOMAIN\"" | base64)
  curl -s "https://hunter.qianxin.com/openApi/search?api-key=$HUNTER_KEY&search=$QUERY&page=1&page_size=100" \
    -o /tmp/hunter_results.json 2>/dev/null
  python3 -c "
import json
try:
    data = json.load(open('/tmp/hunter_results.json'))
    for item in data.get('data',{}).get('arr',[]):
        d = item.get('domain','')
        if d: print(d)
except: pass
" | sort -u > /tmp/subs_hunter.txt
fi

# G: DNS 爆破 SecLists top-5000
if [ -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt ]; then
  while read prefix; do
    r=$(dig +short $prefix.$DOMAIN A 2>/dev/null)
    [ -n "$r" ] && echo "$prefix.$DOMAIN"
  done < /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt > /tmp/subs_bruteforce_ext.txt
fi
```

### 通配符 DNS + 合并

```bash
WILDCARD_IP=$(dig +short randomnonexist12345.$DOMAIN A 2>/dev/null)
[ -n "$WILDCARD_IP" ] && echo "[WARN] 通配符 DNS: $WILDCARD_IP"

cat /tmp/subs_subfinder.txt /tmp/subs_crtsh.txt /tmp/subs_bruteforce.txt \
    /tmp/subs_amass.txt /tmp/subs_fofa.txt /tmp/subs_hunter.txt \
    /tmp/subs_bruteforce_ext.txt 2>/dev/null | sort -u > /tmp/subdomains_all.txt

if [ -n "$WILDCARD_IP" ]; then
  while read sub; do
    ip=$(dig +short $sub A 2>/dev/null)
    [ "$ip" != "$WILDCARD_IP" ] && echo "$sub"
  done < /tmp/subdomains_all.txt > /tmp/subdomains_filtered.txt
  mv /tmp/subdomains_filtered.txt /tmp/subdomains_all.txt
fi
```

---

## httpx 命令（步骤 5）

### SRC 高并发
```bash
httpx -l /tmp/subdomains_all.txt \
  -status-code -title -tech-detect -content-length \
  -web-server -follow-redirects -favicon -cdn \
  -threads 50 -rate-limit 100 \
  -o /tmp/httpx_alive.txt -json -o /tmp/httpx_results.json
```

### RedTeam 低并发
```bash
httpx -l /tmp/subdomains_all.txt \
  -status-code -title -tech-detect -content-length \
  -web-server -follow-redirects -threads 20 \
  -o /tmp/httpx_alive.txt -json -o /tmp/httpx_results.json
```

### 结果统计 Python
```python
import json, collections
alive = 0; status_dist = collections.Counter(); tech_dist = collections.Counter()
cdn_count = 0; non_cdn = []
for line in open('/tmp/httpx_results.json'):
    try:
        r = json.loads(line); alive += 1
        status_dist[r.get('status_code',0)] += 1
        for t in r.get('tech', []): tech_dist[t] += 1
        if r.get('cdn', False): cdn_count += 1
        else: non_cdn.append(r.get('url',''))
    except: pass
print(f'存活: {alive} | CDN: {cdn_count} | 非CDN: {len(non_cdn)}')
print(f'状态码: {dict(status_dist.most_common(10))}')
print(f'技术栈: {dict(tech_dist.most_common(10))}')
```

---

## 智能筛选 Python（步骤 6，SRC专属）

```python
import json, re
P1, P2, P3, P4 = [], [], [], []

P1_KEYWORDS_HOST = ['test', 'dev', 'staging', 'uat', 'beta', 'demo', 'old', 'bak',
                     'backup', 'debug', 'internal', 'pre', 'gray', 'canary', 'admin']
P1_KEYWORDS_TITLE = ['phpinfo', 'test', 'debug', 'index of', 'dashboard', '管理',
                      '后台', 'console', 'swagger', 'actuator', 'druid', 'nacos',
                      'jenkins', 'grafana', 'kibana', 'spring boot']
OLD_FRAMEWORKS = ['thinkphp 5', 'struts2', 'spring boot 1', 'laravel 5',
                   'django 1', 'rails 4', 'jboss', 'weblogic']
SAAS_DOMAINS = ['zendesk', 'salesforce', 'google', 'microsoft', 'amazonaws',
                'cloudfront', 'akamai', 'fastly']

for line in open('/tmp/httpx_results.json'):
    try: r = json.loads(line)
    except: continue
    url = r.get('url', ''); host = r.get('host', '').lower()
    title = r.get('title', '').lower(); tech = [t.lower() for t in r.get('tech', [])]
    cdn = r.get('cdn', False); status = r.get('status_code', 0)

    if any(s in host for s in SAAS_DOMAINS): P4.append(r); continue
    if status == 0: P4.append(r); continue

    is_p1 = any(kw in host for kw in P1_KEYWORDS_HOST) or \
             any(kw in title for kw in P1_KEYWORDS_TITLE) or \
             any(fw in ' '.join(tech) for fw in OLD_FRAMEWORKS) or \
             (status == 403 and not cdn) or \
             (not cdn and any(kw in host for kw in ['api', 'gateway', 'service']))
    if is_p1: P1.append(r); continue

    p2_score = (1 if not cdn else 0) + (1 if any(kw in title for kw in ['login','登录']) else 0)
    if p2_score >= 2: P2.append(r); continue
    P3.append(r)

print(f'P1: {len(P1)} | P2: {len(P2)} | P3: {len(P3)} | P4: {len(P4)}')
for name, lst in [('p1',P1),('p2',P2),('p3',P3)]:
    with open(f'/tmp/targets_{name}.json','w') as f: json.dump(lst,f,ensure_ascii=False)
    with open(f'/tmp/urls_{name}.txt','w') as f:
        for r in lst: f.write(r.get('url','')+'\n')
```

---

## SRC 批量操作命令（步骤 7）

### nuclei 信息收集
```bash
split -l 200 /tmp/httpx_alive.txt /tmp/nuclei_chunk_
for chunk in /tmp/nuclei_chunk_*; do
  (nuclei -l $chunk \
    -tags tech,exposure,token,config,misconfig,default-login,takeover \
    -exclude-tags dos,fuzzing,rce,sqli,xss,lfi,ssti,ssrf,injection \
    -rate-limit 50 -bulk-size 25 -concurrency 10 -timeout 15 \
    -o /tmp/nuclei_$(basename $chunk).txt) &
done; wait
cat /tmp/nuclei_*.txt > /tmp/nuclei_all_results.txt
```

### 子域名接管
```bash
nuclei -l /tmp/httpx_alive.txt -t /root/nuclei-templates/http/takeovers/ -o /tmp/takeover_results.txt
for sub in $(cat /tmp/subdomains_all.txt); do
  cname=$(dig +short CNAME $sub 2>/dev/null)
  if [ -n "$cname" ]; then
    resolved=$(dig +short $cname 2>/dev/null)
    [ -z "$resolved" ] && echo "[TAKEOVER?] $sub → $cname"
  fi
done > /tmp/dangling_cnames.txt
```

### CORS 检测
```bash
for url in $(cat /tmp/urls_p1.txt /tmp/urls_p2.txt 2>/dev/null | shuf | head -500); do
  cors=$(curl -s -o /dev/null -m 5 -H "Origin: https://evil.com" -D- "$url" 2>/dev/null | grep -i "access-control-allow-origin")
  echo "$cors" | grep -qi "evil.com" && echo "[CORS] $url | $cors"
done > /tmp/cors_results.txt
```

### 信息泄露（leak_probe.py）
```bash
scp ${CLAUDE_SKILL_DIR}/scripts/leak_probe.py kali@$KALI_IP:/tmp/
ssh kali@$KALI_IP 'python3 /tmp/leak_probe.py /tmp/urls_p1.txt'
```

### 目录爆破（P1目标）
```bash
for url in $(cat /tmp/urls_p1.txt | head -30); do
  hash=$(echo "$url" | md5sum | cut -c1-8)
  ffuf -u ${url}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -mc 200,301,302,403,500 -t 20 -o /tmp/ffuf_${hash}.json 2>/dev/null &
done; wait
```

### SRC 端口扫描
```bash
SRC_PORTS="80,443,8080,8443,8000,8888,9090,3000,4443,5000,7001,7002,8081-8090,8009,8100,8880,9000,9001,9200,9300,10000,10443,8161,8500,8800,8899,9080,9443,7070,7080,5555,6666,7777,3306,6379,27017,5432,1433,11211,9092,2181,8848,8858,4848,3389,22,21"
for url in $(cat /tmp/urls_p1.txt); do
  host=$(echo "$url" | sed 's|https\?://||' | cut -d: -f1 | cut -d/ -f1)
  dig +short $host A 2>/dev/null
done | sort -u > /tmp/p1_ips.txt
$NMAP_PREFIX nmap $NMAP_SCAN_TYPE -p $SRC_PORTS --min-rate 3000 -T4 --open -iL /tmp/p1_ips.txt -oG /tmp/nmap_src_ports.gnmap
```

---

## RedTeam 逐端口深入命令（步骤 8R）

### httpx 批量探端口
```bash
for port in $(cat /tmp/open_ports.txt); do
  echo "http://TARGET:$port"; echo "https://TARGET:$port"
done | httpx -status-code -title -tech-detect -content-length -web-server \
  -threads 10 -o /tmp/httpx_ports.txt -json -o /tmp/httpx_ports.json
```

### 单端口深入
```bash
PORT=<port>
whatweb -a 3 --no-colour --log-json=/tmp/whatweb_port${PORT}.json http://TARGET:$PORT
nuclei -u http://TARGET:$PORT -severity critical,high,medium -timeout 10

# 信息泄露（SPA假阳性过滤）
HOMEPAGE_HASH=$(curl -s -m 5 "http://TARGET:$PORT/" --noproxy "*" | md5sum)
for path in /debug /debug/config /.env /phpinfo.php /api/Uploads/test /api/test \
  /actuator /actuator/env /druid/index.html /swagger-ui.html /nacos/ /.git/HEAD; do
  resp=$(curl -s -m 5 "http://TARGET:$PORT$path" --noproxy "*")
  code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "http://TARGET:$PORT$path" --noproxy "*")
  resp_hash=$(echo "$resp" | md5sum)
  [ "$resp_hash" = "$HOMEPAGE_HASH" ] && continue
  echo "[$code] http://TARGET:$PORT$path"
done

# 目录爆破
ffuf -u http://TARGET:$PORT/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -mc 200,301,302,403,500 -t 30 -o /tmp/ffuf_port${PORT}.json
```

---

## OSS 存储桶检测命令（步骤 8R-oss）

```bash
PREFIXES="example example-com examplecom app-name app-prod app-test app-backup app-static"

# 阿里云 OSS
for prefix in $PREFIXES; do
  for region in cn-hangzhou cn-shanghai cn-beijing cn-shenzhen cn-chengdu cn-hongkong; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${prefix}.oss-${region}.aliyuncs.com/")
    [ "$code" != "000" ] && [ "$code" != "404" ] && echo "[OSS] ${prefix}.oss-${region}.aliyuncs.com → $code"
  done
done

# 腾讯云 COS
for prefix in $PREFIXES; do
  for region in ap-guangzhou ap-shanghai ap-beijing ap-chengdu ap-hongkong; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${prefix}.cos.${region}.myqcloud.com/")
    [ "$code" != "000" ] && [ "$code" != "404" ] && echo "[COS] ${prefix}.cos.${region}.myqcloud.com → $code"
  done
done

# AWS S3
for prefix in $PREFIXES; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://${prefix}.s3.amazonaws.com/")
  [ "$code" != "000" ] && [ "$code" != "404" ] && echo "[S3] ${prefix}.s3.amazonaws.com → $code"
done

# 发现 200 → 列目录
curl -sk "https://BUCKET_URL/" | grep -oP '(?<=<Key>)[^<]+' | head -50
```

---

## SSL/C段/JS 命令（步骤 10R-12R）

### SSL 证书
```bash
openssl s_client -connect TARGET:443 -servername TARGET 2>/dev/null \
  | openssl x509 -noout -text | grep -A1 "Subject Alternative"
```

### C 段
```bash
$NMAP_PREFIX nmap $NMAP_SCAN_TYPE TARGET/24 -oA /tmp/nmap_csegment
$NMAP_PREFIX nmap $NMAP_SCAN_TYPE -p 80,443,888,3306,6379,8080,8443,8888 \
  --open -iL /tmp/csegment_alive.txt -oA /tmp/nmap_csegment_ports
```

### JS 静态分析
```bash
curl -s http://TARGET | grep -oP '(?<=src=")[^"]*\.js' | sort -u
for js in $(cat /tmp/js_files.txt); do
  curl -s "$js" | grep -iE "http://|https://|api|key|secret|token|password|phone|code"
done
```

### JS 动态爬虫（SPA必用）
```bash
python ${CLAUDE_SKILL_DIR}/scripts/playwright_crawler.py "https://TARGET:PORT/path/" \
  -o $OUTDIR/recon/raw/crawler_results.json
```
