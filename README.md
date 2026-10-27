# cf-ech

<a href="https://nodei.co/npm/cf-ech/"><img src="https://nodei.co/npm/cf-ech.svg?style=mini"></a>

> 寻找支持 ECH 的 Cloudflare 优选域名。

### 用法

输出 20 个本机速度最快的支持 ECH 的 CF 域名：

```
npx cf-ech
```

### 更多用法

- 帮助：`npx cf-ech --help`
- JSON 格式输出：`npx cf-ech -json`
- 输出所有支持 ECH 的域名：`npx cf-ech -all`
- 关闭 ECH 探测、只做普通 CF 优选：`npx cf-ech -no-ech`
- 检测指定域名的 ECH 连接质量：`npx cf-ech -c <domain>`
- ECH + 无 ECH 双模式测速：`npx cf-ech -t <domain>`
- 启动 HTTP 服务：`npx cf-ech -server`（默认 4837 端口）

不加参数时只测 ECH：任何一轮 ECH 握手失败都直接排除该域名。如果只想按普通 TLS 握手做 CF 优选（不看 ECH 支持情况），加 `-no-ech`，扫描流程、100% 成功率门槛和评分规则完全一致，只是每轮握手不带 ECH 配置，也不再去 `cloudflare-ech.com` 取公钥。`-no-ech` 可与 `-all` / `-json` 组合。

### 服务模式

```
npx cf-ech -server                      # 监听 0.0.0.0:4837
npx cf-ech -server 8080                 # 换端口
npx cf-ech -server -host 127.0.0.1      # 只本机可访问
```

启动后用浏览器打开 `http://<本机IP>:4837/` 有用法页，也可以直接用 curl。URL 参数就是命令行参数的长名版本，结果边跑边流式返回：

```bash
curl -N http://127.0.0.1:4837/                              # 默认扫描（前 20）
curl -N http://127.0.0.1:4837/?all=1                        # 全部结果
curl -N http://127.0.0.1:4837/?all=1&noech=1                # 只做普通 TLS 优选
curl    http://127.0.0.1:4837/?json=1                       # JSON 输出（结束时一次性返回）
curl -N "http://127.0.0.1:4837/?mode=check&domain=example.com"   # 等价于 -c
curl -N "http://127.0.0.1:4837/?mode=test&domain=example.com"    # 等价于 -t
```

同一时刻只跑一次扫描，后到的请求排队等待——并发扫描会互相抢带宽，把延迟数字搞脏。服务默认监听 `0.0.0.0`，同网段任何人都能触发扫描；只想本机访问请加 `-host 127.0.0.1`。

### 原理

**ECH（Encrypted Client Hello）** 可加密 TLS 握手中的 SNI，Cloudflare CDN 支持 ECH，但并非所有指向 CF 的域名都启用了它，且不同节点延迟差异很大。

工具解决的问题：

1. 同是 cf 优选域名，如果不开启 ECH，哪个延时低用哪个。但是开启 ECH 后，就不能只看线路延时了，还要看 cf 节点的拥堵程度和计算压力。
2. cf 节点处理 ECH 涉及到用私钥解密的过程，很消耗节点算力，如果这个节点流量集中导致拥堵，就会导致 ECH 解密计算的排队。
3. 如果出现排队，cf 会优先处理无 ECH 的报文，这类报文吞吐量高，转发速度快，而 ECH 报文因为排队等待解密，有概率导致超时。
4. 所以开启 ECH 后，优选域名不光要看线路延迟，还要看拥堵程度。
5. 这个工具就是检测域名解析的 ip 对 ech 的支持情况，以及拥堵情况。
6. 如果开启 ECH，必须用这个工具筛选出高可用的 cf 优选域名。

### 怎么用

以 xray 为例：

- ECH 配置：`cloudflare-ech.com+https://dns.alidns.com/dns-query`
- 优选域名：填入 cf-ech 跑出来的速度最快的域名
