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
- 检测指定域名的 ECH 连接质量：`npx cf-ech -c <domain>`
- ECH + 无 ECH 双模式测速：`npx cf-ech -t <domain>`

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
