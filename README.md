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
- 检测单个域名是否支持 ECH：`npx cf-ech -c <domain>`
- 对指定域名的解析 IP 逐一测速：`npx cf-ech -t <domain>`

### 原理

**ECH（Encrypted Client Hello）** 可加密 TLS 握手中的 SNI，Cloudflare CDN 支持 ECH，但并非所有指向 CF 的域名都启用了它，且不同节点延迟差异很大。

本工具的处理流程：

1. 通过 DoH 查询域名 HTTPS 记录（type 65），提取 `ech` 参数判断是否支持 ECH
2. 对支持 ECH 的域名查询 A 记录（type 1），获取实际解析 IP
3. 对每个 IP 进行两次 TLS 握手测速，取平均值
4. 按延迟排序输出最优域名

### 示例输出

```
cloudflare-ech.com             104.21.x.x      50ms
cloudflare.182682.xyz          172.67.x.x      65ms
abc.work                       104.16.x.x      72ms
...
```

### 怎么用

以 xray 为例：

- ECH 配置：`cloudflare-ech.com+https://dns.alidns.com/dns-query`
- 优选域名：填入 cf-ech 跑出来的速度最快的域名
