## cf-ech

> Find the fastest cf CDN domains that support ech.

寻找支持 ECH 的 Cloudflare 优选域名。

### 用法

输出 20 个本机速度最快的支持 ech 的 cf 域名

```
npx cf-ech
```

### 更多用法

- 帮助：`npx cf-ech --help`
- JSON 格式输出：`npx cf-ech -json`
- 输出所有支持ech的域名：`npx cf-ech -all`
- 检测单个域名是否支持 ECH：`cf-ech -c <domain>`

### 原理

**Why** — [ECH（Encrypted Client Hello）](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-22)可以加密 TLS 握手中的 SNI，使中间设备无法看到你实际访问的域名。Cloudflare CDN 支持 ECH，但并非所有指向 CF 的域名都启用了它，且不同节点延迟差异很大。

**How** — 通过 DoH 查询域名的 [HTTPS 记录（type 65）](https://datatracker.ietf.org/doc/html/rfc9460)，从中提取 `ipv4hint`（CDN 节点 IP）和 `ech`（ECH 配置）。筛选出同时具备两者的域名，对其 IP 做 TLS 握手测速，按延迟排序输出最快的结果。

