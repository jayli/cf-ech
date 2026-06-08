# cf-ech CLI 设计文档

## 概述

cf-ech 是一个零依赖的 Node.js CLI 工具，通过 `npx cf-ech` 直接运行。功能：扫描 Cloudflare 优选域名，找出支持 ECH（Encrypted Client Hello）的域名，按 TLS 握手延迟排序输出最优结果。

## 项目结构

```
cf-ech/
├── bin/cf-ech.js          # 主脚本入口
├── data/domains.txt       # 打底域名数据（641 个已知 CF 优选域名）
├── package.json
├── LICENSE
└── README.md
```

## package.json 关键配置

```json
{
  "name": "cf-ech",
  "version": "1.0.0",
  "bin": { "cf-ech": "./bin/cf-ech.js" },
  "scripts": { "start": "node bin/cf-ech.js" },
  "files": ["bin", "data"],
  "dependencies": {}
}
```

- `bin` 字段使 `npx cf-ech` 可用
- `files` 控制 npm 发布内容
- 零外部依赖

## CLI 参数

| 参数 | 作用 |
|------|------|
| `-json` | 以 JSON 格式输出结果 |
| `-all` | 输出所有支持 ECH 的域名（默认前 20） |

使用原生 `process.argv` 解析，不引入第三方库。

## 执行流程

1. **解析参数** — 从 `process.argv` 读取 `-json`、`-all`
2. **加载本地域名** — 读取 `data/domains.txt`
3. **获取在线域名** — 请求 `https://vps789.com/openApi/cfIpTop20`，失败静默跳过
4. **合并去重** — Set 去重
5. **查询 HTTPS 记录** — 通过 DoH（`dns.alidns.com`）查询 TYPE 65 记录，并发 50，过滤出包含 `ipv4hint` 的域名
6. **TLS 握手测试** — 对每个域名的 ipv4hint IP 做 TLS 连接测试，并发 50，超时 5s
7. **过滤 ECH 域名** — 只保留 HTTPS 记录中包含 ECH 参数（SvcParam key 5）的域名
8. **性能排序** — 每个域名取其最快 IP 的握手延迟，按延迟升序排列
9. **输出结果** — 默认前 20 个，`-all` 输出全部
10. **输出报告** — stderr 输出扫描摘要

## 输出设计

### stdout — 默认模式

```
example.com  128ms
another.com  156ms
```

每行：域名 + 两个空格 + 延迟。方便人读，也方便 `awk '{print $1}'` 提取域名。

### stdout — JSON 模式（-json）

```json
[
  {"domain": "example.com", "elapsed": 128},
  {"domain": "another.com", "elapsed": 156}
]
```

### stderr — 进度信息

扫描过程中的进度（HTTPS 查询进度、TLS 测试通过的 IP 等）输出到 stderr，不干扰 stdout 管道。

### stderr — 报告摘要

```
扫描域名: 680 | 支持 ECH: 45 | 优选结果: 20
```

始终在末尾输出，包含：
- 扫描域名总数
- 支持 ECH 的域名数
- 最终输出的域名数（受 `-all` 影响）

## 核心技术实现

### DoH 查询

- 使用 HTTPS POST 方式向 `dns.alidns.com` 发送 DNS wire-format 查询
- 查询 TYPE 65（HTTPS 记录）
- 解析 SvcParam：key 4 = ipv4hint，key 5 = ECH config
- 纯 Node.js 实现，不依赖系统 DNS

### TLS 握手测试

- 使用 `tls.connect()` 对 ipv4hint 中的 IP 发起 443 端口连接
- servername 设为 `c.consolelog.work`（测试用域名）
- 记录握手完成时间作为延迟指标
- 超时 5s

### 并发控制

- Worker pool 模式，50 并发
- 复用原脚本的 `runWithPool` 实现

## 数据源

1. **本地打底** — `data/domains.txt`（从原项目 `good_cf_domains.txt` 拷贝，641 个域名）
2. **在线补充** — `https://vps789.com/openApi/cfIpTop20` 返回的域名列表，失败时静默跳过

两个来源合并后用 Set 去重。
