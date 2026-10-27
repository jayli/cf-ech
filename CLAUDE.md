# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

cf-ech 是一个 Node.js CLI 工具，用于实测筛选指向 Cloudflare CDN 且能稳定完成 ECH（Encrypted Client Hello）TLS 握手的优质域名。适合作为 Xray / passwall 代理的外层 SNI 优选域名。无第三方依赖，纯 Node.js 标准库实现（要求 Node.js ≥ 22，`tls.connect` 支持 `ech` 选项）。

## 常用命令

```bash
npm start                   # 默认批量扫描，输出前 20 个优质域名
node bin/cf-ech.js          # 等价
npx cf-ech -all             # 输出所有 100% 成功率域名
npx cf-ech -json            # JSON 格式输出
npx cf-ech -no-ech          # 跳过 ECH 探测，只按普通 TLS 握手做 CF 优选（可组合 -all / -json）
npx cf-ech -c <domain>      # 单域名检测（每 IP 5 轮 ECH TLS + 延迟/抖动报告）
npx cf-ech -t <domain>      # 对域名的 A 记录 IP 逐一做 ECH + 无 ECH 双模式 TLS 测速（各 5 轮）
npx cf-ech -server          # 启动 HTTP 服务（0.0.0.0:4837），参数走 URL query，结果流式返回
npx cf-ech -server 8080 -host 127.0.0.1   # 指定端口 / 只监听本机
```

## 架构

两个文件：
- `bin/cf-ech.js` — CLI 入口、DNS/TLS 实测、评分、参数解析、请求执行（约 1060 行）
- `bin/server.js` — HTTP 服务：路由、流式响应、扫描排队（无业务逻辑）

数据文件：
- `data/domains.txt` — 本地域名列表，一行一个（641 个）

### 核心设计原则

**Cloudflare ECH 是边缘节点级别的**：Xray 从 `cloudflare-ech.com` 获取 ECH 公钥加密 ClientHello，任何部署了 ECH 私钥的 CF 边缘 IP 都能终止。域名自身 HTTPS 记录里有没有 `ech` 字段与 ECH 能否工作无关。因此脚本不检查域名的 ECH 记录，而是直接做 ECH TLS 握手实测。

### 核心流程（批量模式）

1. **加载域名** — 读取 `data/domains.txt` + 在线 API (`CF_TOP20_API`) 拉取热门域名，合并去重
2. **获取 ECH 公钥** — 从 `cloudflare-ech.com` 查询 DoH type 65，提取 SvcParam key=5 的 ECH config（全会话一次，缓存）。`-no-ech` 模式下整步跳过，`echConfig` 保持 `null`
3. **DNS A 记录** — 对所有域名并发查询 type 1，获取 IP 列表
4. **CF IP 过滤** — 通过 `api.cloudflare.com/client/v4/ips` 获取 CF IPv4 CIDR，只保留 IP 属 CF 段的域名
5. **IP 去重** — 所有域名共享同一个 IP→域名映射表，同一 IP 只测一次
6. **ECH TLS 实测** — 每个唯一 IP 做 2 轮 `tls.connect({ ech: { config } })` 握手，统计成败和延迟；`-no-ech` 模式下换成普通 `testTLS`，流程与门槛不变
7. **硬性过滤** — 任何握手失败的域名直接排除，只保留 100% 成功率且至少 2 个 IP 的域名
8. **评分排序** — `score = 平均延迟 × 70 + IP间稳定性 × 20 + IP数可控性 × 10`（所有 IP 平均延迟越低越好、IP 间延迟差越小越好、3 个以内 IP 不扣分），按分降序、平均延迟/离散度/最快 IP 延迟 tiebreak
9. **输出** — 默认前 20 个，三列对齐（域名 | IP | 延迟）

### 关键函数

| 函数 | 用途 |
|---|---|
| `fetchECHConfig(domain)` | 从指定域名的 HTTPS 记录提取 ECH 公钥，带缓存 |
| `resolveARecords(domain)` | 单次 DNS type 1 查询 |
| `testECHTLS(ip, timeout, sni, echConfig)` | 带 ECH 配置的 TLS 握手，返回 `{ success, elapsed }` |
| `testTLS(ip, timeout, sni)` | 普通 TLS 握手，ECH config 获取失败时的 fallback |
| `checkDomain(domain, sink)` | `-c` 单域名检测：单次 DNS → CF 验证 → 每 IP 5 轮 ECH TLS → 延迟/抖动/评价 |
| `testDomain(domain, sink)` | `-t` 测速：A 记录 → 每 IP 5 轮 ECH TLS + 5 轮无 ECH TLS → 双模式延迟/抖动对比 |
| `runWithPool(tasks, concurrency)` | 固定并发数的任务池 |
| `runBatchScan(flags, sink)` | 批量扫描全流程，返回 `{ json }`（JSON 模式由调用方统一输出） |
| `runRequest(flags, sink)` | 单次请求的执行入口，按 `flags.mode` 分发到 check / test / 批量 |
| `createSink({ write, info, color })` | 输出抽象：CLI 接 stdout/stderr，HTTP 接响应流 |
| `parseFlags(argv)` | 解析 CLI 参数（`-json` / `-all` / `-no-ech` / `-server` / `-host` / `-c` / `-t` / `-h` / `-v`） |
| `parseQuery(searchParams)` | 把 HTTP query 映射成同一组 flags，非法组合返回 `{ error }` |
| `createServer({ run, parseQuery, isAppError })` | 构建 HTTP 服务，`run` 可注入以便测试 |

### 降级策略

如果 `cloudflare-ech.com` 的 ECH 公钥获取失败，整个扫描降级为普通 TLS 测试，并 stderr 标注警告。`-c` 模式下同样处理。

`-no-ech` 是主动版本：不请求 ECH 公钥，`echConfig` 直接保持 `null`，批量扫描全程走 `testTLS`。它只对批量模式生效，与 `-c` / `-t` 同时使用会报错退出（单域名的无 ECH 结果用 `-t` 看）。

## 服务模式（`-server`）

`cf-ech -server [port] [-host addr]`，默认 `0.0.0.0:4837`。零依赖，用 `node:http`。

路由：
- `GET /` 无参数 → 静态 HTML 用法页（带可点的示例链接），不触发扫描
- `GET /?<params>` → 执行扫描，`text/plain` 流式返回；进度和结果都写同一个流，顺序即执行顺序
- `GET /?json=1` → 缓冲到结束再返回 `application/json`，避免进度文字污染 JSON
- 非 GET → 405，未知路径 → 404，未知 query 键或非法组合 → 400 且不执行扫描

query 键：`all` / `json` / `noech`（`0` 和 `false` 视为关）、`mode=check|test` + `domain=`。
`mode` 与批量开关互斥，规则与 CLI 的 `-no-ech` + `-c/-t` 一致。

实现要点：
- **串行排队**：`createLock()` 保证同一时刻只跑一个扫描。并发扫描会互相抢带宽把延迟数字搞脏，而这工具的全部意义就是延迟。排队请求先收到一行「排队结束」再开始。
- **`AppError`**：无 A 记录、非 CF 域名这类可预期失败抛 `AppError` 而非 `process.exit` —— CLI 转 exit 1，HTTP 转 400。其余异常在 HTTP 里是 500。
- **颜色降级**：`sink.color` 为 false 时 banner 输出纯文本，否则 HTTP 响应里会出现 ANSI 转义码乱码。CLI 侧取 `process.stderr.isTTY`。
- **客户端断开**：只停止写响应，扫描继续跑完（有界），锁正常释放。

服务默认监听 `0.0.0.0`，同网段任何人都能触发扫描（每个请求一次完整扫描、约几十秒）。只想本机访问用 `-host 127.0.0.1`。

## 并发控制

`CONCURRENCY = 50`，`SCAN_TIMEOUT = 5000`ms。所有批量 DNS 和 TLS 操作通过 `runWithPool()` 控制并发。

## 评价标准

`-c` 和 `-t` 模式的评价逻辑：
- **优选接入点**：成功率 100% **且** 所有成功 IP 平均延迟 < `MAX_RECOMMENDED_LATENCY`（800ms）**且** 所有成功 IP 抖动 ≤ `MAX_RECOMMENDED_JITTER`（1000ms）
- **普通 CF 节点**：成功率 ≥ 90%，或成功率 100% 但延迟/抖动超标
- 其余按成功率分级：≥70% 一般、>0% 不推荐、0% 不可用
- `-t` 双模式：ECH 100% 且延迟/抖动达标推荐 ECH 接入；ECH 不达标但 TLS 达标推荐普通接入

## 发布

```bash
npm publish --registry https://registry.npmjs.org/
```
