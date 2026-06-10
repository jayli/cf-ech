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
npx cf-ech -c <domain>      # 单域名检测（每 IP 5 轮 ECH TLS + 延迟/抖动报告）
npx cf-ech -t <domain>      # 对域名的 A 记录 IP 逐一做 ECH + 无 ECH 双模式 TLS 测速（各 5 轮）
```

## 架构

单文件 `bin/cf-ech.js`，约 720 行。

数据文件：
- `data/domains.txt` — 本地域名列表，一行一个（641 个）

### 核心设计原则

**Cloudflare ECH 是边缘节点级别的**：Xray 从 `cloudflare-ech.com` 获取 ECH 公钥加密 ClientHello，任何部署了 ECH 私钥的 CF 边缘 IP 都能终止。域名自身 HTTPS 记录里有没有 `ech` 字段与 ECH 能否工作无关。因此脚本不检查域名的 ECH 记录，而是直接做 ECH TLS 握手实测。

### 核心流程（批量模式）

1. **加载域名** — 读取 `data/domains.txt` + 在线 API (`CF_TOP20_API`) 拉取热门域名，合并去重
2. **获取 ECH 公钥** — 从 `cloudflare-ech.com` 查询 DoH type 65，提取 SvcParam key=5 的 ECH config（全会话一次，缓存）
3. **DNS A 记录** — 对所有域名并发查询 type 1，获取 IP 列表
4. **CF IP 过滤** — 通过 `api.cloudflare.com/client/v4/ips` 获取 CF IPv4 CIDR，只保留 IP 属 CF 段的域名
5. **IP 去重** — 所有域名共享同一个 IP→域名映射表，同一 IP 只测一次
6. **ECH TLS 实测** — 每个唯一 IP 做 2 轮 `tls.connect({ ech: { config } })` 握手，统计成败和延迟
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
| `checkDomain(domain)` | `-c` 单域名检测：单次 DNS → CF 验证 → 每 IP 5 轮 ECH TLS → 延迟/抖动/评价 |
| `testDomain(domain)` | `-t` 测速：A 记录 → 每 IP 5 轮 ECH TLS + 5 轮无 ECH TLS → 双模式延迟/抖动对比 |
| `runWithPool(tasks, concurrency)` | 固定并发数的任务池 |

### 降级策略

如果 `cloudflare-ech.com` 的 ECH 公钥获取失败，整个扫描降级为普通 TLS 测试，并 stderr 标注警告。`-c` 模式下同样处理。

## 并发控制

`CONCURRENCY = 50`，`SCAN_TIMEOUT = 5000`ms。所有批量 DNS 和 TLS 操作通过 `runWithPool()` 控制并发。

## 发布

```bash
npm publish --registry https://registry.npmjs.org/
```
