# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

cf-ech 是一个 Node.js CLI 工具，用于发现支持 ECH（Encrypted Client Hello）的 Cloudflare CDN 优选域名。无第三方依赖，纯 Node.js 标准库实现。

## 常用命令

```bash
npm start                   # 默认扫描
node bin/cf-ech.js          # 等价
npx cf-ech -all             # 输出所有结果
npx cf-ech -json            # JSON 格式输出
npx cf-ech -c <domain>      # 检测单个域名
npx cf-ech -t <domain>      # 对指定域名的 A 记录 IP 逐一测速
```

## 架构与流程

单文件实现 `bin/cf-ech.js`，约 520 行。

数据文件：
- `data/domains.txt` — 本地域名列表，一行一个
- `data/banner.txt` — ASCII banner

核心流程（批量模式）：

1. **加载域名** — 读取 `data/domains.txt` + 在线 API 拉取热门域名，合并去重
2. **HTTPS 记录查询** — 通过 DoH（`dns.alidns.com` / `cloudflare-dns.com`）查询 type 65，提取 `ech`（SvcParam key=5）和 `ipv4hint`（SvcParam key=4）
3. **过滤 ECH 域名** — 只保留 HTTPS 记录中有 `ech` 参数的域名
4. **A 记录查询** — 对 ECH 域名查询 type 1，获取 passwall/xray 实际连接时解析到的 IP
5. **TLS 握手测速** — 每个唯一 IP 用其域名作 SNI 测两次取均值，50 并发
6. **按延迟排序输出** — 取前 20 个，三列对齐输出（域名 | IP | 延迟）

## 并发控制

`CONCURRENCY = 50`，`SCAN_TIMEOUT = 5000`ms。所有批量操作通过 `runWithPool(tasks, concurrency)` 函数以固定并发数执行。

## 发布

```bash
npm publish --registry https://registry.npmjs.org/
```
