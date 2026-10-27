#!/usr/bin/env node

const tls = require('tls');
const https = require('https');
const crypto = require('crypto');
const { readFileSync } = require('fs');
const path = require('path');

const DOMAIN_FILE = path.join(__dirname, '..', 'data', 'domains.txt');
const COLOS_FILE = path.join(__dirname, '..', 'data', 'colos.json');
const TRACE_PATH = '/cdn-cgi/trace';
const CF_TOP20_API = 'https://vps789.com/openApi/cfIpTop20';
const CF_IPS_URL = 'https://api.cloudflare.com/client/v4/ips';
const ECH_PROVIDER = 'cloudflare-ech.com';
const DOH_SERVERS = [
  'https://dns.alidns.com/dns-query',
  'https://cloudflare-dns.com/dns-query',
];
const CONCURRENCY = 50;
const SCAN_TIMEOUT = 5000;
const COLO_TIMEOUT = 5000;
const MAX_RECOMMENDED_LATENCY = 800; // ms — 优选节点的平均延迟上限
const MAX_RECOMMENDED_JITTER = 1000; // ms — 优选节点的单 IP 抖动上限

// 执行结果通过 sink 输出，CLI 接到 stdout/stderr，HTTP 模式接到响应流。
// data：结果正文（等价于原 console.log）；info：过程信息（等价于原 stderr 日志）。
// color：输出端是否支持 ANSI 颜色，非终端（HTTP 响应、管道）下 banner 会退化成纯文本。
function createSink({ write, info, color = false }) {
  return {
    data(text) { write(text + '\n'); },
    info(msg) { info(msg + '\n'); },
    color,
  };
}

// 可预期的失败（无 A 记录、非 CF 域名等）：CLI 转 exit 1，HTTP 转 400。
class AppError extends Error {}

function evaluateCheckDomain({ cfIPCount, overallRate, avgLatency, maxJitter }) {
  if (overallRate === 100 && avgLatency < MAX_RECOMMENDED_LATENCY && maxJitter <= MAX_RECOMMENDED_JITTER) {
    if (cfIPCount >= 2) return '评价: ECH 连接质量优秀，适合作为优选 ECH CF 接入点';
    if (cfIPCount === 1) return '评价: 单 IP 优质 ECH 接入点（缺少冗余）';
  }
  if (overallRate >= 90) {
    return '评价: 可用 ECH（达不到优选）';
  }
  if (overallRate >= 70) {
    return '评价: 连接质量一般，可作为普通 CF 节点接入';
  }
  if (overallRate > 0) {
    return '评价: 连接不稳定，不推荐';
  }
  return '评价: 无法连接，不可用';
}

function evaluateTestDomain({
  cfIPCount,
  echRate,
  echAvgLatency,
  echMaxJitter,
  tlsRate,
  tlsAvgLatency,
  tlsMaxJitter,
}) {
  const echMeetsRecommended = echRate === 100 &&
    echAvgLatency < MAX_RECOMMENDED_LATENCY &&
    echMaxJitter <= MAX_RECOMMENDED_JITTER;
  const tlsMeetsRecommended = tlsRate === 100 &&
    tlsAvgLatency < MAX_RECOMMENDED_LATENCY &&
    tlsMaxJitter <= MAX_RECOMMENDED_JITTER;

  if (echMeetsRecommended) {
    if (cfIPCount >= 2) return '评价: ECH 连接质量优秀，适合作为优选 ECH CF 接入点';
    if (cfIPCount === 1) return '评价: 单 IP 优质 ECH 接入点（缺少冗余）';
  }
  if (tlsMeetsRecommended) {
    return '评价: 普通 CF 节点（凑合能用）';
  }
  if (echRate >= 70 || tlsRate >= 70) {
    return '评价: 连接质量一般，高峰期可能不稳定';
  }
  if (echRate > 0 || tlsRate > 0) {
    return '评价: 连接质量差，不推荐';
  }
  return '评价: 无法连接，不可用';
}

function buildDomainScore(domain, ips, ipResults) {
  let totalSuccess = 0;
  const latencies = [];
  for (const ip of ips) {
    const r = ipResults[ip];
    if (r && r.success) {
      totalSuccess += r.successCount;
      latencies.push(r.elapsed);
    }
  }

  const totalTests = ips.length * 2;
  const successRate = totalTests > 0 ? totalSuccess / totalTests : 0;
  if (successRate < 1 || ips.length < 2) return null;

  const avgLatency = Math.round(latencies.reduce((sum, ms) => sum + ms, 0) / latencies.length);
  const minLatency = Math.min(...latencies);
  const maxLatency = Math.max(...latencies);
  const spread = maxLatency - minLatency;
  const ipCount = ips.length;
  const ipPenalty = Math.max(0, ipCount - 3);

  const latencyScore = Math.max(0, 500 - avgLatency) / 500;
  const stabilityScore = Math.max(0, 250 - spread) / 250;
  const ipCountScore = Math.max(0, 7 - ipPenalty) / 7;
  const score = latencyScore * 70 + stabilityScore * 20 + ipCountScore * 10;

  let bestIP = ips[0];
  let bestLatency = Infinity;
  for (const ip of ips) {
    const r = ipResults[ip];
    if (r && r.success && r.elapsed < bestLatency) {
      bestLatency = r.elapsed;
      bestIP = ip;
    }
  }

  return {
    domain,
    ip: bestIP,
    elapsed: bestLatency,
    score: Math.round(score * 100) / 100,
    ipCount,
    avgLatency,
    spread,
    ipPenalty,
  };
}

// ─── DNS wire-format encoding ───

function encodeDnsName(domain) {
  const parts = domain.split('.');
  const buffers = [];
  for (const label of parts) {
    buffers.push(Buffer.from([label.length]));
    buffers.push(Buffer.from(label, 'ascii'));
  }
  buffers.push(Buffer.from([0x00]));
  return Buffer.concat(buffers);
}

function buildDnsQuery(domain, type) {
  const id = crypto.randomBytes(2);
  const flags = Buffer.from([0x01, 0x00]);
  const header = Buffer.concat([
    id, flags,
    Buffer.from([0x00, 0x01]),
    Buffer.from([0x00, 0x00]),
    Buffer.from([0x00, 0x00]),
    Buffer.from([0x00, 0x00]),
  ]);
  const qname = encodeDnsName(domain);
  const qtype = Buffer.from([type >> 8, type & 0xff]);
  const qclass = Buffer.from([0x00, 0x01]);
  return Buffer.concat([header, qname, qtype, qclass]);
}

function decodeDnsName(buf, offset) {
  let name = '';
  let jumped = false;
  let originalOffset = offset;
  while (true) {
    const len = buf[offset];
    if (len === 0) { offset++; break; }
    if ((len & 0xc0) === 0xc0) {
      if (!jumped) originalOffset = offset + 2;
      offset = ((len & 0x3f) << 8) | buf[offset + 1];
      jumped = true;
      continue;
    }
    offset++;
    name += buf.toString('ascii', offset, offset + len) + '.';
    offset += len;
  }
  return { name: name.slice(0, -1) || '.', nextOffset: jumped ? originalOffset : offset };
}

function parseDnsResponse(buf) {
  const ancount = buf.readUInt16BE(6);
  let offset = 12;
  const qdcount = buf.readUInt16BE(4);
  for (let i = 0; i < qdcount; i++) {
    const { nextOffset } = decodeDnsName(buf, offset);
    offset = nextOffset + 4;
  }
  const answers = [];
  for (let i = 0; i < ancount; i++) {
    const { name, nextOffset } = decodeDnsName(buf, offset);
    offset = nextOffset;
    const type = buf.readUInt16BE(offset); offset += 2;
    offset += 2; // class
    offset += 4; // ttl
    const rdlen = buf.readUInt16BE(offset); offset += 2;
    const rdata = buf.slice(offset, offset + rdlen);
    offset += rdlen;
    answers.push({ name, type, rdata });
  }
  return answers;
}

function parseHTTPSRecord(rdata) {
  let offset = 0;
  const priority = rdata.readUInt16BE(offset); offset += 2;
  const { nextOffset } = decodeDnsName(rdata, offset);
  offset = nextOffset;
  const svcParams = {};
  while (offset < rdata.length) {
    const key = rdata.readUInt16BE(offset); offset += 2;
    const len = rdata.readUInt16BE(offset); offset += 2;
    const value = rdata.slice(offset, offset + len);
    offset += len;
    svcParams[key] = value;
  }
  return { priority, svcParams };
}

function queryDoHSingle(server, query) {
  return new Promise((resolve, reject) => {
    const url = new URL(server);
    const options = {
      hostname: url.hostname,
      port: 443,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message',
        'Content-Length': query.length,
      },
      timeout: 10000,
    };
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try { resolve(parseDnsResponse(Buffer.concat(chunks))); }
        catch (e) { reject(e); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('DoH timeout')); });
    req.on('error', reject);
    req.write(query);
    req.end();
  });
}

async function queryDoH(domain, type = 65) {
  const query = buildDnsQuery(domain, type);
  for (const server of DOH_SERVERS) {
    try {
      return await queryDoHSingle(server, query);
    } catch {}
  }
  throw new Error('所有 DoH 服务器查询失败');
}

// ─── ECH config ───

let echConfigCache = null;
let echConfigFailed = false;

async function fetchECHConfig(domain = ECH_PROVIDER) {
  if (echConfigCache) return echConfigCache;
  if (echConfigFailed) return null;
  try {
    const answers = await queryDoH(domain, 65);
    const httpsRecords = answers.filter(a => a.type === 65);
    for (const r of httpsRecords) {
      const parsed = parseHTTPSRecord(r.rdata);
      if (parsed.svcParams[5]) {
        echConfigCache = parsed.svcParams[5];
        return echConfigCache;
      }
    }
    echConfigFailed = true;
    return null;
  } catch {
    echConfigFailed = true;
    return null;
  }
}

// ─── DNS resolution ───

async function resolveARecords(domain) {
  try {
    const answers = await queryDoH(domain, 1);
    return answers
      .filter(a => a.type === 1)
      .map(a => `${a.rdata[0]}.${a.rdata[1]}.${a.rdata[2]}.${a.rdata[3]}`);
  } catch {
    return [];
  }
}

// ─── 边缘接入点（colo）───

// 三字码 → 城市，取自 Cloudflare 官方状态页的组件名（"Los Angeles, United States - (LAX)"）。
// 内置成文件是为了不多依赖一个会变的接口；缺失时降级成只显示三字码。
let coloCityCache = null;

function loadColoCityMap() {
  if (coloCityCache) return coloCityCache;
  try {
    coloCityCache = JSON.parse(readFileSync(COLOS_FILE, 'utf8'));
  } catch {
    coloCityCache = {};
  }
  return coloCityCache;
}

// 常用接入点的中文名；未收录的退回英文城市名。
const COLO_CITY_ZH = {
  LAX: '洛杉矶', SJC: '圣何塞', SEA: '西雅图', SFO: '旧金山',
  NRT: '东京', KIX: '大阪', ICN: '首尔', TPE: '台北', HKG: '香港',
  SIN: '新加坡', KUL: '吉隆坡', BKK: '曼谷', CGK: '雅加达',
  LHR: '伦敦', FRA: '法兰克福', AMS: '阿姆斯特丹', CDG: '巴黎',
  SYD: '悉尼', MEX: '墨西哥城', SCL: '圣地亚哥', GRU: '圣保罗',
};

function coloCity(colo) {
  if (!colo) return null;
  return COLO_CITY_ZH[colo] || loadColoCityMap()[colo] || null;
}

// 展示用标签："LAX 洛杉矶"，只有三字码时就是 "LAX"，拿不到就是 "未知"。
function describeColo(colo) {
  if (!colo) return '未知';
  const city = coloCity(colo);
  return city ? `${colo} ${city}` : colo;
}

// 从 /cdn-cgi/trace 的正文里取 colo。正文是每行一个 key=value 的纯文本。
function parseTraceColo(body) {
  if (typeof body !== 'string') return null;
  const m = /^colo=([A-Za-z0-9]{3,})$/m.exec(body);
  return m ? m[1].toUpperCase() : null;
}

// 想问出「这次握手落在了哪个 CF 边缘节点」，只有一条路：连上去要 /cdn-cgi/trace。
// 这是 Cloudflare 在每个它代理的域名下自带的调试端点，colo 由 CF 按实际接入点填写。
// 用 GeoIP 查 IP 对 CF 的 anycast 地址是错的：全球边缘共享同一批 IP，
// 地理库只会告诉你这块前缀注册在哪（常见答案是多伦多），跟你的真实落地无关。
// 拿不到就返回 null —— colo 只作标注，绝不参与评分。
function fetchColo(ip, domain, timeoutMs = COLO_TIMEOUT) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const req = https.get({
      host: ip,
      port: 443,
      path: TRACE_PATH,
      servername: domain,
      // 必须显式给 Host：用 IP 做 host 时 Node 会把 Host 写成 IP，
      // CF 按 Host 找站点，用 IP 路由会拿不到 trace（返回空或报错页）。
      headers: { host: domain },
      method: 'GET',
      timeout: timeoutMs,
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const colo = parseTraceColo(Buffer.concat(chunks).toString('utf8'));
        if (colo) return finish(colo);
        // 正文被改写时退回响应头：cf-ray 的后缀就是同一个三字码。
        const ray = String(res.headers['cf-ray'] || '');
        const m = /-([A-Z]{3})$/.exec(ray);
        finish(m ? m[1] : null);
      });
      res.on('error', () => finish(null));
    });
    req.on('timeout', () => { req.destroy(); finish(null); });
    req.on('error', () => finish(null));
  });
}

// 给结果列表补 colo 字段。每条结果需要 ip 和 domain（也可用 domain 选项统一指定，
// 因为 -c / -t 的结果行只带 ip），同一个 (ip, domain) 只探一次。
// 调用点都放在所有握手计时结束之后，避免多出来的连接干扰延迟数字。
async function attachColos(items, { concurrency = CONCURRENCY, domain = null, fetch = fetchColo } = {}) {
  const cache = new Map();
  const tasks = items.map(item => async () => {
    const target = item.domain || domain;
    if (!item.ip || !target) {
      item.colo = null;
      return;
    }
    const key = `${item.ip}|${target}`;
    if (!cache.has(key)) cache.set(key, fetch(item.ip, target));
    item.colo = await cache.get(key);
  });
  await runWithPool(tasks, concurrency);
  return items;
}

// ─── Network utilities ───

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { timeout: 10000 }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString())); }
        catch (e) { reject(e); }
      });
    }).on('error', reject).on('timeout', function() { this.destroy(); reject(new Error('timeout')); });
  });
}

function ipToNum(ip) {
  return ip.split('.').reduce((n, o) => (n << 8) + parseInt(o), 0) >>> 0;
}

function ipInCIDR(ip, cidr) {
  const [base, bits] = cidr.split('/');
  const mask = ~((1 << (32 - parseInt(bits))) - 1) >>> 0;
  return (ipToNum(ip) & mask) === (ipToNum(base) & mask);
}

function ipInCIDRList(ip, cidrs) {
  return cidrs.some(cidr => ipInCIDR(ip, cidr));
}

async function fetchCFIPv4CIDRs() {
  try {
    const data = await fetchJSON(CF_IPS_URL);
    if (data.success && data.result && data.result.ipv4_cidrs) {
      return data.result.ipv4_cidrs;
    }
  } catch {}
  return null;
}

// ─── TLS testing ───

function testTLS(ip, timeoutMs, sni) {
  return new Promise((resolve) => {
    const start = Date.now();
    let settled = false;
    const socket = tls.connect({
      host: ip,
      port: 443,
      servername: sni,
      timeout: timeoutMs,
    }, () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ success: true, elapsed: Date.now() - start });
    });
    socket.on('timeout', () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ success: false, elapsed: Date.now() - start });
    });
    socket.on('error', () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ success: false, elapsed: Date.now() - start });
    });
  });
}

function testECHTLS(ip, timeoutMs, sni, echConfig) {
  return new Promise((resolve) => {
    const start = Date.now();
    let settled = false;
    const opts = {
      host: ip,
      port: 443,
      servername: sni,
      timeout: timeoutMs,
    };
    if (echConfig) {
      opts.ech = { config: echConfig };
    }
    const socket = tls.connect(opts, () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ success: true, elapsed: Date.now() - start });
    });
    socket.on('timeout', () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ success: false, elapsed: Date.now() - start });
    });
    socket.on('error', () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ success: false, elapsed: Date.now() - start });
    });
  });
}

// ─── Concurrency ───

async function runWithPool(tasks, concurrency) {
  const results = [];
  const queue = [...tasks];
  async function worker() {
    while (queue.length) {
      const task = queue.shift();
      results.push(await task());
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, tasks.length) }, () => worker()));
  return results;
}

// ─── Single domain check (-c) ───

async function checkDomain(domain, sink) {
  // 1. Get ECH config from cloudflare-ech.com (same as Xray)
  const echConfig = await fetchECHConfig();

  // 2. DNS resolve
  const allIPs = await resolveARecords(domain);
  if (allIPs.length === 0) {
    throw new AppError('无 A 记录，无法检测');
  }

  // 3. Verify IPs belong to Cloudflare
  const cfCIDRs = await fetchCFIPv4CIDRs();
  let cfIPs = allIPs;
  if (cfCIDRs) {
    cfIPs = allIPs.filter(ip => ipInCIDRList(ip, cfCIDRs));
    if (cfIPs.length === 0) {
      throw new AppError('IP 不属于 Cloudflare IP 段，非 CF 域名');
    }
  }

  // Header
  sink.info(`检测域名: ${domain}`);
  sink.info(`ECH 配置: ${echConfig ? '✓ 已获取' : '✗ 未获取，将使用普通 TLS'}`);
  sink.info(`解析 IP:  ${allIPs.length} 个 (${allIPs.join(', ')})`);
  if (cfCIDRs) {
    if (cfIPs.length < allIPs.length) {
      sink.info(`CF 验证:  ✓ ${cfIPs.length}/${allIPs.length} 个 IP 属 CF 段 (排除: ${allIPs.filter(ip => !cfIPs.includes(ip)).join(', ')})`);
    } else {
      sink.info(`CF 验证:  ✓ 全部 ${cfIPs.length} 个 IP 均属 CF 段`);
    }
  } else {
    sink.info('CF 验证:  ⚠ 无法获取 CF IP 段，跳过验证');
  }

  // 4. ECH TLS handshake test — 5 rounds per IP
  sink.info('');
  sink.info(`测速 (ECH TLS, 每 IP 5 轮, 超时 ${SCAN_TIMEOUT / 1000}s)`);
  const results = [];
  let tested = 0;
  for (const ip of cfIPs) {
    const latencies = [];
    for (let i = 0; i < 5; i++) {
      const r = echConfig
        ? await testECHTLS(ip, SCAN_TIMEOUT, domain, echConfig)
        : await testTLS(ip, SCAN_TIMEOUT, domain);
      if (r.success) latencies.push(r.elapsed);
    }
    tested++;
    sink.info(`  进度: ${tested}/${cfIPs.length}`);
    if (latencies.length > 0) {
      const sorted = [...latencies].sort((a, b) => a - b);
      const avg = Math.round(sorted.reduce((a, b) => a + b, 0) / sorted.length);
      const min = sorted[0];
      const max = sorted[sorted.length - 1];
      results.push({ ip, successRate: latencies.length / 5, avg, min, max, successes: latencies.length });
    } else {
      results.push({ ip, successRate: 0, avg: null, min: null, max: null, successes: 0 });
    }
  }

  // 5. 握手计时全部结束后再探 colo，避免多出来的连接干扰延迟数字
  sink.info('');
  sink.info('探测边缘接入点 (colo)...');
  await attachColos(results, { domain });

  // 6. Output results
  sink.info('');
  const maxIPLen = Math.max(...results.map(r => r.ip.length));
  // Sort: successful IPs by avg latency ascending, failed IPs at bottom
  const sorted = [...results].sort((a, b) => {
    if (a.avg == null && b.avg == null) return 0;
    if (a.avg == null) return 1;
    if (b.avg == null) return -1;
    return a.avg - b.avg;
  });
  for (const r of sorted) {
    const ratePct = Math.round(r.successRate * 100);
    if (r.successes > 0) {
      const jitter = r.max - r.min;
      sink.data(`  ${r.ip.padEnd(maxIPLen + 2)}成功率: ${ratePct}%  延迟: ${r.avg}ms (${r.min}~${r.max}ms, 抖动 ${jitter}ms)  边缘: ${describeColo(r.colo)}`);
    } else {
      sink.data(`  ${r.ip.padEnd(maxIPLen + 2)}成功率: ${ratePct}%  全部超时`);
    }
  }

  // 7. Summary + evaluation
  const totalSuccess = results.reduce((s, r) => s + r.successes, 0);
  const totalTests = results.length * 5;
  const overallRate = Math.round(totalSuccess / totalTests * 100);
  const successResults = results.filter(r => r.avg != null);
  const avgLatency = successResults.length > 0
    ? Math.round(successResults.reduce((s, r) => s + r.avg, 0) / successResults.length)
    : Infinity;
  sink.info('');
  sink.info(`总计: ${cfIPs.length} 个 IP | ${totalTests} 次握手 | 成功 ${totalSuccess} 次 (${overallRate}%) | ECH: ${echConfig ? '已启用' : '未启用'}`);

  const maxJitter = successResults.length > 0
    ? Math.max(...successResults.map(r => r.max - r.min))
    : 0;

  sink.info(evaluateCheckDomain({
    cfIPCount: cfIPs.length,
    overallRate,
    avgLatency,
    maxJitter,
  }));
}

// ─── Speed test (-t) ───

async function testDomain(domain, sink) {
  // 1. Get ECH config
  const echConfig = await fetchECHConfig();

  // 2. DNS resolve
  const aIPs = await resolveARecords(domain);
  if (aIPs.length === 0) {
    throw new AppError('无 A 记录');
  }

  // 3. Verify CF IPs
  const cfCIDRs = await fetchCFIPv4CIDRs();
  let cfIPs = aIPs;
  if (cfCIDRs) {
    cfIPs = aIPs.filter(ip => ipInCIDRList(ip, cfCIDRs));
    if (cfIPs.length === 0) {
      throw new AppError('IP 不属于 Cloudflare IP 段，非 CF 域名');
    }
  }

  // Header
  sink.info(`检测域名: ${domain}`);
  sink.info(`ECH 配置: ${echConfig ? '✓ 已获取' : '✗ 未获取，将使用普通 TLS'}`);
  sink.info(`解析 IP:  ${aIPs.length} 个 (${aIPs.join(', ')})`);
  if (cfCIDRs) {
    if (cfIPs.length < aIPs.length) {
      sink.info(`CF 验证:  ✓ ${cfIPs.length}/${aIPs.length} 个 IP 属 CF 段 (排除: ${aIPs.filter(ip => !cfIPs.includes(ip)).join(', ')})`);
    } else {
      sink.info(`CF 验证:  ✓ 全部 ${cfIPs.length} 个 IP 均属 CF 段`);
    }
  } else {
    sink.info('CF 验证:  ⚠ 无法获取 CF IP 段，跳过验证');
  }

  const maxIPLen = Math.max(...cfIPs.map(ip => ip.length));

  // Helper: print results sorted by latency ascending, failed IPs at bottom
  function printResults(results) {
    const sorted = [...results].sort((a, b) => {
      if (a.avg == null && b.avg == null) return 0;
      if (a.avg == null) return 1;
      if (b.avg == null) return -1;
      return a.avg - b.avg;
    });
    for (const r of sorted) {
      const ratePct = Math.round(r.successRate * 100);
      if (r.successes > 0) {
        const jitter = r.max - r.min;
        sink.data(`  ${r.ip.padEnd(maxIPLen + 2)}成功率: ${ratePct}%  延迟: ${r.avg}ms (${r.min}~${r.max}ms, 抖动 ${jitter}ms)  边缘: ${describeColo(r.colo)}`);
      } else {
        sink.data(`  ${r.ip.padEnd(maxIPLen + 2)}成功率: ${ratePct}%  全部超时`);
      }
    }
  }

  // --- ECH TLS 测速 (5 rounds) ---
  sink.info('');
  sink.info(`测速 (ECH TLS, 每 IP 5 轮, 超时 ${SCAN_TIMEOUT / 1000}s)`);
  const echResults = [];
  let tested = 0;
  for (const ip of cfIPs) {
    const latencies = [];
    for (let i = 0; i < 5; i++) {
      const r = echConfig
        ? await testECHTLS(ip, SCAN_TIMEOUT, domain, echConfig)
        : await testTLS(ip, SCAN_TIMEOUT, domain);
      if (r.success) latencies.push(r.elapsed);
    }
    tested++;
    sink.info(`  进度: ${tested}/${cfIPs.length}`);
    if (latencies.length > 0) {
      const sorted = [...latencies].sort((a, b) => a - b);
      const avg = Math.round(sorted.reduce((a, b) => a + b, 0) / sorted.length);
      echResults.push({ ip, successRate: latencies.length / 5, avg, min: sorted[0], max: sorted[sorted.length - 1], successes: latencies.length });
    } else {
      echResults.push({ ip, successRate: 0, avg: null, min: null, max: null, successes: 0 });
    }
  }

  // --- 普通 TLS 测速 (5 rounds) ---
  sink.info('');
  sink.info(`测速 (普通 TLS, 每 IP 5 轮, 超时 ${SCAN_TIMEOUT / 1000}s)`);
  const tlsResults = [];
  tested = 0;
  for (const ip of cfIPs) {
    const latencies = [];
    for (let i = 0; i < 5; i++) {
      const r = await testTLS(ip, SCAN_TIMEOUT, domain);
      if (r.success) latencies.push(r.elapsed);
    }
    tested++;
    sink.info(`  进度: ${tested}/${cfIPs.length}`);
    if (latencies.length > 0) {
      const sorted = [...latencies].sort((a, b) => a - b);
      const avg = Math.round(sorted.reduce((a, b) => a + b, 0) / sorted.length);
      tlsResults.push({ ip, successRate: latencies.length / 5, avg, min: sorted[0], max: sorted[sorted.length - 1], successes: latencies.length });
    } else {
      tlsResults.push({ ip, successRate: 0, avg: null, min: null, max: null, successes: 0 });
    }
  }

  // 两种模式的握手计时都跑完再探 colo：避免多出来的连接插进延迟测量里。
  // 同一个 (ip, domain) 两段结果共享一次探测，两次 printResults 都拿得到。
  sink.info('');
  sink.info('探测边缘接入点 (colo)...');
  await attachColos([...echResults, ...tlsResults], { domain });

  sink.info('');
  sink.info('ECH TLS 测速结果');
  printResults(echResults);

  sink.info('');
  sink.info('普通 TLS 测速结果');
  printResults(tlsResults);

  // Summary + evaluation
  const echTotal = echResults.reduce((s, r) => s + r.successes, 0);
  const tlsTotal = tlsResults.reduce((s, r) => s + r.successes, 0);
  const totalPerMode = cfIPs.length * 5;
  const echRate = Math.round(echTotal / totalPerMode * 100);
  const tlsRate = Math.round(tlsTotal / totalPerMode * 100);

  const echSuccess = echResults.filter(r => r.avg != null);
  const tlsSuccess = tlsResults.filter(r => r.avg != null);
  const echAvgLatency = echSuccess.length > 0
    ? Math.round(echSuccess.reduce((s, r) => s + r.avg, 0) / echSuccess.length)
    : Infinity;
  const tlsAvgLatency = tlsSuccess.length > 0
    ? Math.round(tlsSuccess.reduce((s, r) => s + r.avg, 0) / tlsSuccess.length)
    : Infinity;

  const echMaxJitter = echSuccess.length > 0
    ? Math.max(...echSuccess.map(r => r.max - r.min))
    : 0;
  const tlsMaxJitter = tlsSuccess.length > 0
    ? Math.max(...tlsSuccess.map(r => r.max - r.min))
    : 0;

  sink.info('');
  sink.info(`总计: ${cfIPs.length} 个 IP | ECH 成功 ${echTotal} 次 (${echRate}%) | 普通 成功 ${tlsTotal} 次 (${tlsRate}%)`);

  sink.info(evaluateTestDomain({
    cfIPCount: cfIPs.length,
    echRate,
    echAvgLatency,
    echMaxJitter,
    tlsRate,
    tlsAvgLatency,
    tlsMaxJitter,
  }));
}

// ─── CLI args ───

function parseFlags(argv) {
  const modeIndex = argv.findIndex(a => a === '-c' || a === '-t');
  const modeFlag = modeIndex === -1 ? null : argv[modeIndex];
  return {
    version: argv.includes('--version') || argv.includes('-v'),
    help: argv.includes('--help') || argv.includes('-h'),
    jsonMode: argv.includes('-json'),
    allMode: argv.includes('-all'),
    noECH: argv.includes('-no-ech') || argv.includes('--no-ech'),
    serverPort: (() => {
      const i = argv.findIndex(a => a === '-server');
      return i === -1 ? null : (argv[i + 1] && !argv[i + 1].startsWith('-') ? argv[i + 1] : '4837');
    })(),
    host: (() => {
      const i = argv.findIndex(a => a === '-host');
      return i !== -1 && argv[i + 1] ? argv[i + 1] : null;
    })(),
    mode: modeFlag === '-c' ? 'check' : modeFlag === '-t' ? 'test' : null,
    domain: modeIndex === -1 ? null : (argv[modeIndex + 1] || null),
  };
}

// 把 HTTP query 映射成和 CLI 一致的开关组合。
// 认得的键: all / json / noech / mode / domain。任何未知键直接报错，
// 避免拼错参数后静默跑成默认扫描。
function parseQuery(searchParams) {
  const known = new Set(['all', 'json', 'noech', 'mode', 'domain']);
  for (const key of searchParams.keys()) {
    if (!known.has(key)) return { error: `未知参数: ${key}` };
  }

  const flag = (name) => {
    const raw = searchParams.get(name);
    if (raw === null) return false;
    return raw !== '0' && raw !== 'false';
  };

  const flags = {
    allMode: flag('all'),
    jsonMode: flag('json'),
    noECH: flag('noech'),
    mode: null,
    domain: null,
  };

  const mode = searchParams.get('mode');
  if (mode === null) {
    if (searchParams.get('domain') !== null) {
      return { error: 'domain 需要配合 mode=check 或 mode=test 使用' };
    }
    return { flags };
  }
  if (mode !== 'check' && mode !== 'test') {
    return { error: `mode 只能是 check 或 test，收到: ${mode}` };
  }
  if (flags.allMode || flags.jsonMode || flags.noECH) {
    return { error: 'mode 与 all / json / noech 不能同时使用' };
  }
  const domain = (searchParams.get('domain') || '').trim();
  if (!domain) return { error: '缺少 domain 参数' };

  flags.mode = mode;
  flags.domain = domain;
  return { flags };
}

// ─── Runners（输出统一走 sink）───

function buildBanner(color) {
  if (!color) {
    return [
      "(             )",
      " `--(_   _)--'",
      '      Y-Y',
      '     /@@ \\',
      '    /     \\',
      "    `--'.  \\             ,",
      '        |   `.__________/)',
      ' CF-ECH',
      '------------------------------------------------',
    ].join('\n');
  }
  const g = '\x1b[32m';
  const w = '\x1b[37m';
  const y = '\x1b[33m';
  const d = '\x1b[90m';
  const r = '\x1b[0m';
  return [
    `${g}(             )${r}`,
    `${g} \`--(_   _)--'${r}`,
    `${g}      Y-Y${r}`,
    `${w}     /${y}@@${w} \\${r}`,
    `${w}    /     \\${r}`,
    `${w}    \`--'.  \\             ,${r}`,
    `${w}        |   \`.__________/)${r}`,
    `${w} CF-ECH${r}`,
    `${d}------------------------------------------------${r}`,
  ].join('\n');
}

const HELP_TEXT = `cf-ech - 发现指向 Cloudflare CDN 的优质域名

用法:
  cf-ech              扫描并输出前 20 个实测支持 ECH 的优质域名
  cf-ech -no-ech      跳过 ECH 探测，只按普通 TLS 握手筛选优选域名
  cf-ech -all         输出所有实测通过的域名
  cf-ech -json        以 JSON 格式输出
  cf-ech -c <domain>  检测指定域名（ECH 实测 + 连接质量评估）
  cf-ech -t <domain>  对指定域名的 A 记录 IP 进行 ECH + 无 ECH 双模式 TLS 测速
  cf-ech -server      启动 HTTP 服务（默认端口 4837），参数通过 URL query 传入
  cf-ech --help       显示帮助信息

服务模式:
  cf-ech -server          监听 0.0.0.0:4837
  cf-ech -server 8080     指定端口
  cf-ech -host 127.0.0.1  限制只本机可访问

  GET /                       用法说明页
  GET /?json=1                批量扫描，JSON 输出
  GET /?all=1&noech=1         全部结果，只做普通 TLS
  GET /?mode=check&domain=a.com   等价于 -c a.com
  GET /?mode=test&domain=a.com    等价于 -t a.com`;

async function runBatchScan(flags, sink) {
  const { jsonMode, allMode, noECH } = flags;

  sink.info(buildBanner(sink.color));
  sink.info(noECH
    ? '正在按普通 TLS 扫描优选 CF 域名列表（已跳过 ECH 探测）...'
    : '正在扫描实测支持 ECH 的 CF 域名列表...');
  sink.info('');

  // 1. Load domains
  const localDomains = readFileSync(DOMAIN_FILE, 'utf8')
    .trim().split('\n').map(d => d.trim()).filter(Boolean);
  sink.info(`本地域名: ${localDomains.length} 个`);

  let onlineDomains = [];
  try {
    const resp = await fetchJSON(CF_TOP20_API);
    if (resp.code === 0 && resp.data && resp.data.good) {
      onlineDomains = resp.data.good
        .map(item => item.ip)
        .filter(ip => ip && /[a-z]/i.test(ip));
    }
    sink.info(`在线域名: ${onlineDomains.length} 个`);
  } catch (e) {
    sink.info(`在线获取失败 (${e.message})，跳过`);
  }

  const domains = [...new Set([...localDomains, ...onlineDomains])];
  sink.info(`合并去重: ${domains.length} 个`);

  // 2. Get ECH config once (skipped entirely in -no-ech mode)
  let echConfig = null;
  if (noECH) {
    sink.info('ECH 公钥: 已跳过 (-no-ech)，仅做普通 TLS 握手');
  } else {
    sink.info('获取 ECH 公钥配置...');
    echConfig = await fetchECHConfig();
    if (echConfig) {
      sink.info(`ECH 公钥: 已获取 (来自 ${ECH_PROVIDER}, ${echConfig.length} bytes)`);
    } else {
      sink.info('警告: 无法获取 ECH 公钥配置，将使用普通 TLS 测试（结果准确性降低）');
    }
  }

  // 3. DNS resolve all domains
  sink.info('DNS 解析所有域名...');
  const domainIPs = {};
  let dnsChecked = 0;
  const dnsTasks = domains.map(domain => async () => {
    const ips = await resolveARecords(domain);
    dnsChecked++;
    if (dnsChecked % 100 === 0 || dnsChecked === domains.length) {
      sink.info(`  进度: ${dnsChecked}/${domains.length}`);
    }
    if (ips.length > 0) domainIPs[domain] = ips;
  });
  await runWithPool(dnsTasks, CONCURRENCY);
  sink.info(`有 A 记录: ${Object.keys(domainIPs).length} 个`);

  // 4. Filter domains with CF IPs
  sink.info('验证 CF IP...');
  const cfCIDRs = await fetchCFIPv4CIDRs();
  const domainCFIPs = {};
  for (const [domain, ips] of Object.entries(domainIPs)) {
    const cfIPs = cfCIDRs ? ips.filter(ip => ipInCIDRList(ip, cfCIDRs)) : ips;
    if (cfIPs.length > 0) domainCFIPs[domain] = cfIPs;
  }
  if (cfCIDRs) {
    sink.info(`IP 属 CF 段的域名: ${Object.keys(domainCFIPs).length} 个`);
  } else {
    sink.info(`警告: 无法获取 CF IP 段，跳过验证，可用域名: ${Object.keys(domainCFIPs).length} 个`);
  }

  if (Object.keys(domainCFIPs).length === 0) {
    sink.info('未找到任何指向 CF IP 的域名');
    return;
  }

  // 5. Deduplicate IPs across domains
  const ipDomains = {};
  for (const [domain, ips] of Object.entries(domainCFIPs)) {
    for (const ip of ips) {
      if (!ipDomains[ip]) ipDomains[ip] = [];
      ipDomains[ip].push(domain);
    }
  }
  const uniqueIPs = Object.keys(ipDomains);
  sink.info(`唯一 IP 数: ${uniqueIPs.length} 个（已跨域名去重）`);

  // 6. ECH (or plain) TLS test each unique IP (2 rounds)
  sink.info(`开始 ${echConfig ? 'ECH TLS' : '普通 TLS'} 实测 (每 IP 2 轮, 并发 ${CONCURRENCY}, 超时 ${SCAN_TIMEOUT / 1000}s)...`);
  const ipResults = {};
  let tested = 0;
  const testTasks = uniqueIPs.map(ip => async () => {
    const domain = ipDomains[ip][0];
    const r1 = echConfig
      ? await testECHTLS(ip, SCAN_TIMEOUT, domain, echConfig)
      : await testTLS(ip, SCAN_TIMEOUT, domain);
    const r2 = echConfig
      ? await testECHTLS(ip, SCAN_TIMEOUT, domain, echConfig)
      : await testTLS(ip, SCAN_TIMEOUT, domain);
    tested++;
    if (tested % 50 === 0 || tested === uniqueIPs.length) {
      sink.info(`  进度: ${tested}/${uniqueIPs.length}`);
    }
    const successes = [r1, r2].filter(r => r.success);
    if (successes.length > 0) {
      ipResults[ip] = {
        success: true,
        successCount: successes.length,
        elapsed: Math.round(successes.reduce((s, r) => s + r.elapsed, 0) / successes.length),
      };
    } else {
      ipResults[ip] = { success: false, successCount: 0 };
    }
  });
  await runWithPool(testTasks, CONCURRENCY);

  // 7. Filter 100% success domains, then score
  const domainScores = [];
  for (const [domain, ips] of Object.entries(domainCFIPs)) {
    const domainScore = buildDomainScore(domain, ips, ipResults);
    if (domainScore) domainScores.push(domainScore);
  }

  // Sort by score descending, then prefer lower average latency, lower spread, and fastest IP.
  domainScores.sort((a, b) =>
    b.score - a.score ||
    a.avgLatency - b.avgLatency ||
    a.spread - b.spread ||
    a.elapsed - b.elapsed
  );

  sink.info('');

  // 8. Output
  const outputList = allMode ? domainScores : domainScores.slice(0, 20);

  // 只对真正要输出的那几条探 colo：全量探会多出上百条连接，且探了也没人看。
  // 放在第 6 步所有计时结束后，不干扰延迟数字。
  sink.info(`探测边缘接入点 (colo): ${outputList.length} 个域名...`);
  await attachColos(outputList);

  if (jsonMode) {
    return { json: outputList };
  }

  const maxDomainLen = Math.max(...outputList.map(r => r.domain.length));
  const maxIPLen = Math.max(...outputList.map(r => r.ip.length));
  const maxLatencyLen = Math.max(...outputList.map(r => String(r.elapsed).length));
  for (const r of outputList) {
    sink.data(`${r.domain.padEnd(maxDomainLen + 2)}${r.ip.padEnd(maxIPLen + 2)}${`${r.elapsed}ms`.padEnd(maxLatencyLen + 3)}${describeColo(r.colo)}`);
  }

  // 9. Report (stderr)
  sink.info('');
  sink.info(`扫描域名: ${domains.length} | CF 域名: ${Object.keys(domainCFIPs).length} | 100%成功率: ${domainScores.length} | 优选结果: ${outputList.length}`);
  sink.info(`硬性要求: 所有 IP 的 TLS 握手成功率必须 100%，且至少 2 个 IP`);
  sink.info(`评分维度: 平均延迟(70%) + IP间稳定性(20%) + IP数<=3奖励(10%)`);
  sink.info(`边缘列: colo 是本次实测的 CF 接入点（受本机网络环境影响），非域名固有属性`);
  sink.info(`ECH: ${noECH ? '已跳过 (-no-ech)' : echConfig ? '已启用' : '未启用(普通TLS)'}`);
}

// 单次请求对应的执行入口。返回 { json } 时由调用方负责把它整体输出，
// 保证 HTTP 的 JSON 响应里不混入流式进度文字。
async function runRequest(flags, sink) {
  if (flags.mode === 'check') return checkDomain(flags.domain, sink);
  if (flags.mode === 'test') return testDomain(flags.domain, sink);
  return runBatchScan(flags, sink);
}

function cliSink() {
  // 换行由 createSink 统一补，这里只负责原样写出去，否则每条会多出空行。
  return createSink({
    write: (line) => process.stdout.write(line),
    info: (line) => process.stderr.write(line),
    color: process.stderr.isTTY === true,
  });
}

function startServer({ port, host }) {
  const { createServer } = require('./server.js');
  const server = createServer({
    run: runRequest,
    parseQuery,
    isAppError: (e) => e instanceof AppError,
    log: (msg) => process.stderr.write(msg + '\n'),
  });

  server.on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
      process.stderr.write(`端口 ${port} 已被占用，换个端口: cf-ech -server <port>\n`);
      process.exit(1);
    }
    process.stderr.write(`服务启动失败: ${e.message}\n`);
    process.exit(1);
  });

  server.listen(port, host, () => {
    const shown = host === '0.0.0.0' ? '<本机IP>' : host;
    process.stderr.write(`cf-ech 服务已启动: http://${shown}:${port}/\n`);
    process.stderr.write(`  用法说明: http://${shown}:${port}/\n`);
    process.stderr.write(`  批量扫描: http://${shown}:${port}/?json=1\n`);
    process.stderr.write(`  按 Ctrl+C 停止\n`);
  });

  return server;
}

// ─── Main ───

async function main() {
  const args = process.argv.slice(2);
  const flags = parseFlags(args);
  const { version, help, noECH, mode, domain, serverPort, host } = flags;
  const sink = cliSink();

  if (version) {
    const pkg = JSON.parse(readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
    sink.data(pkg.version);
    return;
  }

  if (help) {
    sink.data(HELP_TEXT);
    return;
  }

  if (serverPort !== null) {
    if (mode !== null) {
      process.stderr.write('-server 不能与 -c / -t 同时使用\n');
      process.exit(1);
    }
    if (Number.isNaN(Number(serverPort)) || Number(serverPort) < 0 || Number(serverPort) > 65535) {
      process.stderr.write(`无效端口: ${serverPort}\n`);
      process.exit(1);
    }
    return startServer({ port: Number(serverPort), host: host || '0.0.0.0' });
  }

  if (noECH && mode !== null) {
    process.stderr.write('-no-ech 仅用于批量扫描；单域名的无 ECH 结果请用: cf-ech -t <domain>\n');
    process.exit(1);
  }

  if (mode === 'test') {
    if (!domain) {
      process.stderr.write('用法: cf-ech -t <domain>\n');
      process.exit(1);
    }
    return testDomain(domain, sink);
  }

  if (mode === 'check') {
    if (!domain) {
      process.stderr.write('用法: cf-ech -c <domain>\n');
      process.exit(1);
    }
    return checkDomain(domain, sink);
  }

  const result = await runBatchScan(flags, sink);
  if (result && result.json) sink.data(JSON.stringify(result.json, null, 2));
}

if (require.main === module) {
  main().catch(e => {
    process.stderr.write(`${e instanceof AppError ? '' : '致命错误: '}${e.message}\n`);
    process.exit(1);
  });
}

module.exports = {
  AppError,
  createSink,
  buildDomainScore,
  attachColos,
  coloCity,
  describeColo,
  evaluateCheckDomain,
  evaluateTestDomain,
  fetchColo,
  loadColoCityMap,
  parseFlags,
  parseQuery,
  parseTraceColo,
  runBatchScan,
  runRequest,
};
