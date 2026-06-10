#!/usr/bin/env node

const tls = require('tls');
const https = require('https');
const crypto = require('crypto');
const { readFileSync } = require('fs');
const path = require('path');

const DOMAIN_FILE = path.join(__dirname, '..', 'data', 'domains.txt');
const CF_TOP20_API = 'https://vps789.com/openApi/cfIpTop20';
const CF_IPS_URL = 'https://api.cloudflare.com/client/v4/ips';
const ECH_PROVIDER = 'cloudflare-ech.com';
const DOH_SERVERS = [
  'https://dns.alidns.com/dns-query',
  'https://cloudflare-dns.com/dns-query',
];
const CONCURRENCY = 50;
const SCAN_TIMEOUT = 5000;
const MAX_RECOMMENDED_LATENCY = 800; // ms — 优选节点的平均延迟上限
const MAX_RECOMMENDED_JITTER = 1000; // ms — 优选节点的单 IP 抖动上限

function log(msg) { process.stderr.write(msg + '\n'); }

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

async function checkDomain(domain) {
  // 1. Get ECH config from cloudflare-ech.com (same as Xray)
  const echConfig = await fetchECHConfig();

  // 2. DNS resolve
  const allIPs = await resolveARecords(domain);
  if (allIPs.length === 0) {
    log('结果: 无 A 记录，无法检测');
    process.exit(1);
  }

  // 3. Verify IPs belong to Cloudflare
  const cfCIDRs = await fetchCFIPv4CIDRs();
  let cfIPs = allIPs;
  if (cfCIDRs) {
    cfIPs = allIPs.filter(ip => ipInCIDRList(ip, cfCIDRs));
    if (cfIPs.length === 0) {
      log('结果: IP 不属于 Cloudflare IP 段，非 CF 域名');
      process.exit(1);
    }
  }

  // Header
  log(`检测域名: ${domain}`);
  log(`ECH 配置: ${echConfig ? '✓ 已获取' : '✗ 未获取，将使用普通 TLS'}`);
  log(`解析 IP:  ${allIPs.length} 个 (${allIPs.join(', ')})`);
  if (cfCIDRs) {
    if (cfIPs.length < allIPs.length) {
      log(`CF 验证:  ✓ ${cfIPs.length}/${allIPs.length} 个 IP 属 CF 段 (排除: ${allIPs.filter(ip => !cfIPs.includes(ip)).join(', ')})`);
    } else {
      log(`CF 验证:  ✓ 全部 ${cfIPs.length} 个 IP 均属 CF 段`);
    }
  } else {
    log('CF 验证:  ⚠ 无法获取 CF IP 段，跳过验证');
  }

  // 4. ECH TLS handshake test — 5 rounds per IP
  log('');
  log(`测速 (ECH TLS, 每 IP 5 轮, 超时 ${SCAN_TIMEOUT / 1000}s)`);
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
    log(`  进度: ${tested}/${cfIPs.length}`);
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

  // 5. Output results
  log('');
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
      console.log(`  ${r.ip.padEnd(maxIPLen + 2)}成功率: ${ratePct}%  延迟: ${r.avg}ms (${r.min}~${r.max}ms, 抖动 ${jitter}ms)`);
    } else {
      console.log(`  ${r.ip.padEnd(maxIPLen + 2)}成功率: ${ratePct}%  全部超时`);
    }
  }

  // 6. Summary + evaluation
  const totalSuccess = results.reduce((s, r) => s + r.successes, 0);
  const totalTests = results.length * 5;
  const overallRate = Math.round(totalSuccess / totalTests * 100);
  const successResults = results.filter(r => r.avg != null);
  const avgLatency = successResults.length > 0
    ? Math.round(successResults.reduce((s, r) => s + r.avg, 0) / successResults.length)
    : Infinity;
  log('');
  log(`总计: ${cfIPs.length} 个 IP | ${totalTests} 次握手 | 成功 ${totalSuccess} 次 (${overallRate}%) | ECH: ${echConfig ? '已启用' : '未启用'}`);

  const maxJitter = successResults.length > 0
    ? Math.max(...successResults.map(r => r.max - r.min))
    : 0;

  if (overallRate === 100 && avgLatency < MAX_RECOMMENDED_LATENCY && maxJitter <= MAX_RECOMMENDED_JITTER) {
    log('评价: ECH 连接质量优秀，适合作为优选 ECH CF 接入点');
  } else if (overallRate >= 90) {
    log('评价: 连接质量良好，可作为普通 CF 节点接入');
  } else if (overallRate >= 70) {
    log('评价: 连接质量一般，可作为普通 CF 节点接入');
  } else if (overallRate > 0) {
    log('评价: 连接不稳定，不推荐');
  } else {
    log('评价: 无法连接，不可用');
  }
}

// ─── Speed test (-t) ───

async function testDomain(domain) {
  // 1. Get ECH config
  const echConfig = await fetchECHConfig();

  // 2. DNS resolve
  const aIPs = await resolveARecords(domain);
  if (aIPs.length === 0) {
    log('结果: 无 A 记录');
    process.exit(1);
  }

  // 3. Verify CF IPs
  const cfCIDRs = await fetchCFIPv4CIDRs();
  let cfIPs = aIPs;
  if (cfCIDRs) {
    cfIPs = aIPs.filter(ip => ipInCIDRList(ip, cfCIDRs));
    if (cfIPs.length === 0) {
      log('结果: IP 不属于 Cloudflare IP 段，非 CF 域名');
      process.exit(1);
    }
  }

  // Header
  log(`检测域名: ${domain}`);
  log(`ECH 配置: ${echConfig ? '✓ 已获取' : '✗ 未获取，将使用普通 TLS'}`);
  log(`解析 IP:  ${aIPs.length} 个 (${aIPs.join(', ')})`);
  if (cfCIDRs) {
    if (cfIPs.length < aIPs.length) {
      log(`CF 验证:  ✓ ${cfIPs.length}/${aIPs.length} 个 IP 属 CF 段 (排除: ${aIPs.filter(ip => !cfIPs.includes(ip)).join(', ')})`);
    } else {
      log(`CF 验证:  ✓ 全部 ${cfIPs.length} 个 IP 均属 CF 段`);
    }
  } else {
    log('CF 验证:  ⚠ 无法获取 CF IP 段，跳过验证');
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
        console.log(`  ${r.ip.padEnd(maxIPLen + 2)}成功率: ${ratePct}%  延迟: ${r.avg}ms (${r.min}~${r.max}ms, 抖动 ${jitter}ms)`);
      } else {
        console.log(`  ${r.ip.padEnd(maxIPLen + 2)}成功率: ${ratePct}%  全部超时`);
      }
    }
  }

  // --- ECH TLS 测速 (5 rounds) ---
  log('');
  log(`测速 (ECH TLS, 每 IP 5 轮, 超时 ${SCAN_TIMEOUT / 1000}s)`);
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
    log(`  进度: ${tested}/${cfIPs.length}`);
    if (latencies.length > 0) {
      const sorted = [...latencies].sort((a, b) => a - b);
      const avg = Math.round(sorted.reduce((a, b) => a + b, 0) / sorted.length);
      echResults.push({ ip, successRate: latencies.length / 5, avg, min: sorted[0], max: sorted[sorted.length - 1], successes: latencies.length });
    } else {
      echResults.push({ ip, successRate: 0, avg: null, min: null, max: null, successes: 0 });
    }
  }

  log('');
  printResults(echResults);

  // --- 普通 TLS 测速 (5 rounds) ---
  log('');
  log(`测速 (普通 TLS, 每 IP 5 轮, 超时 ${SCAN_TIMEOUT / 1000}s)`);
  const tlsResults = [];
  tested = 0;
  for (const ip of cfIPs) {
    const latencies = [];
    for (let i = 0; i < 5; i++) {
      const r = await testTLS(ip, SCAN_TIMEOUT, domain);
      if (r.success) latencies.push(r.elapsed);
    }
    tested++;
    log(`  进度: ${tested}/${cfIPs.length}`);
    if (latencies.length > 0) {
      const sorted = [...latencies].sort((a, b) => a - b);
      const avg = Math.round(sorted.reduce((a, b) => a + b, 0) / sorted.length);
      tlsResults.push({ ip, successRate: latencies.length / 5, avg, min: sorted[0], max: sorted[sorted.length - 1], successes: latencies.length });
    } else {
      tlsResults.push({ ip, successRate: 0, avg: null, min: null, max: null, successes: 0 });
    }
  }

  log('');
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

  log('');
  log(`总计: ${cfIPs.length} 个 IP | ECH 成功 ${echTotal} 次 (${echRate}%) | 普通 成功 ${tlsTotal} 次 (${tlsRate}%)`);

  if (echRate === 100 && echAvgLatency < MAX_RECOMMENDED_LATENCY && echMaxJitter <= MAX_RECOMMENDED_JITTER) {
    log('评价: ECH 连接质量优秀，适合作为优选 ECH CF 接入点');
  } else if (tlsRate === 100 && tlsAvgLatency < MAX_RECOMMENDED_LATENCY && tlsMaxJitter <= MAX_RECOMMENDED_JITTER) {
    log('评价: 连接质量良好，可作为普通 CF 节点接入');
  } else if (echRate >= 70 || tlsRate >= 70) {
    log('评价: 连接质量一般，高峰期可能不稳定');
  } else if (echRate > 0 || tlsRate > 0) {
    log('评价: 连接质量差，不推荐');
  } else {
    log('评价: 无法连接，不可用');
  }
}

// ─── Main ───

async function main() {
  const args = process.argv.slice(2);
  const jsonMode = args.includes('-json');
  const allMode = args.includes('-all');

  if (args.includes('--version') || args.includes('-v')) {
    const pkg = JSON.parse(readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
    console.log(pkg.version);
    return;
  }

  if (args.includes('--help') || args.includes('-h')) {
    console.log(`cf-ech - 发现指向 Cloudflare CDN 且实测支持 ECH 的优质域名

用法:
  cf-ech              扫描并输出前 20 个优质域名
  cf-ech -all         输出所有实测通过的域名
  cf-ech -json        以 JSON 格式输出
  cf-ech -c <domain>  检测指定域名（ECH 实测 + 连接质量评估）
  cf-ech -t <domain>  对指定域名的 A 记录 IP 进行 ECH + 无 ECH 双模式 TLS 测速
  cf-ech --help       显示帮助信息`);
    return;
  }

  const tIdx = args.indexOf('-t');
  if (tIdx !== -1) {
    const domain = args[tIdx + 1];
    if (!domain) {
      process.stderr.write('用法: cf-ech -t <domain>\n');
      process.exit(1);
    }
    return testDomain(domain);
  }

  const cIdx = args.indexOf('-c');
  if (cIdx !== -1) {
    const domain = args[cIdx + 1];
    if (!domain) {
      process.stderr.write('用法: cf-ech -c <domain>\n');
      process.exit(1);
    }
    return checkDomain(domain);
  }

  const g = '\x1b[32m';
  const w = '\x1b[37m';
  const y = '\x1b[33m';
  const d = '\x1b[90m';
  const r = '\x1b[0m';
  const banner = [
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
  log(banner);
  log('正在扫描实测支持 ECH 的 CF 域名列表...');
  log('');

  // 1. Load domains
  const localDomains = readFileSync(DOMAIN_FILE, 'utf8')
    .trim().split('\n').map(d => d.trim()).filter(Boolean);
  log(`本地域名: ${localDomains.length} 个`);

  let onlineDomains = [];
  try {
    const resp = await fetchJSON(CF_TOP20_API);
    if (resp.code === 0 && resp.data && resp.data.good) {
      onlineDomains = resp.data.good
        .map(item => item.ip)
        .filter(ip => ip && /[a-z]/i.test(ip));
    }
    log(`在线域名: ${onlineDomains.length} 个`);
  } catch (e) {
    log(`在线获取失败 (${e.message})，跳过`);
  }

  const domains = [...new Set([...localDomains, ...onlineDomains])];
  log(`合并去重: ${domains.length} 个`);

  // 2. Get ECH config once
  log('获取 ECH 公钥配置...');
  const echConfig = await fetchECHConfig();
  if (echConfig) {
    log(`ECH 公钥: 已获取 (来自 ${ECH_PROVIDER}, ${echConfig.length} bytes)`);
  } else {
    log('警告: 无法获取 ECH 公钥配置，将使用普通 TLS 测试（结果准确性降低）');
  }

  // 3. DNS resolve all domains
  log('DNS 解析所有域名...');
  const domainIPs = {};
  let dnsChecked = 0;
  const dnsTasks = domains.map(domain => async () => {
    const ips = await resolveARecords(domain);
    dnsChecked++;
    if (dnsChecked % 100 === 0 || dnsChecked === domains.length) {
      log(`  进度: ${dnsChecked}/${domains.length}`);
    }
    if (ips.length > 0) domainIPs[domain] = ips;
  });
  await runWithPool(dnsTasks, CONCURRENCY);
  log(`有 A 记录: ${Object.keys(domainIPs).length} 个`);

  // 4. Filter domains with CF IPs
  log('验证 CF IP...');
  const cfCIDRs = await fetchCFIPv4CIDRs();
  const domainCFIPs = {};
  for (const [domain, ips] of Object.entries(domainIPs)) {
    const cfIPs = cfCIDRs ? ips.filter(ip => ipInCIDRList(ip, cfCIDRs)) : ips;
    if (cfIPs.length > 0) domainCFIPs[domain] = cfIPs;
  }
  if (cfCIDRs) {
    log(`IP 属 CF 段的域名: ${Object.keys(domainCFIPs).length} 个`);
  } else {
    log(`警告: 无法获取 CF IP 段，跳过验证，可用域名: ${Object.keys(domainCFIPs).length} 个`);
  }

  if (Object.keys(domainCFIPs).length === 0) {
    log('未找到任何指向 CF IP 的域名');
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
  log(`唯一 IP 数: ${uniqueIPs.length} 个（已跨域名去重）`);

  // 6. ECH TLS test each unique IP (2 rounds)
  log(`开始 ECH TLS 实测 (每 IP 2 轮, 并发 ${CONCURRENCY}, 超时 ${SCAN_TIMEOUT / 1000}s)...`);
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
      log(`  进度: ${tested}/${uniqueIPs.length}`);
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

  log('');

  // 8. Output
  const outputList = allMode ? domainScores : domainScores.slice(0, 20);

  if (jsonMode) {
    console.log(JSON.stringify(outputList, null, 2));
  } else {
    const maxDomainLen = Math.max(...outputList.map(r => r.domain.length));
    for (const r of outputList) {
      console.log(`${r.domain.padEnd(maxDomainLen + 2)}${r.ip.padEnd(18)}${r.elapsed}ms`);
    }
  }

  // 9. Report (stderr)
  log('');
  log(`扫描域名: ${domains.length} | CF 域名: ${Object.keys(domainCFIPs).length} | 100%成功率: ${domainScores.length} | 优选结果: ${outputList.length}`);
  log(`硬性要求: 所有 IP 的 TLS 握手成功率必须 100%，且至少 2 个 IP`);
  log(`评分维度: 平均延迟(70%) + IP间稳定性(20%) + IP数<=3奖励(10%)`);
  log(`ECH: ${echConfig ? '已启用' : '未启用(普通TLS)'}`);
}

if (require.main === module) {
  main().catch(e => {
    process.stderr.write(`致命错误: ${e.message}\n`);
    process.exit(1);
  });
}

module.exports = {
  buildDomainScore,
};
