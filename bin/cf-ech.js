#!/usr/bin/env node

const tls = require('tls');
const https = require('https');
const crypto = require('crypto');
const { readFileSync } = require('fs');
const path = require('path');

const DOMAIN_FILE = path.join(__dirname, '..', 'data', 'domains.txt');
const CF_TOP20_API = 'https://vps789.com/openApi/cfIpTop20';
const CF_IPS_URL = 'https://api.cloudflare.com/client/v4/ips';
const ECH_TEST_DOMAIN = 'cloudflare.com';
const DOH_SERVERS = [
  'https://dns.alidns.com/dns-query',
  'https://cloudflare-dns.com/dns-query',
];
const CONCURRENCY = 50;
const SCAN_TIMEOUT = 5000;

function log(msg) { process.stderr.write(msg + '\n'); }

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

function testTLS(ip, timeoutMs) {
  return new Promise((resolve) => {
    const start = Date.now();
    let settled = false;
    const socket = tls.connect({
      host: ip,
      port: 443,
      servername: ECH_TEST_DOMAIN,
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

async function fetchHTTPSRecord(domain) {
  try {
    const answers = await queryDoH(domain, 65);
    const httpsRecords = answers.filter(a => a.type === 65);
    if (httpsRecords.length === 0) return null;
    const result = {};
    for (const record of httpsRecords) {
      const parsed = parseHTTPSRecord(record.rdata);
      if (parsed.svcParams[4]) {
        const buf = parsed.svcParams[4];
        const ips = [];
        for (let i = 0; i < buf.length; i += 4) {
          ips.push(`${buf[i]}.${buf[i+1]}.${buf[i+2]}.${buf[i+3]}`);
        }
        result.ipv4hint = ips;
      }
      if (parsed.svcParams[5]) {
        result.ech = parsed.svcParams[5].toString('base64');
      }
    }
    if (!result.ipv4hint || result.ipv4hint.length === 0) return null;
    return result;
  } catch {
    return null;
  }
}

// ─── Main ───

async function checkDomain(domain) {
  log(`检测域名: ${domain}`);
  const record = await fetchHTTPSRecord(domain);
  if (!record) {
    log('结果: 无 HTTPS 记录（非 CF 优选域名或无 ipv4hint）');
    process.exit(1);
  }
  log(`ipv4hint: ${record.ipv4hint.join(', ')}`);

  // 验证 IP 是否属于 CF
  log('验证 IP 是否属于 Cloudflare...');
  const cfCIDRs = await fetchCFIPv4CIDRs();
  if (cfCIDRs) {
    const cfIPs = record.ipv4hint.filter(ip => ipInCIDRList(ip, cfCIDRs));
    if (cfIPs.length === 0) {
      log('结果: IP 不属于 Cloudflare IP 段，非 CF 域名');
      process.exit(1);
    }
    log(`CF IP: ${cfIPs.join(', ')}`);
  } else {
    log('警告: 无法获取 CF IP 段列表，跳过验证');
  }

  if (!record.ech) {
    log('结果: 是 CF 域名但不支持 ECH');
    process.exit(1);
  }
  log('ECH: 支持');
  let bestIP = null;
  let bestElapsed = Infinity;
  for (const ip of record.ipv4hint) {
    const r = await testTLS(ip, SCAN_TIMEOUT);
    if (r.success && r.elapsed < bestElapsed) {
      bestElapsed = r.elapsed;
      bestIP = ip;
    }
  }
  if (!bestIP) {
    log('结果: 支持 ECH 但 TLS 握手全部超时');
    process.exit(1);
  }
  log(`TLS 握手: ${bestElapsed}ms (${bestIP})`);
  log('');
  log(`✓ ${domain} 是支持 ECH 的指向 CF CDN 节点的域名`);
  console.log(`${domain}  ${bestElapsed}ms`);
}

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
    console.log(`cf-ech - 发现支持 ECH 的指向 Cloudflare CDN 的域名

用法:
  cf-ech              扫描并输出前 20 个支持 ECH 的优选域名
  cf-ech -all         输出所有支持 ECH 的域名
  cf-ech -json        以 JSON 格式输出
  cf-ech -c <domain>  检测指定域名是否为支持 ECH 的 CF 域名
  cf-ech --help       显示帮助信息`);
    return;
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

  const g = '\x1b[32m';  // green
  const w = '\x1b[37m';  // white
  const y = '\x1b[33m';  // yellow
  const d = '\x1b[90m';  // dim/gray
  const r = '\x1b[0m';   // reset
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
  log('正在扫描出 支持 ECH 的 CF 域名列表...');
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

  // 2. Query HTTPS records
  log('查询 HTTPS 记录...');
  const domainHTTPS = {};
  let checked = 0;
  const httpsTasks = domains.map(domain => async () => {
    const record = await fetchHTTPSRecord(domain);
    checked++;
    if (checked % 50 === 0 || checked === domains.length) {
      log(`  进度: ${checked}/${domains.length}`);
    }
    if (record) domainHTTPS[domain] = record;
  });
  await runWithPool(httpsTasks, CONCURRENCY);
  log(`有 HTTPS 记录: ${Object.keys(domainHTTPS).length} 个`);

  // 3. Build IP → domain map and test TLS
  const ipDomains = {};
  for (const [domain, record] of Object.entries(domainHTTPS)) {
    for (const ip of record.ipv4hint) {
      if (!ipDomains[ip]) ipDomains[ip] = [];
      ipDomains[ip].push(domain);
    }
  }
  const uniqueIPs = Object.keys(ipDomains);
  log(`测试 ${uniqueIPs.length} 个 IP 的 TLS 握手...`);

  const ipResult = {};
  let tested = 0;
  const testTasks = uniqueIPs.map(ip => async () => {
    const result = await testTLS(ip, SCAN_TIMEOUT);
    tested++;
    if (tested % 20 === 0 || tested === uniqueIPs.length) {
      log(`  进度: ${tested}/${uniqueIPs.length}`);
    }
    ipResult[ip] = result;
  });
  await runWithPool(testTasks, CONCURRENCY);

  // 4. Filter ECH domains and find best IP per domain
  const results = [];
  for (const [domain, record] of Object.entries(domainHTTPS)) {
    if (!record.ech) continue;
    let bestElapsed = Infinity;
    for (const ip of record.ipv4hint) {
      const r = ipResult[ip];
      if (r && r.success && r.elapsed < bestElapsed) {
        bestElapsed = r.elapsed;
      }
    }
    if (bestElapsed < Infinity) {
      results.push({ domain, elapsed: bestElapsed });
    }
  }
  results.sort((a, b) => a.elapsed - b.elapsed);

  // 5. Output
  const outputList = allMode ? results : results.slice(0, 20);

  if (jsonMode) {
    console.log(JSON.stringify(outputList, null, 2));
  } else {
    for (const r of outputList) {
      console.log(`${r.domain}  ${r.elapsed}ms`);
    }
  }

  // 6. Report (stderr)
  log('');
  log(`扫描域名: ${domains.length} | 支持 ECH: ${results.length} | 优选结果: ${outputList.length}`);
}

main().catch(e => {
  process.stderr.write(`致命错误: ${e.message}\n`);
  process.exit(1);
});
