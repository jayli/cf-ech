// 系统代理探测 + 零依赖的 HTTP CONNECT 隧道 Agent。
//
// 为什么需要这一层：Node 的 https 是 libuv 自己拨号，既不读 macOS 系统代理表
// （那是 CFNetwork 的配置），也不读 HTTPS_PROXY（要 --use-env-proxy 才认）。
// 结果是 curl 能通、这个工具却直连被挡。这里补上那一步。
//
// 只作用于控制面请求（域名列表、CF 网段、DoH）。测速握手必须直连：
// 走代理量到的是代理的延迟，不是这条 CF 线路的真实延迟。

const http = require('http');
const https = require('https');
const tls = require('tls');
const { execFileSync } = require('child_process');

const SCUTIL_TIMEOUT = 2000;
const PROXY_CONNECT_TIMEOUT = 10000;

// 解析 `scutil --proxy` 的文本输出。格式是嵌套的字典，例如：
//   <dictionary> {
//     ExceptionsList : <array> { 0 : *.local }
//     HTTPEnable : 1
//     HTTPPort : 1087
//     HTTPProxy : 127.0.0.1
//     HTTPSEnable : 1
//     ...
//   }
// 返回 { https, http, socks, exceptions }，没启用的项为 null。
function parseScutilProxy(text) {
  const scalars = new Map();
  const exceptions = [];

  let inExceptions = false;
  let depth = 0;

  for (const rawLine of String(text).split('\n')) {
    const line = rawLine.trim();

    if (inExceptions) {
      if (line.startsWith('}')) { inExceptions = false; continue; }
      // 例外项形如 `0 : *.local`
      const ex = /^\d+\s*:\s*(.+)$/.exec(line);
      if (ex) exceptions.push(ex[1].trim());
      continue;
    }

    if (/^ExceptionsList\s*:\s*<array>\s*\{$/.test(line)) {
      inExceptions = true;
      continue;
    }

    // 只收顶层 key : value（嵌套字典里的不关心，深度不为 0 时跳过）
    if (line === '<dictionary> {') { depth++; continue; }
    if (line === '}') { depth = Math.max(0, depth - 1); continue; }
    if (depth !== 1) continue;

    const m = /^([A-Za-z]+)\s*:\s*(.*)$/.exec(line);
    if (m) scalars.set(m[1], m[2].trim());
  }

  const enabled = (name) => scalars.get(`${name}Enable`) === '1';
  const build = (name) => {
    if (!enabled(name)) return null;
    const host = scalars.get(`${name}Proxy`);
    const port = Number(scalars.get(`${name}Port`));
    if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) return null;
    return { host, port };
  };

  return {
    https: build('HTTPS'),
    http: build('HTTP'),
    socks: build('SOCKS'),
    exceptions,
  };
}

// 挑一个能用的代理：HTTPS 优先（CONNECT 隧道对两者等价，但优先尊重用户的 https 设置），
// 其次 HTTP，最后才看 SOCKS（本文件只实现 CONNECT，SOCKS 由调用方当作不可用）。
function pickProxy(parsed) {
  if (!parsed) return null;
  for (const kind of ['https', 'http']) {
    const entry = parsed[kind];
    if (entry) {
      return { kind, url: `http://${entry.host}:${entry.port}` };
    }
  }
  return null;
}

// 探测系统代理。目前只实现 macOS（scutil）。返回
//   { proxy: { kind, url } | null, socksOnly: bool, exceptions: [...] }
// 缓存一次结果：-server 模式并发请求时不必反复 shell out。
let cachedDetection = null;

function detectSystemProxy({ platform = process.platform, exec = execFileSync } = {}) {
  if (cachedDetection) return cachedDetection;

  let detection = { proxy: null, socksOnly: false, exceptions: [] };

  if (platform === 'darwin') {
    try {
      const out = exec('scutil', ['--proxy'], {
        encoding: 'utf8',
        timeout: SCUTIL_TIMEOUT,
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      const parsed = parseScutilProxy(out);
      detection.exceptions = parsed.exceptions;
      detection.proxy = pickProxy(parsed);
      detection.socksOnly = !detection.proxy && Boolean(parsed.socks);
    } catch {
      // scutil 不在、超时、被沙箱挡住 —— 都当作「没有系统代理」，直连。
    }
  }

  cachedDetection = detection;
  return detection;
}

function resetProxyDetectionCache() {
  cachedDetection = null;
}

// 把 "127.0.0.1:1087" 这类例外项匹配到目标主机。系统表里的例外项除了 IP 还有网段
// （192.168.0.0/16 之类），这里只处理精确主机名/localhost 和 IPv4 网段，够用且不误伤。
function ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map(Number);
  if (nums.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((nums[0] << 24) + (nums[1] << 16) + (nums[2] << 8) + nums[3]) >>> 0;
}

function matchesException(host, exceptions) {
  if (!host) return false;
  const target = host.toLowerCase();
  const targetInt = ipv4ToInt(target);

  return exceptions.some((rule) => {
    const r = rule.toLowerCase();
    if (r === target) return true;
    if (r.startsWith('*.') && target.endsWith(r.slice(1))) return true;
    if (r === 'localhost' && (target === '127.0.0.1' || target === '::1')) return true;

    const cidr = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(r);
    if (cidr && targetInt !== null) {
      const baseInt = ipv4ToInt(cidr[1]);
      const bits = Number(cidr[2]);
      if (baseInt === null || bits < 0 || bits > 32) return false;
      const mask = bits === 0 ? 0 : (~((1 << (32 - bits)) - 1)) >>> 0;
      return (targetInt & mask) === (baseInt & mask);
    }
    return false;
  });
}

// https.Agent 的子类：先向代理发 CONNECT 建隧道，再在隧道上做 TLS。
// 这是「零依赖走 HTTP 代理」的全部实现，不需要 undici / ProxyAgent。
//
// 并发自己限：把 CONNECT 放在 createConnection 里做，就绕过了 Node 的 maxSockets 排队
// （实测 maxSockets 设 8、24 并发时仍然同时开 24 条 CONNECT，本地代理直接反 503）。
// 所以这里自带一个信号量，限制的是「同时在建的 CONNECT 握手」：
// 握手一旦完成就还名额，隧道本身交给 Agent 复用（名额跟着 socket 生命周期走会死锁。
// 空 socket 不关，名额永不归还，后面的请求全部饿死）。
class ConnectProxyAgent extends https.Agent {
  constructor(proxyUrl, options = {}) {
    const { maxConnections = 6, ...agentOptions } = options;
    super({ keepAlive: true, ...agentOptions });
    const u = new URL(proxyUrl);
    this.proxy = {
      protocol: u.protocol,
      hostname: u.hostname,
      port: Number(u.port || (u.protocol === 'https:' ? 443 : 80)),
    };
    this.maxConnections = maxConnections;
    this.inflight = 0;
    this.waiting = [];
  }

  // 拿到一个名额才能开工。名额只约束握手的瞬时并发，隧道建立（或失败）就归还。
  acquire() {
    return new Promise((resolve) => {
      const grant = () => { this.inflight++; resolve(() => this.release()); };
      if (this.inflight < this.maxConnections) grant();
      else this.waiting.push(grant);
    });
  }

  release() {
    this.inflight = Math.max(0, this.inflight - 1);
    const next = this.waiting.shift();
    if (next) next();
  }

  createConnection(options, callback) {
    const { hostname, port, protocol } = this.proxy;
    const target = `${options.host}:${options.port}`;

    this.acquire().then((release) => {
      let released = false;
      const done = () => {
        if (released) return;
        released = true;
        release();
      };

      // 代理本身可能是 https（少见），按协议选模块。
      const transport = protocol === 'https:' ? https : http;
      const connectOpts = {
        hostname,
        port,
        method: 'CONNECT',
        path: target,
        headers: { host: target },
        timeout: PROXY_CONNECT_TIMEOUT,
      };
      if (protocol === 'https:') connectOpts.agent = false;

      const req = transport.request(connectOpts);

      req.once('connect', (res, socket) => {
        if (res.statusCode !== 200) {
          socket.destroy();
          done();
          callback(new Error(`代理返回 CONNECT ${res.statusCode}`));
          return;
        }
        socket.setTimeout(0);
        const secured = tls.connect(
          { socket, servername: options.servername || options.host },
          () => { done(); callback(null, secured); },
        );
        secured.once('error', (err) => { done(); callback(err); });
      });

      req.once('timeout', () => req.destroy(new Error('代理连接超时')));
      req.once('error', (err) => { done(); callback(err); });
      req.end();
    });
  }
}

// 全进程共享一个代理 Agent：每个请求新建一条 CONNECT 逗道会把本地代理打爆
// （实测 50 并发 DoH 时 Clash 返回约 20% 的 CONNECT 503）。keepAlive 让隧道复用，
// 并发上限由 ConnectProxyAgent 自己的信号量控制（控制面都是短请求，6 条足够）。
const agentCache = new Map();

function sharedAgent(proxyUrl) {
  if (!agentCache.has(proxyUrl)) {
    agentCache.set(proxyUrl, new ConnectProxyAgent(proxyUrl, {
      maxConnections: 6,
    }));
  }
  return agentCache.get(proxyUrl);
}

// 关掉所有池化隧道。测试必须调它：keep-alive 的 socket 会让进程不退出，
// `npm test` 就卡在那里。生产路径不需要（进程自己退）。
function closeSharedAgents() {
  for (const agent of agentCache.values()) agent.destroy();
  agentCache.clear();
}

// 给一个 URL 选出这次请求要用的代理，或 null（直连）。
// 例外列表命中时不走代理。
function agentForUrl(url, detection = detectSystemProxy()) {
  if (!detection || !detection.proxy) return null;
  const host = typeof url === 'string' ? new URL(url).hostname : url.hostname;
  if (matchesException(host, detection.exceptions)) return null;
  return sharedAgent(detection.proxy.url);
}

module.exports = {
  ConnectProxyAgent,
  agentForUrl,
  closeSharedAgents,
  detectSystemProxy,
  matchesException,
  parseScutilProxy,
  pickProxy,
  resetProxyDetectionCache,
  sharedAgent,
};
