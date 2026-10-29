const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');

const {
  ConnectProxyAgent,
  agentForUrl,
  detectSystemProxy,
  matchesException,
  closeSharedAgents,
  parseScutilProxy,
  pickProxy,
  resetProxyDetectionCache,
} = require('../bin/proxy.js');

// 一份真实的 `scutil --proxy` 输出（macOS）。用它当夹具，
// 保证解析是对着真实格式写的，不是对着想象格式写的。
const REAL_SCUTIL = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254.0.0/16
    2 : 127.0.0.1
    3 : localhost
    4 : 0.0.0.0
    5 : ::1
    6 : fc00::/7
    7 : 192.168.0.0/16
    8 : 10.0.0.0/8
    9 : 172.16.0.0/12
  }
  ExcludeSimpleHostnames : 0
  HTTPEnable : 1
  HTTPPort : 1087
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 1088
  HTTPSProxy : 127.0.0.1
  ProxyAutoConfigEnable : 0
  SOCKSEnable : 1
  SOCKSPort : 1080
  SOCKSProxy : 127.0.0.1
}`;

test('parseScutilProxy reads host, port and the exceptions list', () => {
  const parsed = parseScutilProxy(REAL_SCUTIL);
  assert.deepEqual(parsed.https, { host: '127.0.0.1', port: 1088 });
  assert.deepEqual(parsed.http, { host: '127.0.0.1', port: 1087 });
  assert.deepEqual(parsed.socks, { host: '127.0.0.1', port: 1080 });
  assert.deepEqual(parsed.exceptions, [
    '*.local', '169.254.0.0/16', '127.0.0.1', 'localhost', '0.0.0.0',
    '::1', 'fc00::/7', '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12',
  ]);
});

test('parseScutilProxy treats disabled entries as absent', () => {
  const text = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
  }
  HTTPEnable : 0
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 0
  HTTPSPort : 7890
  HTTPSProxy : 127.0.0.1
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://example.com/proxy.pac
  SOCKSEnable : 0
  SOCKSPort : 1080
  SOCKSProxy : 127.0.0.1
}`;
  const parsed = parseScutilProxy(text);
  assert.equal(parsed.http, null);
  assert.equal(parsed.https, null);
  assert.equal(parsed.socks, null);
  assert.equal(pickProxy(parsed), null);
});

test('parseScutilProxy ignores ports with no host and accepts socks-only setups', () => {
  const noHost = parseScutilProxy('<dictionary> {\n  HTTPEnable : 1\n  HTTPPort : 7890\n}');
  assert.equal(noHost.http, null);

  const socksOnly = parseScutilProxy(
    '<dictionary> {\n  HTTPEnable : 0\n  SOCKSEnable : 1\n  SOCKSPort : 1080\n  SOCKSProxy : 127.0.0.1\n}',
  );
  assert.deepEqual(socksOnly.socks, { host: '127.0.0.1', port: 1080 });
  assert.equal(pickProxy(socksOnly), null);
});

test('parseScutilProxy survives empty or malformed input', () => {
  for (const input of ['', 'garbage', null, undefined]) {
    const parsed = parseScutilProxy(input);
    assert.equal(parsed.https, null);
    assert.equal(parsed.http, null);
    assert.deepEqual(parsed.exceptions, []);
  }
});

test('pickProxy prefers https, then http, and skips socks', () => {
  assert.deepEqual(
    pickProxy(parseScutilProxy(REAL_SCUTIL)),
    { kind: 'https', url: 'http://127.0.0.1:1088' },
  );

  const httpOnly = parseScutilProxy(
    '<dictionary> {\n  HTTPEnable : 1\n  HTTPPort : 7890\n  HTTPProxy : proxy.lan\n  HTTPSEnable : 0\n}',
  );
  assert.deepEqual(pickProxy(httpOnly), { kind: 'http', url: 'http://proxy.lan:7890' });
});

test('matchesException honours hostnames, wildcards and CIDRs', () => {
  const exceptions = ['*.local', '127.0.0.1', '192.168.0.0/16', '10.0.0.0/8', '169.254.0.0/16'];
  assert.equal(matchesException('printer.local', exceptions), true);
  assert.equal(matchesException('LOCALHOST', ['localhost']), true);
  assert.equal(matchesException('127.0.0.1', exceptions), true);
  assert.equal(matchesException('192.168.1.20', exceptions), true);
  assert.equal(matchesException('10.255.0.1', exceptions), true);
  assert.equal(matchesException('169.254.3.4', exceptions), true);
  assert.equal(matchesException('dns.alidns.com', exceptions), false);
  assert.equal(matchesException('11.0.0.1', exceptions), false);
  assert.equal(matchesException('192.169.0.1', exceptions), false);
});

test('agentForUrl returns null when nothing is configured or host is excepted', () => {
  assert.equal(agentForUrl('https://a.com', { proxy: null, exceptions: [] }), null);
  const detection = { proxy: { kind: 'https', url: 'http://127.0.0.1:1087' }, exceptions: ['127.0.0.1'] };
  assert.equal(agentForUrl('https://127.0.0.1/x', detection), null);
  assert.ok(agentForUrl('https://a.com', detection) instanceof ConnectProxyAgent);
});

test('agentForUrl shares one pooled agent per proxy url', () => {
  const detection = { proxy: { kind: 'https', url: 'http://127.0.0.1:65535' }, exceptions: [] };
  const a = agentForUrl('https://a.example.com', detection);
  const b = agentForUrl('https://b.example.com', detection);
  assert.equal(a, b, 'same proxy must reuse one agent so tunnels are pooled');
  assert.equal(a.keepAlive, true);
  // 不能依赖 https.Agent 的 maxSockets：CONNECT 在 createConnection 里做，绕过了它的排队，
  // 所以并发上限由自己的信号量（maxConnections）控制。
  assert.equal(a.maxConnections, 6);

  const other = agentForUrl('https://a.example.com', {
    proxy: { kind: 'http', url: 'http://127.0.0.1:65534' }, exceptions: [],
  });
  assert.notEqual(a, other, 'a different proxy must not share the pool');

  // 共享 agent 是 keep-alive 的，测试结束必须关掉，否则进程不退出。
  closeSharedAgents();
});

test('detectSystemProxy degrades to direct on non-darwin', () => {
  resetProxyDetectionCache();
  const detection = detectSystemProxy({ platform: 'linux', exec: () => { throw new Error('should not run'); } });
  assert.deepEqual(detection, { proxy: null, socksOnly: false, exceptions: [] });
});

test('detectSystemProxy degrades to direct when scutil fails', () => {
  resetProxyDetectionCache();
  const detection = detectSystemProxy({ platform: 'darwin', exec: () => { throw new Error('scutil gone'); } });
  assert.equal(detection.proxy, null);
  resetProxyDetectionCache();
});

test('detectSystemProxy parses scutil output and caches the result', () => {
  resetProxyDetectionCache();
  let calls = 0;
  const exec = () => { calls++; return REAL_SCUTIL; };
  const first = detectSystemProxy({ platform: 'darwin', exec });
  const second = detectSystemProxy({ platform: 'darwin', exec });
  assert.equal(calls, 1, 'scutil must only be shelled out once');
  assert.deepEqual(first.proxy, { kind: 'https', url: 'http://127.0.0.1:1088' });
  assert.equal(second, first);
  resetProxyDetectionCache();
});

// 起一个最小 CONNECT 代理，验证隧道是真的建立起来了（不需要用户的 1087）。
function startConnectProxy() {
  return new Promise((resolve) => {
    const seen = [];
    const proxy = http.createServer((req, res) => {
      res.writeHead(405).end();
    });
    proxy.on('connect', (req, clientSocket, head) => {
      seen.push(req.url);
      const [host, port] = req.url.split(':');
      const upstream = net.connect(Number(port), host, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head && head.length) upstream.write(head);
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);
      });
      const kill = () => { upstream.destroy(); clientSocket.destroy(); };
      upstream.on('error', kill);
      clientSocket.on('error', kill);
    });
    proxy.listen(0, '127.0.0.1', () => resolve({ proxy, seen, port: proxy.address().port }));
  });
}

test('ConnectProxyAgent tunnels TLS through a CONNECT proxy', async () => {
  const { proxy, seen, port } = await startConnectProxy();
  let agent;
  try {
    agent = new ConnectProxyAgent(`http://127.0.0.1:${port}`, { keepAlive: true });
    const body = await new Promise((resolve, reject) => {
      https.get('https://example.com/', { agent, timeout: 15000 }, (res) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
      }).on('error', reject).on('timeout', function () { this.destroy(new Error('timeout')); });
    });
    assert.equal(body.status, 200);
    assert.match(body.body, /example/i);
    assert.deepEqual(seen, ['example.com:443'], 'CONNECT must be issued against the real target');
  } finally {
    // 隧道是 keep-alive 的：不销毁 agent 里的池化 socket，测试进程不会退出。
    if (agent) agent.destroy();
    proxy.closeAllConnections();
    await new Promise(r => proxy.close(r));
  }
});

test('ConnectProxyAgent surfaces a rejected CONNECT instead of hanging', async () => {
  const proxy = http.createServer();
  proxy.on('connect', (req, clientSocket) => {
    clientSocket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
  });
  await new Promise(r => proxy.listen(0, '127.0.0.1', r));
  try {
    const agent = new ConnectProxyAgent(`http://127.0.0.1:${proxy.address().port}`);
    const err = await new Promise((resolve) => {
      https.get('https://example.com/', { agent, timeout: 5000 }, () => resolve(null))
        .on('error', resolve);
    });
    assert.ok(err, 'request must fail');
    assert.match(err.message, /CONNECT 403/);
  } finally {
    proxy.closeAllConnections();
    await new Promise(r => proxy.close(r));
  }
});
