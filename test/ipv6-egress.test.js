const test = require('node:test');
const assert = require('node:assert/strict');

const {
  AppError,
  IPV6_EGRESS_FALLBACK_TARGETS,
  assertIPv6Egress,
  checkIPv6Egress,
  ipInCIDRv6,
  resolveIPv6EgressTargets,
} = require('../bin/cf-ech.js');

function fakeSink() {
  const lines = [];
  return { lines, info: (msg) => lines.push(msg), data: () => {}, color: false };
}

test('checkIPv6Egress 任一目标连通即判定有出口', async () => {
  const ok = await checkIPv6Egress({
    targets: ['2606:4700::1', '2606:4700::2'],
    probe: async (ip) => ip === '2606:4700::2',
  });
  assert.equal(ok, true);
});

test('checkIPv6Egress 全部目标不通则判定无出口', async () => {
  const ok = await checkIPv6Egress({
    targets: ['2606:4700::1', '2606:4700::2'],
    probe: async () => false,
  });
  assert.equal(ok, false);
});

test('checkIPv6Egress 并发探测所有目标，并透传端口与超时', async () => {
  const calls = [];
  await checkIPv6Egress({
    targets: ['a::1', 'b::2'],
    port: 443,
    timeoutMs: 1234,
    probe: async (ip, port, timeoutMs) => { calls.push([ip, port, timeoutMs]); return false; },
  });
  assert.deepEqual(calls, [['a::1', 443, 1234], ['b::2', 443, 1234]]);
});

test('resolveIPv6EgressTargets 用域名实际解析出的 AAAA 作为探测目标', async () => {
  const calls = [];
  const targets = await resolveIPv6EgressTargets({
    domain: 'cloudflare-ech.com',
    resolve: async (domain, ipVersion) => {
      calls.push([domain, ipVersion]);
      return ['2606:4700::6812:a76', '2606:4700::6812:b76'];
    },
  });
  assert.deepEqual(calls, [['cloudflare-ech.com', 6]]);
  assert.deepEqual(targets, ['2606:4700::6812:a76', '2606:4700::6812:b76']);
});

test('resolveIPv6EgressTargets 解析不到 AAAA 时退回内置目标', async () => {
  const targets = await resolveIPv6EgressTargets({ resolve: async () => [] });
  assert.deepEqual(targets, IPV6_EGRESS_FALLBACK_TARGETS);
});

test('内置退回目标必须是 CF 网站边缘段，不能是 CF DNS 服务段', () => {
  // 回归：曾硬编码 2606:4700:4700::1111 / ::1001（Cloudflare DNS 服务段）。
  // 实测该段 :53 和 :853 可达但 :443 不通，而工具真正要连的是 2606:4700::/32
  // 的网站边缘地址（:443 可达），于是 v6 明明通却报「本机没有 IPv6 出口」。
  assert.ok(IPV6_EGRESS_FALLBACK_TARGETS.length >= 2);
  for (const target of IPV6_EGRESS_FALLBACK_TARGETS) {
    assert.equal(ipInCIDRv6(target, '2606:4700::/32'), true, `${target} 应属 CF 网站边缘段`);
    assert.equal(ipInCIDRv6(target, '2606:4700:4700::/48'), false, `${target} 不应落在 CF DNS 服务段`);
  }
});

test('assertIPv6Egress 在 IPv4 模式下不探测、不输出', async () => {
  const sink = fakeSink();
  let probed = false;
  await assertIPv6Egress(4, sink, {
    resolveTargets: async () => { probed = true; return []; },
    check: async () => false,
  });
  assert.equal(probed, false);
  assert.deepEqual(sink.lines, []);
});

test('assertIPv6Egress 出口正常时放行并报告一行', async () => {
  const sink = fakeSink();
  await assertIPv6Egress(6, sink, {
    resolveTargets: async () => ['2606:4700::6812:a76'],
    check: async () => true,
  });
  assert.equal(sink.lines.length, 2);
  assert.match(sink.lines[0], /IPv6 出口/);
  assert.match(sink.lines[1], /正常/);
});

test('assertIPv6Egress 探测的是解析出来的目标，不是写死的地址', async () => {
  const seen = [];
  await assertIPv6Egress(6, fakeSink(), {
    resolveTargets: async () => ['2606:4700::aaaa', '2606:4700::bbbb'],
    check: async (opts) => { seen.push(...opts.targets); return true; },
  });
  assert.deepEqual(seen, ['2606:4700::aaaa', '2606:4700::bbbb']);
});

test('assertIPv6Egress 出口不通时抛 AppError 并列出实际探测过的目标', async () => {
  const sink = fakeSink();
  await assert.rejects(
    () => assertIPv6Egress(6, sink, {
      resolveTargets: async () => ['2606:4700::aaaa'],
      check: async () => false,
    }),
    (err) => {
      assert.ok(err instanceof AppError, '应当是 AppError（CLI exit 1 / HTTP 400）');
      assert.match(err.message, /IPv6 出口/);
      assert.match(err.message, /2606:4700::aaaa/, '要报告实际探测的目标');
      assert.match(err.message, /直连/, '要点明测速是直连的，不走代理');
      assert.match(err.message, /-6/, '要给出可执行的下一步');
      return true;
    },
  );
});
