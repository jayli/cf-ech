const test = require('node:test');
const assert = require('node:assert/strict');

const {
  AppError,
  IPV6_EGRESS_TARGETS,
  assertIPv6Egress,
  checkIPv6Egress,
} = require('../bin/cf-ech.js');

function fakeSink() {
  const lines = [];
  return { lines, info: (msg) => lines.push(msg), data: () => {}, color: false };
}

test('checkIPv6Egress 任一目标连通即判定有出口', async () => {
  const ok = await checkIPv6Egress({
    targets: ['2606:4700:4700::1111', '2606:4700:4700::1001'],
    probe: async (ip) => ip === '2606:4700:4700::1001',
  });
  assert.equal(ok, true);
});

test('checkIPv6Egress 全部目标不通则判定无出口', async () => {
  const ok = await checkIPv6Egress({
    targets: ['2606:4700:4700::1111', '2606:4700:4700::1001'],
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

test('默认探测目标是 Cloudflare 的 IPv6 地址', () => {
  assert.ok(IPV6_EGRESS_TARGETS.length >= 2);
  for (const target of IPV6_EGRESS_TARGETS) {
    assert.ok(target.includes(':'), `${target} 不是 IPv6 字面量`);
    assert.match(target, /^2606:4700:/, `${target} 不属于 Cloudflare 的 2606:4700::/32`);
  }
});

test('assertIPv6Egress 在 IPv4 模式下不探测、不输出', async () => {
  const sink = fakeSink();
  let probed = false;
  await assertIPv6Egress(4, sink, { check: async () => { probed = true; return false; } });
  assert.equal(probed, false);
  assert.deepEqual(sink.lines, []);
});

test('assertIPv6Egress 出口正常时放行并报告一行', async () => {
  const sink = fakeSink();
  await assertIPv6Egress(6, sink, { check: async () => true });
  assert.equal(sink.lines.length, 2);
  assert.match(sink.lines[0], /IPv6 出口/);
  assert.match(sink.lines[1], /正常/);
});

test('assertIPv6Egress 出口不通时抛 AppError 并说明原因', async () => {
  const sink = fakeSink();
  await assert.rejects(
    () => assertIPv6Egress(6, sink, { check: async () => false }),
    (err) => {
      assert.ok(err instanceof AppError, '应当是 AppError（CLI exit 1 / HTTP 400）');
      assert.match(err.message, /IPv6 出口/);
      assert.match(err.message, /直连/, '要点明测速是直连的，不走代理');
      assert.match(err.message, /-6/, '要给出可执行的下一步');
      return true;
    },
  );
});
