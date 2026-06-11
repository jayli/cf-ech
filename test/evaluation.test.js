const test = require('node:test');
const assert = require('node:assert/strict');

const { evaluateCheckDomain, evaluateTestDomain } = require('../bin/cf-ech.js');

test('-c single IP with excellent metrics is rated as quality single-IP ECH', () => {
  const message = evaluateCheckDomain({
    cfIPCount: 1,
    overallRate: 100,
    avgLatency: 100,
    maxJitter: 10,
  });

  assert.equal(message, '评价: 单 IP 优质 ECH 接入点（缺少冗余）');
});

test('-c single IP with poor metrics is rated as usable ECH, not quality', () => {
  const message = evaluateCheckDomain({
    cfIPCount: 1,
    overallRate: 100,
    avgLatency: 900,
    maxJitter: 10,
  });

  assert.equal(message, '评价: 可用 ECH（达不到优选）');
});

test('-t single IP with excellent ECH metrics is rated as quality single-IP ECH', () => {
  const message = evaluateTestDomain({
    cfIPCount: 1,
    echRate: 100,
    echAvgLatency: 100,
    echMaxJitter: 10,
    tlsRate: 100,
    tlsAvgLatency: 100,
    tlsMaxJitter: 10,
  });

  assert.equal(message, '评价: 单 IP 优质 ECH 接入点（缺少冗余）');
});

test('-t single IP with high ECH latency but 100% rate is rated as mediocre', () => {
  const message = evaluateTestDomain({
    cfIPCount: 1,
    echRate: 100,
    echAvgLatency: 900,
    echMaxJitter: 10,
    tlsRate: 50,
    tlsAvgLatency: 900,
    tlsMaxJitter: 10,
  });

  assert.equal(message, '评价: 连接质量一般，高峰期可能不稳定');
});

test('-t labels ordinary TLS fallback as a makeshift Cloudflare node', () => {
  const message = evaluateTestDomain({
    cfIPCount: 2,
    echRate: 80,
    echAvgLatency: 100,
    echMaxJitter: 10,
    tlsRate: 100,
    tlsAvgLatency: 100,
    tlsMaxJitter: 10,
  });

  assert.equal(message, '评价: 普通 CF 节点（凑合能用）');
});
