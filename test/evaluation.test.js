const test = require('node:test');
const assert = require('node:assert/strict');

const { evaluateCheckDomain, evaluateTestDomain } = require('../bin/cf-ech.js');

test('-c requires at least two CF IPs for preferred ECH evaluation', () => {
  const message = evaluateCheckDomain({
    cfIPCount: 1,
    overallRate: 100,
    avgLatency: 100,
    maxJitter: 10,
  });

  assert.equal(message, '评价: 可用 ECH（达不到优选）');
});

test('-t reports usable ECH when ECH is healthy but has fewer than two CF IPs', () => {
  const message = evaluateTestDomain({
    cfIPCount: 1,
    echRate: 100,
    echAvgLatency: 100,
    echMaxJitter: 10,
    tlsRate: 100,
    tlsAvgLatency: 100,
    tlsMaxJitter: 10,
  });

  assert.equal(message, '评价: 可用 ECH（达不到优选）');
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
