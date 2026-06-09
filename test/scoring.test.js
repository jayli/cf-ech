const test = require('node:test');
const assert = require('node:assert/strict');

const { buildDomainScore } = require('../bin/cf-ech.js');

test('penalizes domains with high latency spread across successful IPs', () => {
  const stable = buildDomainScore('stable.example', ['104.1.1.1', '104.1.1.2'], {
    '104.1.1.1': { success: true, successCount: 2, elapsed: 82 },
    '104.1.1.2': { success: true, successCount: 2, elapsed: 88 },
  });
  const uneven = buildDomainScore('uneven.example', ['104.2.2.1', '104.2.2.2'], {
    '104.2.2.1': { success: true, successCount: 2, elapsed: 70 },
    '104.2.2.2': { success: true, successCount: 2, elapsed: 240 },
  });

  assert.ok(stable.score > uneven.score);
  assert.equal(stable.spread, 6);
  assert.equal(uneven.spread, 170);
});

test('starts penalizing IP count only after three IPs', () => {
  const threeIPs = buildDomainScore('three.example', ['104.3.3.1', '104.3.3.2', '104.3.3.3'], {
    '104.3.3.1': { success: true, successCount: 2, elapsed: 100 },
    '104.3.3.2': { success: true, successCount: 2, elapsed: 100 },
    '104.3.3.3': { success: true, successCount: 2, elapsed: 100 },
  });
  const fourIPs = buildDomainScore('four.example', ['104.4.4.1', '104.4.4.2', '104.4.4.3', '104.4.4.4'], {
    '104.4.4.1': { success: true, successCount: 2, elapsed: 100 },
    '104.4.4.2': { success: true, successCount: 2, elapsed: 100 },
    '104.4.4.3': { success: true, successCount: 2, elapsed: 100 },
    '104.4.4.4': { success: true, successCount: 2, elapsed: 100 },
  });

  assert.equal(threeIPs.ipPenalty, 0);
  assert.ok(fourIPs.ipPenalty > 0);
  assert.ok(threeIPs.score > fourIPs.score);
});

