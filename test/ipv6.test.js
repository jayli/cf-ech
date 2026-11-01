const test = require('node:test');
const assert = require('node:assert/strict');

const { formatIPv6, ipInCIDRv6 } = require('../bin/cf-ech.js');

function bytes(hex) {
  return Buffer.from(hex, 'hex');
}

test('formatIPv6 renders the RFC 5952 canonical text form', () => {
  assert.equal(formatIPv6(bytes('26064700000000000000000000000001')), '2606:4700::1');
  assert.equal(formatIPv6(bytes('20010db8000000000000000000000001')), '2001:db8::1');
  assert.equal(formatIPv6(bytes('00000000000000000000000000000001')), '::1');
  assert.equal(formatIPv6(bytes('00000000000000000000000000000000')), '::');
  assert.equal(formatIPv6(bytes('fe800000000000000000000000000001')), 'fe80::1');
});

test('formatIPv6 compresses a zero run even when it is not the first group', () => {
  assert.equal(
    formatIPv6(bytes('2400cb00204900010000000000000abc')),
    '2400:cb00:2049:1::abc',
  );
});

test('formatIPv6 compresses the longest zero run, not an earlier shorter one', () => {
  // 组: 0000 aaaa 0000 0000 bbbb 0000 0000 0000 —— 最长的是尾部三组
  assert.equal(
    formatIPv6(bytes('0000aaaa00000000bbbb000000000000')),
    '0:aaaa:0:0:bbbb::',
  );
});

test('formatIPv6 does not compress a single zero group', () => {
  // RFC 5952 4.2.2：:: 不得只用来缩短一组 0
  assert.equal(formatIPv6(bytes('20010db8000000010002000300000001')), '2001:db8:0:1:2:3:0:1');
});

test('formatIPv6 rejects rdata that is not 16 bytes', () => {
  assert.equal(formatIPv6(bytes('26064700')), null);
  assert.equal(formatIPv6(null), null);
});

test('ipInCIDRv6 matches inside and outside the Cloudflare prefixes', () => {
  assert.equal(ipInCIDRv6('2606:4700::1', '2606:4700::/32'), true);
  assert.equal(ipInCIDRv6('2606:4700:ffff:ffff:ffff:ffff:ffff:ffff', '2606:4700::/32'), true);
  assert.equal(ipInCIDRv6('2400:cb00::1', '2606:4700::/32'), false);
  assert.equal(ipInCIDRv6('2a06:98c1::1', '2a06:98c0::/29'), true);
  assert.equal(ipInCIDRv6('2a06:98c8::1', '2a06:98c0::/29'), false);
});

test('ipInCIDRv6 handles expanded and compressed spellings of the same address', () => {
  assert.equal(
    ipInCIDRv6('2606:4700:0000:0000:0000:0000:0000:0001', '2606:4700::/32'),
    true,
  );
});

test('ipInCIDRv6 handles /128 and /0 edge prefixes', () => {
  assert.equal(ipInCIDRv6('2606:4700::1', '2606:4700::1/128'), true);
  assert.equal(ipInCIDRv6('2606:4700::2', '2606:4700::1/128'), false);
  assert.equal(ipInCIDRv6('2606:4700::1', '::/0'), true);
});
