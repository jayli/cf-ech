const test = require('node:test');
const assert = require('node:assert/strict');

const {
  attachColos,
  coloCity,
  describeColo,
  loadColoCityMap,
  parseTraceColo,
} = require('../bin/cf-ech.js');

test('parseTraceColo reads the colo line out of a trace body', () => {
  const body = [
    'fl=1256f139',
    'h=absen.com',
    'ip=42.120.75.13',
    'colo=LAX',
    'loc=CN',
    'tls=TLSv1.3',
    '',
  ].join('\n');

  assert.equal(parseTraceColo(body), 'LAX');
});

test('parseTraceColo upper-cases and ignores lookalike lines', () => {
  assert.equal(parseTraceColo('colo=sin\n'), 'SIN');
  // 不能把 cdn_loop 之类的前缀误当 colo
  assert.equal(parseTraceColo('tls_colo=SIN\n'), null);
  assert.equal(parseTraceColo('my_colo=LAX\n'), null);
});

test('parseTraceColo returns null when the body carries no colo', () => {
  assert.equal(parseTraceColo('<!DOCTYPE html><html>404</html>'), null);
  assert.equal(parseTraceColo(''), null);
  assert.equal(parseTraceColo(undefined), null);
});

test('describeColo prefers the Chinese city name and falls back to the code', () => {
  assert.equal(describeColo('LAX'), 'LAX 洛杉矶');
  assert.equal(describeColo('SIN'), 'SIN 新加坡');
  // 未收录进中文表的三字码至少还能显示代号
  assert.equal(describeColo('QQQ'), 'QQQ');
  assert.equal(describeColo(null), '未知');
});

test('the bundled colo table covers the well-known Cloudflare data centers', () => {
  const map = loadColoCityMap();

  assert.equal(map.LAX, 'Los Angeles, United States');
  assert.equal(map.SIN, 'Singapore, Singapore');
  assert.equal(map.NRT, 'Tokyo, Japan');
  assert.ok(Object.keys(map).length > 300, `内置 colo 表条目过少: ${Object.keys(map).length}`);
  assert.equal(coloCity('LAX'), '洛杉矶');
  assert.equal(coloCity('NRT'), '东京');
  assert.equal(coloCity('QQQ'), null);
});

test('attachColos fills every row and probes each ip once', async () => {
  const calls = [];
  const items = [
    { ip: '104.1.1.1', domain: 'a.example' },
    { ip: '104.1.1.2', domain: 'a.example' },
    { ip: '104.1.1.1', domain: 'a.example' },
  ];

  await attachColos(items, {
    fetch: async (ip) => { calls.push(ip); return ip === '104.1.1.1' ? 'LAX' : 'SIN'; },
  });

  assert.deepEqual(items.map(i => i.colo), ['LAX', 'SIN', 'LAX']);
  assert.deepEqual(calls.sort(), ['104.1.1.1', '104.1.1.2']);
});

test('attachColos uses the shared domain for rows that only carry an ip', async () => {
  const seen = [];
  const items = [{ ip: '104.2.2.1' }, { ip: '104.2.2.2' }];

  await attachColos(items, {
    domain: 'only.example',
    fetch: async (ip, domain) => { seen.push([ip, domain]); return 'HKG'; },
  });

  assert.deepEqual(items.map(i => i.colo), ['HKG', 'HKG']);
  assert.deepEqual(seen.sort(), [['104.2.2.1', 'only.example'], ['104.2.2.2', 'only.example']]);
});

test('attachColos records null instead of failing when the probe cannot answer', async () => {
  const items = [{ ip: '104.3.3.1', domain: 'x.example' }, { domain: 'y.example' }];

  await attachColos(items, { fetch: async () => null });

  assert.deepEqual(items.map(i => i.colo), [null, null]);
});

test('attachColos records null when a domain is missing entirely', async () => {
  const items = [{ ip: '104.4.4.1' }];
  let probed = false;

  await attachColos(items, { fetch: async () => { probed = true; return 'LAX'; } });

  assert.equal(items[0].colo, null);
  assert.equal(probed, false);
});
