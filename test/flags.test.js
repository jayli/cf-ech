const test = require('node:test');
const assert = require('node:assert/strict');

const { parseFlags } = require('../bin/cf-ech.js');

test('defaults every flag to off when no arguments are given', () => {
  assert.deepEqual(parseFlags([]), {
    version: false,
    help: false,
    jsonMode: false,
    allMode: false,
    noECH: false,
    ipVersion: 4,
    ipVersionConflict: false,
    serverPort: null,
    host: null,
    mode: null,
    domain: null,
  });
});

test('defaults to IPv4 and accepts -4 as an explicit restatement', () => {
  assert.equal(parseFlags([]).ipVersion, 4);
  assert.equal(parseFlags(['-4']).ipVersion, 4);
  assert.equal(parseFlags(['--ipv4']).ipVersion, 4);
  assert.equal(parseFlags(['-4']).ipVersionConflict, false);
});

test('selects IPv6 scanning with -6', () => {
  assert.equal(parseFlags(['-6']).ipVersion, 6);
  assert.equal(parseFlags(['--ipv6']).ipVersion, 6);
  assert.equal(parseFlags(['-6', '-all', '-json']).ipVersion, 6);
});

test('reports -4 and -6 given together as a conflict', () => {
  assert.equal(parseFlags(['-4', '-6']).ipVersionConflict, true);
});

test('enables no-ECH scanning for both flag spellings', () => {
  assert.equal(parseFlags(['-no-ech']).noECH, true);
  assert.equal(parseFlags(['--no-ech']).noECH, true);
});

test('leaves no-ECH off for the ECH default scan', () => {
  assert.equal(parseFlags(['-all']).noECH, false);
  assert.equal(parseFlags(['-json']).noECH, false);
});

test('parses combined flags independently', () => {
  const flags = parseFlags(['-no-ech', '-all', '-json']);

  assert.equal(flags.noECH, true);
  assert.equal(flags.allMode, true);
  assert.equal(flags.jsonMode, true);
  assert.equal(flags.help, false);
});

test('defaults the server port to 4837 when -server carries no value', () => {
  assert.equal(parseFlags(['-server']).serverPort, '4837');
  assert.equal(parseFlags(['-server', '-all']).serverPort, '4837');
});

test('reads an explicit server port and host', () => {
  const flags = parseFlags(['-server', '8080', '-host', '127.0.0.1']);

  assert.equal(flags.serverPort, '8080');
  assert.equal(flags.host, '127.0.0.1');
});

test('parses -c and -t into mode plus domain', () => {
  assert.equal(parseFlags(['-c', 'example.com']).mode, 'check');
  assert.equal(parseFlags(['-c', 'example.com']).domain, 'example.com');
  assert.equal(parseFlags(['-t', 'example.com']).mode, 'test');
  assert.equal(parseFlags(['-t', 'example.com']).domain, 'example.com');
});

test('reports a missing domain rather than inventing one', () => {
  assert.equal(parseFlags(['-c']).mode, 'check');
  assert.equal(parseFlags(['-c']).domain, null);
});
