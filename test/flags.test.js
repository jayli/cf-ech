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
  });
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
