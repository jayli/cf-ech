#!/usr/bin/env node

const tls = require('tls');
const https = require('https');
const crypto = require('crypto');
const { readFileSync } = require('fs');
const path = require('path');

const DOMAIN_FILE = path.join(__dirname, '..', 'data', 'domains.txt');
const CF_TOP20_API = 'https://vps789.com/openApi/cfIpTop20';
const ECH_TEST_DOMAIN = 'c.consolelog.work';
const DOH_SERVER = 'https://dns.alidns.com/dns-query';
const CONCURRENCY = 50;
const SCAN_TIMEOUT = 5000;

function log(msg) { process.stderr.write(msg + '\n'); }

// ─── DNS wire-format encoding ───

function encodeDnsName(domain) {
  const parts = domain.split('.');
  const buffers = [];
  for (const label of parts) {
    buffers.push(Buffer.from([label.length]));
    buffers.push(Buffer.from(label, 'ascii'));
  }
  buffers.push(Buffer.from([0x00]));
  return Buffer.concat(buffers);
}

function buildDnsQuery(domain, type) {
  const id = crypto.randomBytes(2);
  const flags = Buffer.from([0x01, 0x00]);
  const header = Buffer.concat([
    id, flags,
    Buffer.from([0x00, 0x01]),
    Buffer.from([0x00, 0x00]),
    Buffer.from([0x00, 0x00]),
    Buffer.from([0x00, 0x00]),
  ]);
  const qname = encodeDnsName(domain);
  const qtype = Buffer.from([type >> 8, type & 0xff]);
  const qclass = Buffer.from([0x00, 0x01]);
  return Buffer.concat([header, qname, qtype, qclass]);
}

function decodeDnsName(buf, offset) {
  let name = '';
  let jumped = false;
  let originalOffset = offset;
  while (true) {
    const len = buf[offset];
    if (len === 0) { offset++; break; }
    if ((len & 0xc0) === 0xc0) {
      if (!jumped) originalOffset = offset + 2;
      offset = ((len & 0x3f) << 8) | buf[offset + 1];
      jumped = true;
      continue;
    }
    offset++;
    name += buf.toString('ascii', offset, offset + len) + '.';
    offset += len;
  }
  return { name: name.slice(0, -1) || '.', nextOffset: jumped ? originalOffset : offset };
}

function parseDnsResponse(buf) {
  const ancount = buf.readUInt16BE(6);
  let offset = 12;
  const qdcount = buf.readUInt16BE(4);
  for (let i = 0; i < qdcount; i++) {
    const { nextOffset } = decodeDnsName(buf, offset);
    offset = nextOffset + 4;
  }
  const answers = [];
  for (let i = 0; i < ancount; i++) {
    const { name, nextOffset } = decodeDnsName(buf, offset);
    offset = nextOffset;
    const type = buf.readUInt16BE(offset); offset += 2;
    offset += 2; // class
    offset += 4; // ttl
    const rdlen = buf.readUInt16BE(offset); offset += 2;
    const rdata = buf.slice(offset, offset + rdlen);
    offset += rdlen;
    answers.push({ name, type, rdata });
  }
  return answers;
}

function parseHTTPSRecord(rdata) {
  let offset = 0;
  const priority = rdata.readUInt16BE(offset); offset += 2;
  const { nextOffset } = decodeDnsName(rdata, offset);
  offset = nextOffset;
  const svcParams = {};
  while (offset < rdata.length) {
    const key = rdata.readUInt16BE(offset); offset += 2;
    const len = rdata.readUInt16BE(offset); offset += 2;
    const value = rdata.slice(offset, offset + len);
    offset += len;
    svcParams[key] = value;
  }
  return { priority, svcParams };
}

function queryDoH(domain, type = 65) {
  return new Promise((resolve, reject) => {
    const query = buildDnsQuery(domain, type);
    const url = new URL(DOH_SERVER);
    const options = {
      hostname: url.hostname,
      port: 443,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message',
        'Content-Length': query.length,
      },
      timeout: 10000,
    };
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try { resolve(parseDnsResponse(Buffer.concat(chunks))); }
        catch (e) { reject(e); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('DoH timeout')); });
    req.on('error', reject);
    req.write(query);
    req.end();
  });
}
