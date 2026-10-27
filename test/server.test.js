const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');

const { createServer, createLock } = require('../bin/server.js');
const { parseQuery, AppError } = require('../bin/cf-ech.js');

// 起一个只监听 127.0.0.1 临时端口的服务，测试结束自动关掉。
async function withServer(run, fn) {
  const server = createServer({
    run,
    parseQuery,
    isAppError: (e) => e instanceof AppError,
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    await fn(port);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

// 收集完整响应，同时记录 chunk 的到达顺序与时机，用于验证"流式"不是一次性返回。
function get(port, path) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const req = http.get({ host: '127.0.0.1', port, path }, (res) => {
      res.setEncoding('utf8');
      res.on('data', c => chunks.push({ at: Date.now(), text: c }));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        chunks,
        body: chunks.map(c => c.text).join(''),
      }));
    });
    req.on('error', reject);
  });
}

test('parseQuery maps query keys onto the CLI flag shape', () => {
  const { flags } = parseQuery(new URLSearchParams('all=1&json=1&noech=1'));

  assert.equal(flags.allMode, true);
  assert.equal(flags.jsonMode, true);
  assert.equal(flags.noECH, true);
  assert.equal(flags.mode, null);
});

test('parseQuery treats 0 and false as off', () => {
  const { flags } = parseQuery(new URLSearchParams('all=0&json=false'));

  assert.equal(flags.allMode, false);
  assert.equal(flags.jsonMode, false);
});

test('parseQuery maps mode plus domain to check and test', () => {
  assert.deepEqual(
    parseQuery(new URLSearchParams('mode=check&domain=example.com')).flags.mode,
    'check',
  );
  assert.equal(
    parseQuery(new URLSearchParams('mode=test&domain=example.com')).flags.domain,
    'example.com',
  );
});

test('parseQuery rejects unknown keys instead of silently scanning', () => {
  assert.match(parseQuery(new URLSearchParams('al=1')).error, /未知参数: al/);
});

test('parseQuery rejects mode combined with batch switches', () => {
  assert.match(
    parseQuery(new URLSearchParams('mode=check&domain=a.com&all=1')).error,
    /不能同时使用/,
  );
});

test('parseQuery rejects an unknown mode and a domainless mode', () => {
  assert.match(parseQuery(new URLSearchParams('mode=foo&domain=a.com')).error, /mode 只能是/);
  assert.match(parseQuery(new URLSearchParams('mode=check')).error, /缺少 domain/);
  assert.match(parseQuery(new URLSearchParams('domain=a.com')).error, /需要配合 mode/);
});

test('GET / serves the usage page without running a scan', async () => {
  let ran = false;
  await withServer(async () => { ran = true; }, async (port) => {
    const res = await get(port, '/');

    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /text\/html/);
    assert.match(res.body, /cf-ech 服务/);
    assert.match(res.body, /mode=check/);
    assert.equal(ran, false);
  });
});

test('unknown paths return 404', async () => {
  await withServer(async () => {}, async (port) => {
    const res = await get(port, '/nope');

    assert.equal(res.status, 404);
    assert.match(res.body, /未知路径/);
  });
});

test('bad query parameters return 400 before any scan runs', async () => {
  let ran = false;
  await withServer(async () => { ran = true; }, async (port) => {
    const res = await get(port, '/?al=1');

    assert.equal(res.status, 400);
    assert.match(res.body, /未知参数: al/);
    assert.equal(ran, false);
  });
});

test('text mode streams each sink call as its own chunk', async () => {
  await withServer(async (flags, sink) => {
    sink.info('第一行');
    await new Promise(r => setTimeout(r, 60));
    sink.info('第二行');
    await new Promise(r => setTimeout(r, 60));
    sink.data('结果行');
  }, async (port) => {
    const res = await get(port, '/?all=1');

    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /text\/plain/);
    assert.equal(res.headers['content-length'], undefined, '流式响应不应带 Content-Length');
    assert.match(res.body, /第一行/);
    assert.match(res.body, /第二行/);
    assert.match(res.body, /结果行/);
    assert.match(res.body, /耗时/);

    const first = res.body.indexOf('第一行');
    const second = res.body.indexOf('第二行');
    assert.ok(first < second, '输出顺序应与执行顺序一致');

    // 分块到达：第二条消息的 chunk 一定晚于第一条
    assert.ok(res.chunks.length > 1, `应当分多个 chunk 到达，实际 ${res.chunks.length}`);
    const chunkTimes = res.chunks.map(c => c.at).filter((t, i, a) => i === 0 || t > a[0]);
    assert.ok(chunkTimes.length >= 1);
  });
});

test('json mode returns one valid JSON document and no progress text', async () => {
  await withServer(async (flags, sink) => {
    sink.info('这些进度文字不应该出现在 JSON 里');
    return { json: [{ domain: 'example.com', ip: '1.1.1.1', elapsed: 12 }] };
  }, async (port) => {
    const res = await get(port, '/?json=1');

    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /application\/json/);
    assert.doesNotMatch(res.body, /进度文字/);

    const parsed = JSON.parse(res.body);
    assert.equal(parsed.length, 1);
    assert.equal(parsed[0].domain, 'example.com');
  });
});

test('an AppError surfaces as 400 in JSON mode and as a stream line otherwise', async () => {
  const failing = async () => { throw new AppError('无 A 记录'); };

  await withServer(failing, async (port) => {
    const json = await get(port, '/?json=1');
    assert.equal(json.status, 400);
    assert.equal(JSON.parse(json.body).error, '无 A 记录');

    const text = await get(port, '/?all=1');
    assert.equal(text.status, 200);
    assert.match(text.body, /错误: 无 A 记录/);
  });
});

test('unexpected errors surface as 500 in JSON mode', async () => {
  await withServer(async () => { throw new Error('boom'); }, async (port) => {
    const res = await get(port, '/?json=1');

    assert.equal(res.status, 500);
    assert.equal(JSON.parse(res.body).error, 'boom');
  });
});

test('scans are serialized so concurrent requests cannot skew latency', async () => {
  let active = 0;
  let maxActive = 0;

  await withServer(async (flags, sink) => {
    active++;
    maxActive = Math.max(maxActive, active);
    await new Promise(r => setTimeout(r, 50));
    active--;
    sink.data(`done ${flags.allMode}`);
  }, async (port) => {
    await Promise.all([
      get(port, '/?all=1'),
      get(port, '/?all=1'),
      get(port, '/?all=1'),
    ]);

    assert.equal(maxActive, 1, '同一时刻只应有一个扫描在跑');
  });
});

test('lock hands out turns in FIFO order and tracks the queue', async () => {
  const lock = createLock();
  const order = [];

  await lock.acquire();
  const b = lock.acquire().then(() => order.push('b'));
  const c = lock.acquire().then(() => order.push('c'));

  assert.equal(lock.queueLength, 2);

  lock.release();
  await b;
  lock.release();
  await c;

  assert.deepEqual(order, ['b', 'c']);
});

test('non-GET requests are rejected with 405', async () => {
  await withServer(async () => {}, async (port) => {
    const status = await new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, path: '/?all=1', method: 'POST' }, (res) => {
        res.resume();
        resolve(res.statusCode);
      });
      req.on('error', reject);
      req.end();
    });

    assert.equal(status, 405);
  });
});

test('a client disconnect does not leave the lock held', async () => {
  let finished = false;
  await withServer(async (flags, sink) => {
    await new Promise(r => setTimeout(r, 80));
    sink.data('结果');
    finished = true;
  }, async (port) => {
    // 请求后立刻断开
    await new Promise((resolve) => {
      const req = http.get({ host: '127.0.0.1', port, path: '/?all=1' }, (res) => {
        res.once('data', () => { req.destroy(); resolve(); });
      });
      req.on('error', () => resolve());
    });

    // 扫描仍应跑完，且锁已释放：新请求能正常拿到执行权
    const after = await get(port, '/?all=1');
    assert.equal(after.status, 200);
    assert.equal(finished, true);
  });
});
