'use strict';

const http = require('http');

// 一次只跑一个扫描：并发会互相抢带宽，把延迟数字搞脏，而这工具的全部意义就是延迟。
function createLock() {
  let busy = false;
  const waiting = [];

  return {
    get queueLength() { return waiting.length; },
    async acquire() {
      if (!busy) {
        busy = true;
        return;
      }
      await new Promise(resolve => waiting.push(resolve));
    },
    release() {
      const next = waiting.shift();
      if (next) next();
      else busy = false;
    },
  };
}

function esc(text) {
  return String(text).replace(/[&<>"]/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]
  ));
}

function indexPage(port) {
  const samples = [
    ['/?json=1', '批量扫描，JSON 输出'],
    ['/?all=1', '批量扫描，输出所有通过域名'],
    ['/?noech=1', '跳过 ECH 探测，只按普通 TLS 优选'],
    ['/?all=1&noech=1', '普通 TLS 优选，输出全部结果'],
    ['/?mode=check&domain=example.com', '等价于 cf-ech -c example.com'],
    ['/?mode=test&domain=example.com', '等价于 cf-ech -t example.com'],
  ];
  const rows = samples
    .map(([href, desc]) => `<tr><td><a href="${esc(href)}">${esc(href)}</a></td><td>${esc(desc)}</td></tr>`)
    .join('\n      ');

  return `<!doctype html>
<html lang="zh-CN">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>cf-ech 服务${port ? ` :${esc(port)}` : ''}</title>
<style>
  body { font: 15px/1.6 -apple-system, "PingFang SC", system-ui, sans-serif; max-width: 46rem; margin: 2rem auto; padding: 0 1rem; color: #1f2328; }
  h1 { font-size: 1.4rem; margin-bottom: .25rem; }
  p.sub { color: #59636e; margin-top: 0; }
  code, td a { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9em; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
  td { padding: .4rem .6rem; border-bottom: 1px solid #e7eaee; vertical-align: top; }
  td:first-child { white-space: nowrap; }
  .note { background: #f6f8fa; border-left: 3px solid #d0d7de; padding: .6rem .9rem; color: #454c54; font-size: .9em; }
</style>
<h1>cf-ech 服务</h1>
<p class="sub">筛选实测支持 ECH 的 Cloudflare 优选域名，结果边跑边流式返回。</p>

<table>
      ${rows}
</table>

<p class="note">
同一时刻只跑一次扫描，后到的请求排队等待，避免并发互相干扰把延迟数字搞脏。<br>
扫描过程中先返回过程日志，最后是结果；<code>json=1</code> 例外，它在结束时一次性返回合法 JSON。<br>
服务默认监听 <code>0.0.0.0</code>，同网段的任何人都能触发扫描；只想本机访问请用 <code>cf-ech -server -host 127.0.0.1</code>。
</p>
</html>
`;
}

/**
 * parseQuery 与 isAppError 由调用方注入，避免和 cf-ech.js 形成循环 require
 * （cf-ech.js 的 module.exports 在 main() 之后才赋值，循环依赖会拿到空对象）。
 *
 * @param {object} options
 * @param {(flags: object, sink: object) => Promise<object|void>} options.run 执行函数
 * @param {(params: URLSearchParams) => ({flags?: object, error?: string})} options.parseQuery
 * @param {(e: Error) => boolean} [options.isAppError] 是否是可预期的业务失败
 * @param {(msg: string) => void} [options.log] 服务端日志，默认丢弃
 */
function createServer({ run, parseQuery, isAppError = () => false, log = () => {} }) {
  const lock = createLock();
  let served = 0;

  function send(res, status, contentType, body) {
    if (res.writableEnded) return;
    res.writeHead(status, {
      'Content-Type': contentType,
      'Content-Length': Buffer.byteLength(body),
      'Cache-Control': 'no-store',
    });
    res.end(body);
  }

  const sendText = (res, status, body) =>
    send(res, status, 'text/plain; charset=utf-8', body);
  const sendJSON = (res, status, value) =>
    send(res, status, 'application/json; charset=utf-8', JSON.stringify(value, null, 2) + '\n');

  function responseError(res, status, message) {
    if (res.headersSent) {
      if (!res.writableEnded) res.end(`\n错误: ${message}\n`);
      return;
    }
    sendText(res, status, status === 200 ? message : `参数错误: ${message}\n\nGET / 查看可用参数\n`);
  }

  async function handle(req, res) {
    const url = new URL(req.url, 'http://localhost');

    if (req.method !== 'GET') {
      res.writeHead(405, { Allow: 'GET', 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('只支持 GET\n');
      return;
    }

    if (url.pathname !== '/' && url.pathname !== '/index.html') {
      sendText(res, 404, `未知路径: ${url.pathname}\n可用: GET /\n`);
      return;
    }

    if (!url.searchParams.toString()) {
      const port = server.address() ? server.address().port : '';
      send(res, 200, 'text/html; charset=utf-8', indexPage(port));
      return;
    }

    const parsed = parseQuery(url.searchParams);
    if (parsed.error) {
      sendText(res, 400, `参数错误: ${parsed.error}\n\nGET / 查看可用参数\n`);
      return;
    }

    const flags = parsed.flags;
    const jsonMode = flags.jsonMode;
    const requestId = ++served;
    const queued = lock.queueLength;

    let closed = false;
    res.on('close', () => { closed = true; });

    // 流式：不设 Content-Length，Node 自动用 chunked，每次 write 立即发出。
    // JSON 模式要等到最后才能写出合法 JSON，所以先不发响应头。
    if (!jsonMode) {
      res.writeHead(200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Accel-Buffering': 'no',
      });
      res.flushHeaders();
    }

    const write = (text) => {
      if (closed || jsonMode) return;
      res.write(text + '\n');
    };

    // CLI 把过程日志打 stderr、结果打 stdout；HTTP 只有一个流，
    // 两路都写响应体，客户端看到的顺序就是实际发生顺序。
    // color: false —— 响应体不是终端，ANSI 颜色码会变成乱码。
    const sink = { data: write, info: write, color: false };

    await lock.acquire();
    const startedAt = Date.now();
    log(`[${requestId}] 开始 ${url.search}`);

    try {
      if (queued > 0) write(`（排队结束：前面 ${queued} 个任务已完成）`);

      const result = await run(flags, sink);

      if (jsonMode) {
        sendJSON(res, 200, result && result.json ? result.json : []);
      } else {
        write('');
        write(`耗时 ${((Date.now() - startedAt) / 1000).toFixed(1)}s`);
        if (!closed) res.end();
      }
      log(`[${requestId}] 完成，用时 ${((Date.now() - startedAt) / 1000).toFixed(1)}s`);
    } catch (e) {
      const message = e && e.message ? e.message : String(e);
      log(`[${requestId}] 失败: ${message}`);

      if (jsonMode) {
        sendJSON(res, isAppError(e) ? 400 : 500, { error: message });
      } else {
        responseError(res, 500, message);
      }
    } finally {
      lock.release();
    }
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((e) => {
      log(`未捕获异常: ${e && e.stack ? e.stack : e}`);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      }
      if (!res.writableEnded) res.end('内部错误\n');
    });
  });

  return server;
}

module.exports = { createServer, createLock, indexPage };
