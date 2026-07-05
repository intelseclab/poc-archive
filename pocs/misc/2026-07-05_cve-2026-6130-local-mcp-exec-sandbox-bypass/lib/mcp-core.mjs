import { createInterface } from 'readline';

// === Protocol handler (transport-agnostic) ===
export function createProtocolHandler(tools, handlers) {
  return {
    handleMessage(m) {
      if (m.method === 'initialize' && m.id != null)
        return { id: m.id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {}, resources: {} }, serverInfo: { name: 'local-mcp', version: '1.1.0' } } };
      if (m.method === 'tools/list' && m.id != null)
        return { id: m.id, result: { tools } };
      if (m.method === 'tools/call' && m.id != null) {
        const h = handlers[m.params.name];
        if (!h) return { id: m.id, result: { content: [{ type: 'text', text: 'Unknown tool: ' + m.params.name }], isError: true } };
        return Promise.resolve().then(() => h(Object.assign(m.params.arguments || {}, { _progressToken: m._meta?.progressToken })))
          .then(r => ({ id: m.id, result: { content: [{ type: 'text', text: JSON.stringify(r) }] } }))
          .catch(e => ({ id: m.id, result: { content: [{ type: 'text', text: e?.message || String(e) }], isError: true } }));
      }
      if (m.method === 'resources/list' && m.id != null) {
        const list = (typeof handlers._resources === 'function') ? handlers._resources() : (handlers._resources || []);
        return { id: m.id, result: { resources: list } };
      }
      if (m.method === 'resources/read' && m.id != null) {
        const uri = m.params?.uri;
        if (!uri) return { id: m.id, result: { content: [], isError: true } };
        if (typeof handlers._readResource === 'function') {
          return Promise.resolve().then(() => handlers._readResource(uri))
            .then(r => ({ id: m.id, result: { contents: Array.isArray(r) ? r : [r] } }))
            .catch(e => ({ id: m.id, result: { content: [{ type: 'text', text: e?.message || String(e) }], isError: true } }));
        }
        return { id: m.id, result: { contents: [] } };
      }
      if (m.method === 'ping' && m.id != null)
        return { id: m.id, result: {} };
      return null;
    }
  };
}

// === Stdio transport ===
export function serve(tools, handlers) {
  const proto = createProtocolHandler(tools, handlers);
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  let buf = '';
  rl.on('line', l => {
    buf += l;
    try { const m = JSON.parse(buf); buf = ''; handle(m); } catch {}
  });
  function handle(m) {
    const result = proto.handleMessage(m);
    if (!result) return;
    if (result instanceof Promise) {
      result.then(r => send(r.id, r.result));
    } else {
      send(result.id, result.result);
    }
  }
  function send(id, result) { process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n'); }
}

// === HTTP transport (Streamable HTTP, MCP 2025-03-26) ===
import http from 'http';

export function serveHttp(tools, handlers, port = 3100) {
  const proto = createProtocolHandler(tools, handlers);

  const server = http.createServer((req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // GET /health or GET / for simple checks
    if (req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, server: 'local-mcp', transport: 'streamable-http' }));
      return;
    }

    if (req.method !== 'POST') {
      res.writeHead(405);
      res.end('Method Not Allowed');
      return;
    }

    const accept = req.headers['accept'] || '';
    const wantsStream = accept.includes('text/event-stream');

    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      let msg;
      try { msg = JSON.parse(body); } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' } }));
        return;
      }

      const result = proto.handleMessage(msg);

      if (result instanceof Promise) {
        if (wantsStream) {
          // SSE streaming
          res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
          });
          result.then(r => {
            res.write(`data: ${JSON.stringify({ jsonrpc: '2.0', id: r.id, result: r.result })}\n\n`);
            res.write('data: [DONE]\n\n');
            res.end();
          }).catch(() => { res.end(); });
        } else {
          // Wait for promise, return JSON
          result.then(r => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ jsonrpc: '2.0', id: r.id, result: r.result }));
          }).catch(() => {
            res.writeHead(500);
            res.end();
          });
        }
      } else if (result) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: result.id, result: result.result }));
      } else {
        res.writeHead(204);
        res.end();
      }
    });
  });

  server.listen(port, '0.0.0.0', () => {
    process.stderr.write(`MCP HTTP server listening on http://0.0.0.0:${port}\n`);
  });

  return server;
}
