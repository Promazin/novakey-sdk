import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { RelayerEngine, RelayerError } from './engine.ts';
import type { RelayRequest } from './types.ts';

/**
 * Create a lightweight Node.js HTTP server exposing the NovaKey gas-sponsoring relayer API:
 * - `GET /health`
 * - `POST /api/v1/relay`
 * - `GET /api/v1/tx/:txHash`
 */
export function createRelayerServer(engine: RelayerEngine): Server {
  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    // Standard CORS headers for browser dApps
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = req.url ?? '/';

    try {
      if (req.method === 'GET' && url === '/health') {
        sendJson(res, 200, {
          status: 'ok',
          service: '@novakey/relayer-node',
          metrics: engine.getMetrics(),
        });
        return;
      }

      if (req.method === 'POST' && url === '/api/v1/relay') {
        const rawBody = await readRequestBody(req);
        let parsed: RelayRequest;
        try {
          parsed = JSON.parse(rawBody) as RelayRequest;
        } catch {
          throw new RelayerError('Invalid JSON payload', 400, 'INVALID_JSON');
        }

        const receipt = await engine.relay(parsed);
        sendJson(res, 200, receipt);
        return;
      }

      if (req.method === 'GET' && url.startsWith('/api/v1/tx/')) {
        const txHash = url.slice('/api/v1/tx/'.length);
        const receipt = engine.getReceipt(txHash);
        if (!receipt) {
          sendJson(res, 404, {
            error: 'Transaction receipt not found',
            code: 'TX_NOT_FOUND',
          });
          return;
        }
        sendJson(res, 200, receipt);
        return;
      }

      sendJson(res, 404, {
        error: 'Endpoint not found',
        code: 'NOT_FOUND',
      });
    } catch (err) {
      if (err instanceof RelayerError) {
        sendJson(res, err.statusCode, {
          error: err.message,
          code: err.code,
        });
        return;
      }
      sendJson(res, 500, {
        error: err instanceof Error ? err.message : 'Internal server error',
        code: 'INTERNAL_ERROR',
      });
    }
  });
}

function sendJson(res: ServerResponse, statusCode: number, data: unknown): void {
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

function readRequestBody(req: IncomingMessage, maxBytes = 65_536): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;

    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new RelayerError('Request body too large', 413, 'PAYLOAD_TOO_LARGE'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      resolve(Buffer.concat(chunks).toString('utf-8'));
    });

    req.on('error', reject);
  });
}
