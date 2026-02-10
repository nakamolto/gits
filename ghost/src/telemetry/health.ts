import http from 'node:http';

export type HealthStatus = {
  ok: boolean;
  ready: boolean;
  ghost_id?: string;
  epoch?: string;
  last_block?: number;
  warnings?: string[];
  modules?: Record<string, { started: boolean; lastEpochTick?: string }>;
};

export class HealthServer {
  private readonly port: number;
  private readonly getStatus: () => Promise<HealthStatus> | HealthStatus;
  private server?: http.Server;

  constructor(args: { port: number; getStatus: () => Promise<HealthStatus> | HealthStatus }) {
    this.port = args.port;
    this.getStatus = args.getStatus;
  }

  async start(): Promise<void> {
    if (this.server) return;

    this.server = http.createServer(async (req, res) => {
      if (!req.url || req.method !== 'GET') {
        res.statusCode = 404;
        res.end();
        return;
      }

      const url = new URL(req.url, 'http://127.0.0.1');
      if (url.pathname !== '/health') {
        res.statusCode = 404;
        res.end();
        return;
      }

      try {
        const status = await this.getStatus();
        const body = JSON.stringify(status);
        res.statusCode = status.ok ? 200 : 503;
        res.setHeader('content-type', 'application/json');
        res.end(body);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        res.statusCode = 500;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ ok: false, ready: false, warnings: [msg] } satisfies HealthStatus));
      }
    });

    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(this.port, resolve);
    });
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    const s = this.server;
    this.server = undefined;

    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
}
