import net from 'node:net';

/**
 * Per-app loopback listener that byte-pipes to the upstream only while the gate is
 * open. It never parses the proxy protocol and can only ever dial the upstream
 * port, so it has no code path that reaches the internet directly.
 */
export class GatePort {
  constructor({ port, isOpen, upstreamPort }) {
    this.port = port;
    this.isOpen = isOpen;
    this.upstreamPort = upstreamPort; // function: settings can change at runtime
    this.pairs = new Set();
    this.stats = { up: 0, down: 0, accepted: 0, refused: 0 };
    this.server = net.createServer((client) => this.#handle(client));
  }

  listen() {
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.port, '127.0.0.1', () => {
        this.server.off('error', reject);
        resolve();
      });
    });
  }

  #handle(client) {
    client.on('error', () => {});
    if (!this.isOpen()) {
      this.stats.refused++;
      client.resetAndDestroy();
      return;
    }
    this.stats.accepted++;
    const upstream = net.connect({ host: '127.0.0.1', port: this.upstreamPort() });
    const pair = { client, upstream };
    this.pairs.add(pair);
    upstream.on('error', () => {});
    client.on('data', (d) => { this.stats.up += d.length; });
    upstream.on('data', (d) => { this.stats.down += d.length; });
    client.pipe(upstream);
    upstream.pipe(client);
    const cleanup = () => {
      this.pairs.delete(pair);
      if (!client.destroyed) client.destroy();
      if (!upstream.destroyed) upstream.destroy();
    };
    client.once('close', cleanup);
    upstream.once('close', cleanup);
  }

  /** Hard reset: the app sees the drop immediately rather than a hang. */
  dropAll() {
    for (const { client, upstream } of this.pairs) {
      upstream.destroy();
      if (!client.destroyed) client.resetAndDestroy();
    }
    this.pairs.clear();
  }

  get active() { return this.pairs.size; }

  close() {
    this.dropAll();
    return new Promise((resolve) => this.server.close(() => resolve()));
  }
}
