// Docker-network compatibility proxy for host-native alert-store.
//
// n8n workflows call http://alert-store:8787. The real alert-store process runs
// on the Mac host so SQLite writes stay off Docker Desktop bind mounts.
const net = require('net');

const listenHost = process.env.ALERT_STORE_PROXY_HOST || '0.0.0.0';
const listenPort = Number(process.env.ALERT_STORE_PROXY_PORT || process.env.ALERT_STORE_PORT || 8787);
const targetHost = process.env.ALERT_STORE_HOST_TARGET || 'host.docker.internal';
const targetPort = Number(process.env.ALERT_STORE_PORT_TARGET || process.env.ALERT_STORE_PORT || 8787);
const connectTimeoutMs = Math.max(1000, Number(process.env.ALERT_STORE_PROXY_CONNECT_TIMEOUT_MS || 5000));
const idleTimeoutMs = Math.max(5000, Number(process.env.ALERT_STORE_PROXY_IDLE_TIMEOUT_MS || 60000));
const maxConnections = Math.max(8, Number(process.env.ALERT_STORE_PROXY_MAX_CONNECTIONS || 256));

const server = net.createServer((client) => {
  const upstream = net.connect({host: targetHost, port: targetPort});
  let closed = false;
  let connectTimer = null;
  const close = (error) => {
    if (closed) return;
    closed = true;
    if (connectTimer) clearTimeout(connectTimer);
    if (error) console.error(`alert-store proxy connection failed: ${error.message}`);
    client.destroy();
    upstream.destroy();
  };
  connectTimer = setTimeout(
    () => close(new Error(`upstream connect timeout after ${connectTimeoutMs}ms`)),
    connectTimeoutMs,
  );
  connectTimer.unref();

  client.setNoDelay(true);
  client.setKeepAlive(true, 10000);
  client.setTimeout(idleTimeoutMs, () => close(new Error(`client idle timeout after ${idleTimeoutMs}ms`)));
  upstream.setNoDelay(true);
  upstream.setKeepAlive(true, 10000);
  upstream.setTimeout(idleTimeoutMs, () => close(new Error(`upstream idle timeout after ${idleTimeoutMs}ms`)));
  upstream.once('connect', () => {
    clearTimeout(connectTimer);
    client.pipe(upstream);
    upstream.pipe(client);
  });
  client.on('error', close);
  upstream.on('error', close);
  client.on('close', () => close());
  upstream.on('close', () => close());
});

server.maxConnections = maxConnections;
server.on('error', (error) => {
  console.error(`alert-store proxy listener failed: ${error.message}`);
  process.exitCode = 1;
});
server.listen(listenPort, listenHost, () => {
  console.log(`alert-store proxy listening on ${listenHost}:${listenPort} -> ${targetHost}:${targetPort}`);
});
