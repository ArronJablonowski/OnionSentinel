// Docker-network compatibility proxy for host-native alert-store.
//
// n8n workflows call http://alert-store:8787. The real alert-store process runs
// on the Mac host so SQLite writes stay off Docker Desktop bind mounts.
const net = require('net');

const listenHost = process.env.ALERT_STORE_PROXY_HOST || '0.0.0.0';
const listenPort = Number(process.env.ALERT_STORE_PROXY_PORT || process.env.ALERT_STORE_PORT || 8787);
const targetHost = process.env.ALERT_STORE_HOST_TARGET || 'host.docker.internal';
const targetPort = Number(process.env.ALERT_STORE_PORT_TARGET || process.env.ALERT_STORE_PORT || 8787);

const server = net.createServer((client) => {
  const upstream = net.connect({host: targetHost, port: targetPort});
  client.pipe(upstream);
  upstream.pipe(client);
  const close = () => {
    client.destroy();
    upstream.destroy();
  };
  client.on('error', close);
  upstream.on('error', close);
});

server.listen(listenPort, listenHost, () => {
  console.log(`alert-store proxy listening on ${listenHost}:${listenPort} -> ${targetHost}:${targetPort}`);
});
