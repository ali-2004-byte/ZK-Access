const LOOPBACK_HOST = '127.0.0.1';

export function listenLocal(app, { portVariable, defaultPort, serviceName }) {
  const rawPort = process.env[portVariable];
  const port = rawPort === undefined ? defaultPort : Number(rawPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new RangeError(`${portVariable} must be a port from 1 to 65535`);
  }

  const server = app.listen(port, LOOPBACK_HOST, () => {
    console.log(`${serviceName} listening at http://${LOOPBACK_HOST}:${port}`);
  });
  return server;
}
