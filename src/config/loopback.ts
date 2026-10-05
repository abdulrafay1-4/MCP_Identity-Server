const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

function parse(value: string): URL | undefined {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

export function isLoopbackHttpUrl(value: string): boolean {
  const url = parse(value);
  return url?.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
}

export function isHttpsOrLoopbackUrl(value: string): boolean {
  return parse(value)?.protocol === "https:" || isLoopbackHttpUrl(value);
}
