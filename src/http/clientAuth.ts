import { timingSafeEqual } from "node:crypto";
import type { DemoClient } from "../config/client.js";

export interface ClientCredentials {
  clientId: string;
  clientSecret: string;
}

export function parseBasicAuth(header: string | undefined): ClientCredentials | undefined {
  if (!header || !header.startsWith("Basic ")) {
    return undefined;
  }

  let decoded: string;
  try {
    decoded = Buffer.from(header.slice("Basic ".length), "base64").toString("utf-8");
  } catch {
    return undefined;
  }

  const separatorIndex = decoded.indexOf(":");
  if (separatorIndex === -1) {
    return undefined;
  }

  return {
    clientId: decoded.slice(0, separatorIndex),
    clientSecret: decoded.slice(separatorIndex + 1)
  };
}

function timingSafeEqualStr(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

export function isValidClient(credentials: ClientCredentials | undefined, client: DemoClient): boolean {
  if (!credentials) {
    return false;
  }
  return (
    timingSafeEqualStr(credentials.clientId, client.clientId) &&
    timingSafeEqualStr(credentials.clientSecret, client.clientSecret)
  );
}
