import { randomUUID } from "node:crypto";
import type { MiddlewareHandler } from "hono";
import type { Logger } from "../log.js";

const REQUEST_ID_HEADER = "x-request-id";

export interface AppEnv {
  Variables: {
    requestId: string;
  };
}

/**
 * One log line per request. Only the path is logged: the /authorize query string carries
 * state and code_challenge, and bodies and headers are never touched.
 */
export function requestLogging(logger: Logger): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const requestId = c.req.header(REQUEST_ID_HEADER) ?? randomUUID();
    c.set("requestId", requestId);
    c.header("X-Request-Id", requestId);
    const startedAt = Date.now();

    await next();

    logger.info("http_request", {
      requestId,
      method: c.req.method,
      path: new URL(c.req.url).pathname,
      status: c.res.status,
      durationMs: Date.now() - startedAt
    });
  };
}
