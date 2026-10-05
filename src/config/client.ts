import { z } from "zod";
import { DEFAULT_ISSUER, type EnvSource } from "./env.js";
import { isLoopbackHttpUrl } from "./loopback.js";

const PLACEHOLDER_SECRET = "demo-client-secret-change-me";

export interface DemoClient {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  audience: string;
}

const clientEnvSchema = z.object({
  CLIENT_ID: z.string().min(1).default("demo-agent-client"),
  CLIENT_SECRET: z.string().min(1).default(PLACEHOLDER_SECRET),
  CLIENT_REDIRECT_URI: z
    .string()
    .url({ message: "CLIENT_REDIRECT_URI must be a valid absolute URL" })
    .default("http://localhost:4000/callback"),
  CLIENT_AUDIENCE: z
    .string()
    .url({ message: "CLIENT_AUDIENCE must be a valid absolute URL" })
    .default("http://localhost:8000/mcp")
});

export function loadDemoClient(source: EnvSource = process.env): DemoClient {
  const result = clientEnvSchema.safeParse(source);

  if (!result.success) {
    const issue = result.error.issues[0];
    const field = issue?.path.join(".") || "environment";
    const message = issue?.message ?? "invalid client configuration";
    throw new Error(`Invalid environment variable ${field}: ${message}`);
  }

  const env = result.data;

  if (env.CLIENT_SECRET === PLACEHOLDER_SECRET && !isLoopbackHttpUrl(source.ISSUER ?? DEFAULT_ISSUER)) {
    throw new Error(
      "Invalid environment variable CLIENT_SECRET: set a real secret; the placeholder is allowed only when ISSUER is a loopback http URL (localhost, 127.0.0.1 or [::1])"
    );
  }

  return {
    clientId: env.CLIENT_ID,
    clientSecret: env.CLIENT_SECRET,
    redirectUri: env.CLIENT_REDIRECT_URI,
    audience: env.CLIENT_AUDIENCE
  };
}
