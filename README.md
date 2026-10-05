# MCP Identity Server

[![ci](https://github.com/abdulrafay1-4/MCP_Identity-Server/actions/workflows/ci.yml/badge.svg)](https://github.com/abdulrafay1-4/MCP_Identity-Server/actions/workflows/ci.yml)

An OAuth 2.1 authorization server for AI agents. Each agent gets its own short-lived,
narrowly scoped token instead of its user's credentials. An agent can delegate a narrower
token to another agent, and revoking any token also revokes everything delegated from it.
A small verifier module lets any MCP server accept these tokens.

## Why

The MCP SDK gives servers the resource-server half of OAuth: they can validate a bearer
token and publish RFC 9728 metadata. Something still has to issue the tokens, and agent
systems add a case most deployments don't handle: one agent handing part of its authority
to another in the middle of a task, and being able to take it back.

| | Common practice | Here |
|---|---|---|
| Token subject | the user | the agent instance |
| Lifetime | hours or days | minutes (300 s by default) |
| Scope | everything the user can do | one or two tools |
| Delegation | sharing credentials | explicit, narrower, recorded |
| Revocation mid-task | rarely possible | yes, including every descendant |

## How delegation and revocation work

An agent exchanges its token for a child token (RFC 8693). The server enforces:

1. `scope(child) ⊆ scope(parent)`. A request for wider scope is refused with `invalid_scope`, not trimmed.
2. `exp(child) <= exp(parent)`.
3. The child's audience is the parent's audience.
4. Chain depth is capped by `MAX_DELEGATION_DEPTH`.
5. The parent must be live: not expired and not revoked.

Each child records its parent, so the tree can be walked in both directions.

```
orchestrator              filings:read quotes:read
 ├── research-bot         filings:read
 │    └── summarizer      filings:read
 └── pricing-bot          quotes:read

revoke(orchestrator)  ->  every token below it is inactive on its next use
revoke(research-bot)  ->  research-bot and summarizer inactive; pricing-bot unaffected
```

A JWT can't be recalled once it's issued, so the server keeps revocation state and
resource servers ask it on each request (RFC 7662 introspection). A token counts as active
only if neither it nor any of its ancestors is revoked. Checking the ancestry on every
lookup is what keeps a child created during its parent's revocation from surviving.

| Option | Trade-off |
|---|---|
| Short TTL only | revocation takes as long as the TTL |
| Introspection (used here) | exact on the next request; resource servers depend on the authorization server being reachable |
| Cached revocation list | cheaper, but can be stale |
| Offline chains (macaroons) | no issuer at verify time; revocation spreads slowly and the revocation set keeps growing |

If the authorization server is unreachable, protected tools refuse requests.

## Endpoints

| Endpoint | Spec | Purpose |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | discovery |
| `GET /jwks.json` | RFC 7517 | signing keys, including keys kept for verification during rotation |
| `GET /authorize` | OAuth 2.1, RFC 7636, RFC 9207 | authorization code with PKCE; the redirect carries `iss` |
| `POST /token` | OAuth 2.1, RFC 8693 | `authorization_code`, `refresh_token`, token exchange |
| `POST /introspect` | RFC 7662 | is this token active |
| `POST /revoke` | RFC 7009 | revoke an access or refresh token and everything delegated from it |
| `GET /healthz`, `GET /readyz` | | liveness, and readiness including the database |

## Token

```json
{
  "iss": "https://auth.example.com",
  "sub": "agent:research-bot:7f3a",
  "aud": "https://mcp.example.com/mcp",
  "scope": "filings:read",
  "jti": "5c9b0f1e-...",
  "act": { "sub": "agent:orchestrator:1c9d" },
  "iat": 1786600000,
  "exp": 1786600300
}
```

`sub` is the agent, so you can tell which agent did what. `jti` names the token so it can be
revoked. `aud` binds it to one resource server (RFC 8707), so a token for one server does not
work on another. `act` names the agent that delegated it. Tokens are signed with RS256 and
carry a `kid`.

## Quick start

```bash
git clone https://github.com/abdulrafay1-4/MCP_Identity-Server.git
cd MCP_Identity-Server
npm install
npm start
```

With no `DATABASE_URL` it uses an in-memory store. To use Postgres:

```bash
docker run -d --name mcp-identity-pg -e POSTGRES_PASSWORD=dev -p 5432:5432 postgres:16-alpine
DATABASE_URL=postgres://postgres:dev@localhost:5432/postgres npm start
```

Migrations run on startup.

## Walkthrough: delegate, then revoke

These commands use the defaults: issuer `http://localhost:3000`, the demo client
`demo-agent-client` / `demo-client-secret-change-me`, redirect URI
`http://localhost:4000/callback` and audience `http://localhost:8000/mcp`.

```bash
# 1. PKCE verifier and S256 challenge
VERIFIER=$(openssl rand -base64 96 | tr -d '=+/\n' | cut -c1-64)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')

# 2. Authorize (auto-approved) and read the code from the redirect
LOCATION=$(curl -s -o /dev/null -D - \
  "http://localhost:3000/authorize?response_type=code&client_id=demo-agent-client&redirect_uri=http://localhost:4000/callback&scope=filings:read%20quotes:read&code_challenge=$CHALLENGE&code_challenge_method=S256&agent_id=orchestrator" \
  | grep -i '^location:' | tr -d '\r')
CODE=$(echo "$LOCATION" | grep -oE 'code=[^&]+' | cut -d= -f2)

# 3. Exchange the code for the orchestrator's token
ROOT=$(curl -s -u demo-agent-client:demo-client-secret-change-me \
  -d grant_type=authorization_code -d code="$CODE" \
  -d redirect_uri=http://localhost:4000/callback -d code_verifier="$VERIFIER" \
  http://localhost:3000/token | grep -oE '"access_token":"[^"]+"' | cut -d'"' -f4)

# 4. Delegate a narrower token to research-bot
CHILD=$(curl -s -u demo-agent-client:demo-client-secret-change-me \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$ROOT" -d scope=filings:read -d agent_id=research-bot \
  http://localhost:3000/token | grep -oE '"access_token":"[^"]+"' | cut -d'"' -f4)

# 5. The child is active
curl -s -u demo-agent-client:demo-client-secret-change-me -d token="$CHILD" http://localhost:3000/introspect

# 6. Revoke the parent
curl -s -u demo-agent-client:demo-client-secret-change-me -d token="$ROOT" http://localhost:3000/revoke

# 7. The child is now inactive, although it was never revoked directly
curl -s -u demo-agent-client:demo-client-secret-change-me -d token="$CHILD" http://localhost:3000/introspect
# {"active":false}
```

Exchanging `$CHILD` for `quotes:read` returns `invalid_scope`: research-bot only holds
`filings:read`, and a child can't hold more than its parent.

## Protecting an MCP server

`src/verifier.ts` implements the MCP SDK's `OAuthTokenVerifier`. It checks the signature,
issuer, audience and expiry locally, then calls `/introspect` so revocation takes effect.

```ts
import { requireBearerAuth } from "@modelcontextprotocol/server";
import { McpTokenVerifier } from "./src/verifier.js";

const verifier = new McpTokenVerifier({
  issuer: "https://auth.example.com",
  resource: "https://mcp.example.com/mcp",
  clientId: process.env.INTROSPECTION_CLIENT_ID!,
  clientSecret: process.env.INTROSPECTION_CLIENT_SECRET!,
});

const authenticate = requireBearerAuth({ verifier, requiredScopes: ["filings:read"] });
```

`TOOL_SCOPES` and `requiredScopeForTool()` map tool names to scopes.

## Configuration

Every variable has a default, so local development needs none. Outside local development
the server refuses to start unless `ISSUER` is https and `CLIENT_SECRET` is set to a real value.

| Variable | Default | |
|---|---|---|
| `ISSUER` | `http://localhost:3000` | `iss` claim and discovery base URL. https, or http on localhost only |
| `PORT` | `3000` | |
| `DATABASE_URL` | unset | Postgres connection string. Unset means the in-memory store |
| `TOKEN_TTL_SECONDS` | `300` | access token lifetime |
| `MAX_DELEGATION_DEPTH` | `5` | longest delegation chain |
| `REFRESH_TOKEN_TTL_SECONDS` | `2592000` | refresh family lifetime (30 days), fixed at the original grant |
| `REFRESH_REUSE_GRACE_SECONDS` | `10` | window in which a just-rotated refresh token may be retried once. `0` disables it |
| `KEY_RING_PATH` | `.data/keys.json` | signing key ring file. Holds the active private key |
| `SIGNING_KEY` | unset | PKCS#8 PEM to seed the first key. Ignored once the ring file exists |
| `RATE_LIMIT_MAX` | `60` | requests per window, per endpoint |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | |
| `PRUNE_INTERVAL_MS` | `60000` | how often expired rows are deleted |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. Logs are JSON lines |
| `CLIENT_ID` | `demo-agent-client` | the pre-registered client |
| `CLIENT_SECRET` | placeholder | allowed only with a localhost `ISSUER` |
| `CLIENT_REDIRECT_URI` | `http://localhost:4000/callback` | |
| `CLIENT_AUDIENCE` | `http://localhost:8000/mcp` | `aud` when `/authorize` gets no `resource` |

Rotate the signing key with `npm run rotate-key`. The previous key keeps verifying the tokens
it signed but stops signing. `npm run rotate-key -- retire <kid>` stops accepting it entirely.
The server reads the key ring at startup.

## Testing

```bash
npm test              # in-memory store and embedded Postgres (pglite)
npm run typecheck
DATABASE_URL=postgres://postgres:dev@localhost:5432/postgres npm test   # adds the real Postgres suites
```

475 tests. 411 need no database: they run against the in-memory store and against pglite.
The other 64 run against a real Postgres server when `DATABASE_URL` is set, each test file in a
throwaway database of its own.

The store, delegation, revocation and refresh behaviour are each written once as a shared
suite and run against three backends: in memory, pglite (Postgres compiled to WebAssembly,
no server), and a real Postgres server. CI runs everything against Postgres 16 on every push.

Tests for rejected requests were checked by temporarily disabling the check they target and
confirming the test then fails. A few passed anyway at first because a second check caught the
same input, so those checks now have tests of their own.

## Project layout

```
src/
  server.ts            entry point
  http/app.ts          OAuth endpoints (Hono)
  http/                client authentication, rate limiting, request logging
  tokens.ts            issue and verify JWTs
  keys.ts              signing key ring: active, published, retired
  verifier.ts          OAuthTokenVerifier for MCP servers
  cimd.ts              Client ID Metadata Document fetching
  pkce.ts, resource.ts, hash.ts, log.ts
  config/              validated configuration
  cli/rotateKey.ts     key rotation command
  store/               TokenStore interface, memory and Postgres implementations
migrations/            SQL migrations
test/                  unit, contract and integration tests
```

## Standards

| Standard | Use |
|---|---|
| OAuth 2.1 | authorization code grant, PKCE required |
| RFC 7636 | PKCE, `S256` only |
| RFC 8414 | authorization server metadata |
| RFC 7517 | JWKS |
| RFC 7662 | token introspection |
| RFC 7009 | token revocation |
| RFC 8693 | token exchange, used for delegation between agents |
| RFC 8707 | resource indicators |
| RFC 9207 | `iss` in authorization responses |
| Client ID Metadata Documents | `client_id` as an HTTPS URL, per the MCP authorization spec of 2026-07-28 |

RFC 8693 is written for impersonation, where the subject stays the same and an actor is
added. Agent-to-agent delegation changes the subject, so the child token gets the new agent
as `sub` and the delegating agent in `act`.

## Not implemented

- Dynamic Client Registration (RFC 7591). The MCP spec now prefers Client ID Metadata Documents.
- A login or consent screen. `/authorize` approves automatically.
- Multiple tenants or issuers.
- Sender-constrained tokens (DPoP or mTLS). Tokens are bearer tokens.
- Shared state across instances. Rate limits and the signing key file are per instance.
- Revoking tokens issued from an authorization code when that code is replayed. The replay
  itself is refused.

## License

MIT
