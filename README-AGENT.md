# README-AGENT.md — Super Duper Admin Portal setup guide for AI agents

You are an AI coding agent helping an engineer spin up this repo. This file is your operational runbook; [README.md](README.md) has full feature docs, and `docs/okta-xaa-handoff.md` is a worked example of the advanced Cross App Access setup (its hostnames and IDs belong to the original author's deployment — treat them as placeholders).

## What this is

A **chat-first admin portal for Okta administrators**: React/Vite SPA + Express API. Admins chat with an LLM that has Okta tools, trigger admin actions (suspend user, reset MFA) gated by **Okta Access Requests (OIG)** approvals, and the same tools are exposed over REST and a stdio **MCP server** (`mcp-server/index.js`, tools: `sdap_chat`, `sdap_trigger_action`, `sdap_okta_request`).

Unlike the companion repos ([sis-demo](https://github.com/barneslardo/sis-demo), [super-lms](https://github.com/barneslardo/super-lms)) there is **no database** — state lives in `.data/` (sessions, access-request cache). Uses **npm**, not pnpm.

**Architecture you must understand before serving it:**
- `api-server.js` → port **3201** (`API_PORT`). All real work: LLM proxy, `/api/okta/*` Okta Management API proxy (SSWS token stays server-side), OIDC/SAML auth, access requests.
- `web-server.js` → port **3200** (`PORT`). Serves the built `dist/` only — it does **NOT** proxy `/api` (returns 404 for it).
- The SPA bakes its API origin **at build time** from `VITE_API_BASE`. Empty `VITE_API_BASE` = relative URLs = you need a reverse proxy routing `/api/*` to :3201 and everything else to :3200 on one origin. For a proxy-less setup, set `VITE_API_BASE` to the API origin **before `npm run build`** and set `WEB_ORIGIN` so CORS allows the web origin.

## Ground rules for agents

1. **Never commit** `.env.local` / `.env`, `secrets/`, `.data/`, or any token. The Okta SSWS token grants real admin power in the org — server-side only, never into frontend code or logs.
2. **All `skylarbarnes.com` / `sledai.oktapreview.com` values are the original author's** — substitute your engineer's (table below).
3. **Ask your engineer for:** Okta org URL + admin access, an SSWS API token (see 2a for scopes), at least one LLM key (OpenAI / Anthropic / Grok), and public DNS names if deploying. Do not guess or fabricate any of these.
4. Steps marked **[HUMAN]** happen in the Okta Admin Console.
5. `DEMO_AUTH_BYPASS=true` disables login entirely. Fine on localhost; **never deploy publicly with it on** — flip to `false` once OIDC/SAML works, and put the deployed app behind HTTPS + real auth.

### Value substitution table

| Placeholder | Replace with |
|---|---|
| `https://sledai.oktapreview.com` | Your Okta org URL (`OKTA_ORG_URL`, `OKTA_API_DOMAIN`) |
| `https://ai-admin.skylarbarnes.com` | Your web public URL (`WEB_ORIGIN`) |
| `https://ai-admin-api.skylarbarnes.com` | Your API public URL (`VITE_API_BASE` when no shared-origin proxy) |
| `exkzd4x270Uxefp211d7`, `0oa…`, `auszdlcnxzbhKo6OJ1d7`, `cen…` IDs | IDs from your org (SAML app, OIDC app, custom AS, OIG catalog entries) |

## Phase 0 — Prerequisites

```bash
node --version    # need 20+
npm --version
```

Ports: **3200** (web) and **3201** (API) by default — change `PORT` / `API_PORT` in `.env.local` on conflict. Dev mode also uses 5173 (Vite).

## Phase 1 — Run locally, minimal config

Chat works with just an LLM key; Okta data tools additionally need the SSWS token.

```bash
npm install
cp .env.example .env.local
```

Minimal `.env.local` to start (get real values from the engineer):

```env
OPENAI_API_KEY=<from engineer>        # or ANTHROPIC_API_KEY / GROK_API_KEY
DEFAULT_LLM_PROVIDER=openai
OKTA_ORG_URL=https://<your-org>.oktapreview.com
OKTA_API_DOMAIN=<your-org>.oktapreview.com
OKTA_API_TOKEN=<from engineer — see 2a>
PORT=3200
API_PORT=3201
DEMO_AUTH_BYPASS=true
SESSION_SECRET=<generate: openssl rand -hex 32>
# Proxy-less local build wiring:
VITE_API_BASE=http://localhost:3201
WEB_ORIGIN=http://localhost:3200
```

Build and run (production-style, most predictable):

```bash
npm run build         # VITE_API_BASE is baked in here
npm run serve:api &   # API :3201   (or use pm2, see Phase 3)
npm run serve &       # web :3200
```

(Dev mode alternative: `npm run dev:full` starts Vite :5173 + API :3201; Vite has no `/api` proxy configured, so dev mode also relies on `VITE_API_BASE` — export it before starting.)

**Verify:**
1. `curl -s http://localhost:3201/api/available-models` lists models for your configured key(s).
2. Open `http://localhost:3200` — with `DEMO_AUTH_BYPASS=true` you land in the portal; send a chat message and confirm a reply.
3. Quick Actions → list users returns data from your org (proves the SSWS token works).

## Phase 2 — Okta wiring (layered)

### 2a. SSWS API token (minimum for real Okta data)

**[HUMAN]** Okta Admin Console → Security → API → Tokens → Create. The token inherits its creator's permissions — for demos prefer creating it as a **read-only admin** unless the action tools are needed (suspend/unsuspend/MFA-reset require user-management permissions). Set it as `OKTA_API_TOKEN`.

**Verify:** `curl -s -H "Authorization: SSWS $TOKEN" https://<org>/api/v1/users?limit=1` returns a user.

### 2b. Real login — OIDC (preferred) or SAML

- **[HUMAN]** Create an OIDC Web App (Authorization Code). Sign-in redirect URI: `<API public URL>/api/oidc/callback`. Initiate login URI (for the Okta tile): `<API public URL>/api/oidc/login`.
- Set `OKTA_OIDC_CLIENT_ID`, `OKTA_OIDC_REDIRECT_URI`, `OIDC_SCOPES=openid profile email offline_access`, `POST_LOGIN_REDIRECT=<web public URL>/`, and cookie settings for your domains (`COOKIE_DOMAIN` only when web+API share a parent domain).
- SAML alternative: README.md "SAML 2.0 Integration" — set `SAML_ENTRY_POINT`, `SAML_ISSUER`, `SAML_CERT` (the IdP **public** cert), `SAML_SP_ENTITY_ID`, `SAML_SP_ACS_URL=<API public URL>/api/saml/acs`.
- Then set `DEMO_AUTH_BYPASS=false`, restart the API, and **verify** login lands you back authenticated (`GET /api/auth/me` returns the user).

### 2c. Access Requests / OIG approvals (advanced, optional)

Human-in-the-loop approvals for destructive actions. Requires an Okta org with **Identity Governance**. **[HUMAN]** creates the catalog entries in Access Requests; the agent then sets `OKTA_ACCESS_REQUESTS_TOKEN` (scope `okta.accessRequests.request.manage`) and maps `OKTA_ACCESS_REQUEST_CATALOG_ENTRIES={"suspend_user":"cen…", …}`. Discover entry IDs with `node scripts/discover-access-request-catalog.mjs`. Contract details: `docs/access-request-flo-contract.md`.

### 2d. Agent token exchange / Cross App Access (advanced, optional)

Mirrors the sis-demo ID-JAG pattern against a custom AS minting `sdap.*` scopes. Follow `docs/okta-xaa-handoff.md` as a worked example, substituting your org, AS ID, app IDs, and hostnames throughout. Needs `secrets/agent-private-key.json` (generate an RS256 JWK — see the sis-demo README-AGENT for the jose one-liner; jose is installed in this repo's node_modules too), `OKTA_OIDC_CLIENT_ID`, `AGENT_ID`, `RESOURCE_AS_ISSUER`, `AGENT_TOKEN_SCOPE=sdap.logs.read sdap.users.read sdap.users.manage sdap.act`.

### 2e. MCP server (optional)

Register in the engineer's MCP client (Claude Desktop / Cursor):

```json
{ "mcpServers": { "sdap": {
  "command": "node",
  "args": ["/absolute/path/to/super-duper-admin-portal/mcp-server/index.js"],
  "cwd": "/absolute/path/to/super-duper-admin-portal"
} } }
```

It shells the same env config — `.env.local` must be present in `cwd`.

## Phase 3 — Deploying (EC2 or similar)

- Security group: expose **only 80/443**; reverse proxy (nginx/Caddy/ALB) in front. Two workable shapes:
  1. **Single origin (recommended):** one hostname; proxy `/api/*` → `127.0.0.1:3201`, everything else → `127.0.0.1:3200`. Build with `VITE_API_BASE` **empty**.
  2. **Split origins:** `admin.your-domain.com` → :3200 and `admin-api.your-domain.com` → :3201. Build with `VITE_API_BASE=https://admin-api.your-domain.com`, set `WEB_ORIGIN=https://admin.your-domain.com` and `COOKIE_DOMAIN=.your-domain.com`.
- `npm run build` **after** finalizing `VITE_API_BASE` (it's compile-time), then `npm run pm2:start` (ecosystem runs `sdap-web` + `sdap-api`; it preloads `lib/dnsBootstrap.js`, which pins DNS to 1.1.1.1/8.8.8.8 — override with `DNS_SERVERS` if your VPC requires internal resolvers).
- `DEMO_AUTH_BYPASS=false` before anything is reachable beyond localhost. This portal wields an admin-scoped Okta token — treat the host as sensitive infrastructure.
- `.data/` (sessions + access-request cache) must persist across deploys; set `SDAP_DATA_DIR` to a stable path like `/var/lib/sdap` if the checkout is replaced on deploy.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| SPA loads but every API call fails | `VITE_API_BASE` wrong at build time (it's baked in — rebuild), or CORS: origin not in allowlist → set `WEB_ORIGIN`. |
| `/api/*` 404 from the web port | Expected — `web-server.js` doesn't proxy. Route `/api` to :3201 at the reverse proxy, or use `VITE_API_BASE`. |
| Chat replies with model/key errors | `GET /api/available-models` to see which providers registered; check the corresponding key. |
| Okta tools return 401/403 | SSWS token expired/insufficient permissions — recreate per 2a. |
| Login redirect loops on split origins | `COOKIE_DOMAIN` unset (or domains don't share a parent) — the session cookie set on the API host must be sent from the web host. |
| Okta/LLM calls time out on the host but curl works | DNS — `dnsBootstrap` pins 1.1.1.1/8.8.8.8; set `DNS_SERVERS` for VPC-internal resolvers. |

## File map (orientation)

```
api-server.js                    all API routes (chat, okta proxy, auth, actions)
web-server.js                    static dist/ server (no /api proxy)
lib/oktaAccessRequests.js        OIG Access Requests client
lib/executeAccessRequestAction.js  post-approval action execution
lib/agentTokenExchange.js        ID-JAG token exchange
lib/oidc.js                      OIDC login (PKCE) + id_token verify
lib/dataDir.js                   .data/ resolution (SDAP_DATA_DIR)
mcp-server/index.js              stdio MCP server
docs/okta-xaa-handoff.md         worked XAA example (author's IDs — substitute)
docs/access-request-flo-contract.md  approval flow contract
```
