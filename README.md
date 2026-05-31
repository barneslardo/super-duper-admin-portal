# Super Duper Admin Portal

**Chat-first admin interface for Okta administrators on sledai.oktapreview.com**

Dark theme with orange accent. Built for demo / internal use. Chat with LLMs that understand your Okta org, trigger safe admin actions (via approval workflows), and expose everything via REST + MCP.

## Ports (Important on this machine)

This host already has **many** services running. We have deliberately chosen:

- **Web (SPA)**: `3200`
- **API**: `3201`

These ports were confirmed free when the project was set up.  
If they ever become conflicted, just change `PORT` and `API_PORT` in `.env.local` (and restart).

All internal calls from the frontend use relative URLs (`/api/...`), so no other code changes are needed when you change ports.

## Features (v0.1)

- **Enhanced chat** with conversation history (localStorage), model selector (GPT-4o / Claude 3.5 / Grok), markdown, copy buttons, suggested Okta prompts
- **LLM proxy** (server-side keys) with a strong Okta admin system prompt
- **Quick Actions** panel that calls backend REST endpoints (list users, failed logins, suspend, MFA reset)
- **Okta Management API proxy** at `/api/okta/*` (SSWS token stays on server)
- **pm2** deployment with separate resilient web + api processes
- **MCP server** so agents (Claude Desktop, Cursor, etc.) can call the same tools
- **SAML 2.0 ready** (placeholder) – intended to be launched from the Okta dashboard with JIT provisioning

## Quick Start

```bash
cd ~/oktaAdminApp

# 1. Configure environment
cp .env.example .env.local
# Edit .env.local and add at least one LLM key + OKTA_API_TOKEN

# 2. Install (already done, but if needed)
npm install

# 3. Development (two terminals or use the helper)
npm run dev          # Vite frontend on 5173
npm run dev:api      # API on 3001

# Or everything together:
npm run dev:full

# 4. Production build + pm2
npm run build
npm run pm2:start

# Useful pm2 commands
npm run pm2:status
npm run pm2:logs
npm run pm2:restart
npm run pm2:stop
```

The web UI will be on **http://your-host:3200** (API on 3201).  
Both are configurable via `PORT` / `API_PORT` in `.env.local`.

## Environment Variables (.env.local)

See [.env.example](.env.example). Minimum for chat to work:

- `OPENAI_API_KEY` (or ANTHROPIC_API_KEY / GROK_API_KEY)
- `OKTA_API_TOKEN` (SSWS token with at least read users + logs)
- `OKTA_ORG_URL=https://sledai.oktapreview.com`

`DEMO_AUTH_BYPASS=true` lets you use the portal immediately without SAML.

## SAML 2.0 Integration (Okta Dashboard Launch + JIT)

Goal: Users assigned the app in Okta get automatically logged into the portal as full admins (via SAML JIT).

### High-level steps

1. In sledai.oktapreview.com admin console:
   - Applications → Create App Integration → SAML 2.0
   - App name: `Super Duper Admin Portal`
   - Single sign-on URL (ACS): `https://your-portal-host:3201/api/saml/acs` (POST)
   - Audience URI (SP Entity ID): `super-duper-admin-portal` (or your choice)
   - Attribute statements (example):
     - `email` → `user.email`
     - `firstName` → `user.firstName`
     - `lastName` → `user.lastName`
     - `login` → `user.login`

2. After saving, download the **Identity Provider metadata** (or copy the X.509 cert + SSO URL).

3. Update `.env.local`:
   ```
   SAML_ENTRY_POINT=...
   SAML_ISSUER=...
   SAML_CERT=-----BEGIN CERTIFICATE-----...
   ```

4. Implement the ACS handler in `api-server.js` using `samlify` (package already installed). The current endpoint returns 501.

5. In the Okta app assignment, turn on **SAML JIT provisioning** (or use a separate provisioning integration).

6. Set `DEMO_AUTH_BYPASS=false` and restart the api process.

When complete, the app will appear in users' Okta dashboard and they will land already authenticated.

## Architecture

```
Browser (SPA - Vite React)
    ↓
web-server.js (port 3200)          ← serves dist/, SPA fallback
    ↓ (same origin calls)
api-server.js (port 3201)
    ├── /api/chat          → LLM proxy (OpenAI/Anthropic/Grok)
    ├── /api/okta/*        → Okta Mgmt API (SSWS)
    ├── /api/actions/*     → Fire approval webhooks / workflows
    └── /api/saml/acs      → SAML handler (future)
    + express-session (demo + future real auth)

pm2 (ecosystem.config.cjs)
    ├── sdap-web
    └── sdap-api   (both autorestart, resilient)

mcp-server/        (stdio MCP tools for agents)
```

## Adding Real Destructive Action Approvals

In `api-server.js` the `/api/actions/:actionId` endpoint already accepts an `APPROVAL_WEBHOOK_URL`.

Point it at an Okta Workflow (or any HTTPS endpoint) that:
- Receives the action + user + reason
- Creates an access request / approval task in Okta
- Only on approval does it call back or use the SSWS token to perform the real change

## MCP Usage (Claude Desktop example)

```json
{
  "mcpServers": {
    "sdap": {
      "command": "node",
      "args": ["/home/skylar/oktaAdminApp/mcp-server/index.js"],
      "cwd": "/home/skylar/oktaAdminApp"
    }
  }
}
```

Tools exposed: `sdap_chat`, `sdap_trigger_action`, `sdap_okta_request`.

## Deploy Notes (pm2)

- Always run `npm run build` before `pm2 start`
- The two processes are independent — you can restart just the api when you change keys
- Logs: `npm run pm2:logs`
- To run on a real server, put an nginx reverse proxy in front (example configs exist in sibling projects)

## Next Steps / Roadmap

- Full SAML + proper session + SLO
- Streaming LLM responses (SSE)
- Real Okta data in the Users tab
- Function calling in the chat so the LLM can directly propose actions
- Audit logging of all admin actions

---

**This is a demo application.** Treat the Okta token and LLM keys with care. Do not expose publicly without proper auth + network controls.
