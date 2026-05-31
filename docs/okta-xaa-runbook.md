# Okta Cross App Access (ID-JAG) — Setup Runbook

The "Okta secures AI" showpiece: the in-app agent acts **on behalf of the signed-in admin**,
with effective permission = the **intersection** of (agent grants) ∩ (human entitlements),
enforced by a custom authorization server's policy.

Flow (two hops, both `POST /oauth2/v1/token`):

```
Human ──OIDC login──▶ app gets id_token
        Hop 1 (org AS):     id_token  + agent client_assertion ─▶ ID-JAG        (grant=token-exchange, requested_token_type=id-jag)
        Hop 2 (custom AS):  ID-JAG    + agent client_assertion ─▶ access_token  (grant=jwt-bearer)
        app calls the resource with access_token  (scope = human ∩ agent)
```

Code already scaffolded:
- `lib/oidc.js` — human OIDC login (PKCE + private_key_jwt)
- `lib/agentTokenExchange.js` — hop 1 + hop 2 + client_assertion signing
- `api-server.js` — routes `/api/oidc/login`, `/api/oidc/callback`, `/api/agent/okta/*`
- `secrets/agent-private-key.json` — agent signing key (kid `q6xPvjQY…`), git-ignored

## What YOU configure in the Okta admin console

> Fill `RESOURCE_AS_ISSUER` in `.env.local` once step 3 is done, then restart the API.

1. **Agent key** — confirm the public JWK (kid `q6xPvjQY…`) is registered on the OIDC app /
   UD agent. The matching private key is already in `secrets/agent-private-key.json`. (Rotate
   if you ever need to: generate a new keypair, upload the public JWK, replace the file.)

2. **OIDC sign-in** on app `0oazd6ro1qbcFDGB21d7`:
   - Grant type: Authorization Code (+ Token Exchange).
   - Client auth: **private_key_jwt** (public key from step 1).
   - Sign-in redirect URI: `https://ai-admin-api.skylarbarnes.com/api/oidc/callback`
     (add `http://localhost:3201/api/oidc/callback` for local).
   - Scopes: `openid profile email`.

3. **Custom authorization server** (the resource app's AS):
   - **Audience = your MCP/API endpoint** (e.g. `https://ai-admin-api.skylarbarnes.com/mcp`).
   - Define scopes: `sdap.logs.read`, `sdap.users.read`, `sdap.users.manage`, `sdap.act`.
   - Add a **claim** carrying the user's admin entitlement (e.g. group/role) into the token.
   - **Access policies = the intersection:** only issue `sdap.*` scopes when BOTH the
     agent is granted them AND the user's entitlement claim allows them. (e.g. a "log reader"
     admin can never receive `sdap.act`.)
   - Copy the issuer URL → `RESOURCE_AS_ISSUER` in `.env.local`.

4. **Cross App Access / resource connection** — connect the agent (requesting app) to the
   resource app; grant the agent its allowed scopes. Enable the **consent-required** resource
   type for the on-stage "user authorizes the agent" moment.

5. **Okta Management API access for the backend** (so the SEAM call in `/api/agent/okta/*`
   works today): grant the app `okta.logs.read` + `okta.users.read` and assign a **least-priv
   custom admin role**. Longer term, expose the Mgmt API as an XAA resource and call it with
   the brokered `delegated.access_token` instead of the SSWS token (see the SEAM comment in
   `api-server.js`).

## Test sequence

1. `pm2 restart sdap-api` (or `API_PORT=3299 node api-server.js` for an isolated run).
2. Browse `/api/oidc/login` → authenticate → should land back authenticated (`/api/auth/me`
   shows `authMethod: "oidc"`).
3. `GET /api/agent/okta/logs?since=...` → should run both hops and return logs **iff** the
   signed-in admin's entitlement grants `sdap.logs.read`; otherwise `403` with the
   `need`/`granted` intersection detail.

## Cleanup
- The old inline private-key JSON block still sitting in `.env.local` (under the
  `# JWT Token for API Actions` comment) is now superseded by `secrets/agent-private-key.json`
  and can be deleted.
