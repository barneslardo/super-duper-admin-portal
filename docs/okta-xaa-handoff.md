# Okta Cross App Access (XAA / ID-JAG) — Status & Handoff

_Last updated: 2026-05-31. Supersedes the original `okta-xaa-runbook.md`._

## TL;DR — current state

**The "Okta secures AI" showpiece works end-to-end.** A human admin signs in via OIDC, and
the in-app agent calls the Okta Management API **on behalf of that admin**, brokered through a
two-hop token exchange (ID-JAG), with the effective scope minted by a custom authorization
server. No static token sits in the request path.

Verified working today:
```
GET /api/agent/okta/logs?since=…   → 200 + live Okta System Log
GET /api/agent/okta/users?limit=1  → 200 + live Okta users
```
Both run: human `id_token` → **hop 1** (ID-JAG @ org AS) → **hop 2** (access token @ custom AS)
→ scope-intersection check → SEAM call to Okta with the org SSWS token.

**What's NOT yet proven:** the *deny* path. We tested as a super-admin who gets every scope, so
we demonstrated the plumbing but not the "human ∩ agent" constraint. See **Next steps**.

---

## The architecture

### The flow (two hops, both `POST /oauth2/v1/token`)
```
Human ──OIDC (PKCE + private_key_jwt)──▶ app gets id_token
   Hop 1  (ORG AS  /oauth2/v1/token):                  id_token + agent client_assertion
                                                        grant=token-exchange, requested_token_type=id-jag,
                                                        audience=<custom AS issuer>          → ID-JAG (~300s)
   Hop 2  (CUSTOM AS /oauth2/<id>/v1/token):            ID-JAG + agent client_assertion
                                                        grant=jwt-bearer                     → access_token
   App enforces granted scope ⊇ required, then calls Okta (SEAM) with that authorization.
```

### Who's who in Okta (org `sledai.oktapreview.com`)
| Thing | ID / value | Role |
|---|---|---|
| **Human sign-on app** (OIDC) | `0oazd6ro1qbcFDGB21d7` | Humans log in here → `id_token`. Also the agent's "user sign-on" credential. `private_key_jwt`. |
| **AI agent** (UD registration) | `wlpzd73wrostoEGIn1d7` | The XAA principal. **Its agent-ID *is* the client_id** used to authenticate both hops. |
| **Custom authorization server** (resource) | `auszdlcnxzbhKo6OJ1d7` | Issuer `https://sledai.oktapreview.com/oauth2/auszdlcnxzbhKo6OJ1d7`; audience `https://ai-admin-api.skylarbarnes.com/mcp`. Mints the effective `sdap.*` scope. |
| **Resource-connection client** | `0oaze1b3lt9nq4fxG1d7` ("SDAP Agent Resource Client") | Confidential `client_credentials` app created so the agent's **Resource Connection** had a `client_id`+`secret` to register. |
| **Agent signing key** | kid `846981c5de57e85875ce00f132eadb47` | Generated on the agent; **private** JWK in `secrets/agent-private-key.json`. Public copy ALSO added to app `0oazd6…` JWKS (one key serves login + hops). |
| **Old signing key** | kid `q6xPvjQY7Ryhn5a4OR9vE75xz0Gout8MBj4kD4cFX30` | Superseded; still registered on app `0oazd6…` (harmless). No longer used to sign. |

### Custom AS (`auszdlcnxzbhKo6OJ1d7`) config
- **Scopes:** `sdap.logs.read`, `sdap.users.read`, `sdap.users.manage`, `sdap.act`.
- **Claim:** `sdap_entitlement` — Groups, regex `^sdap-`, in **Access Token**, **Any scope**. Carries the human's entitlement for the intersection.
- **Access policy:** assigned to the agent/connection client(s); group-conditioned rules; grant type **JWT Bearer only** (hop 2's grant). Each rule caps which `sdap.*` it may mint → human side of the intersection.

### App / hosting
- **API** `ai-admin-api.skylarbarnes.com` → `api-server.js`, port `3201`, pm2 process **`sdap-api`**. Behind Cloudflare.
- **UI** `ai-admin.skylarbarnes.com` → `web-server.js` serving `dist/`, pm2 process **`sdap-web`**. Build with `npm run build`.
- **Okta tile → Initiate login URI:** `https://ai-admin-api.skylarbarnes.com/api/oidc/login`
- **Sign-in redirect URI (on app `0oazd6…`):** `https://ai-admin-api.skylarbarnes.com/api/oidc/callback`

### Code
- `lib/oidc.js` — human OIDC login (discovery + PKCE + `private_key_jwt` + `verifyIdToken`).
- `lib/agentTokenExchange.js` — `signClientAssertion`, `getIdJag` (hop 1), `exchangeIdJagForAccessToken` (hop 2), `getDelegatedAccessToken`. **Both hops sign as `AGENT_CLIENT_ID`** (falls back to `OKTA_OIDC_CLIENT_ID`).
- `api-server.js` — routes: `/api/oidc/login`, `/api/oidc/callback`, `/api/agent/okta/*` (the on-behalf-of proxy with the `requiredScopeFor` intersection gate), `/api/okta/*` (legacy SSWS proxy), `/api/logout`, `/api/auth/me`, `/api/chat` (LLM proxy with agentic tool-use loop — see below).
- **`/api/chat` is agentic** — the system prompt tells the model it is a registered Okta AI agent with real delegated access, and all three providers (Anthropic, Grok, OpenAI) are wired with a `fetch_okta_data` tool-use loop (up to 5 rounds). When the admin asks for logs or users, the model calls `fetch_okta_data(path)` → the handler executes `getDelegatedAccessToken` + the Okta SEAM call server-side, returns the data, and the model analyses and responds. The signed-in admin's name/email is injected into the system prompt per request.
- `secrets/agent-private-key.json` — agent signing key (git-ignored).
- `secrets/app-0oazd6ro1qbcFDGB21d7.backup.json` — pre-change backup of the sign-on app.

### `.env.local` keys that matter
```
OKTA_ORG_URL=https://sledai.oktapreview.com
OKTA_OIDC_CLIENT_ID=0oazd6ro1qbcFDGB21d7          # human login (app)
OKTA_OIDC_REDIRECT_URI=https://ai-admin-api.skylarbarnes.com/api/oidc/callback
OIDC_SCOPES=openid profile email
AGENT_CLIENT_ID=wlpzd73wrostoEGIn1d7             # agent = OAuth client for BOTH hops
AGENT_TOKEN_SCOPE=sdap.logs.read sdap.users.read sdap.users.manage sdap.act
RESOURCE_AS_ISSUER=https://sledai.oktapreview.com/oauth2/auszdlcnxzbhKo6OJ1d7   # hop-1 audience + hop-2 base
POST_LOGIN_REDIRECT=https://ai-admin.skylarbarnes.com/    # was SAML_SUCCESS_REDIRECT
OKTA_API_TOKEN=<SSWS>                             # SEAM call; has okta.logs.read + okta.users.read
# AGENT_PRIVATE_KEY_PATH defaults to ./secrets/agent-private-key.json
# SAML_* are commented out (decommissioned)
```

---

## Lessons learned (the things that cost us time)

1. **The agent — not the sign-on app — is the OAuth client for the hops.** Sign the
   `client_assertion` with `iss`/`sub` = the **agent ID** (`wlpzd73…`), using the
   **agent-registration key**. Signing as the app `0oazd6…` got past client auth but the org AS
   refused to mint an ID-JAG (`requested_token_type … not supported`). Fixed via `AGENT_CLIENT_ID`.
2. **"Token Exchange" is not a console checkbox.** Add `urn:ietf:params:oauth:grant-type:token-exchange`
   to the app's `grant_types` via the **Apps API** (PUT the app). It won't appear in the UI grant-type picker.
3. **ID-JAG needs the resource *registered*.** A bare custom AS isn't enough — the org AS only
   mints an id-jag for a resource the agent is connected to. Register it under the agent's
   **Resource Connections** (we used the custom AS's `…/v1/authorize` + `…/v1/token` endpoints).
4. **The resource connection wanted a `client_id`+`client_secret`.** Our app and agent are
   key-based (no secret), so we created a dedicated confidential `client_credentials` service app
   (`0oaze1b3…`). That client likely must be allowed by the custom AS access policy (we set the
   connection to "allow all scopes" + ensured policy coverage).
5. **Adding our public key via the agent UI didn't work; *generating* a key on the agent did.**
   Okta showed the private key once; we saved it to `secrets/agent-private-key.json`. Because the
   code uses **one** key file for both human login (app) and the hops (agent), we also added that
   key's **public** half to the app `0oazd6…` JWKS via API so both validate.
6. **App signing keys live under `settings.oauthClient.jwks`**, not `credentials.oauthClient.jwks`.
7. **In-memory sessions** (express-session default `MemoryStore`) → **every API restart logs
   everyone out.** After any `pm2 restart sdap-api`, the human must re-login before agent calls work
   (the flow needs `req.session.id_token`). Consider a persistent store later.
8. **Initiate login URI must be the `/api/oidc/login` route**, not the host root. A root 404 also
   produced a confusing CSP error (Express's default 404 page sets `default-src 'none'`, which
   blocked Cloudflare's injected beacon script). Fixing the URI fixed both.
9. **The two subdomains share the same site**, so the session cookie works cross-origin with
   `sameSite=none; secure` + `app.set('trust proxy', 1)` (both already in place; `NODE_ENV=production`
   is set in `ecosystem.config.cjs`).

---

## What we accomplished today
- Replaced SAML with **OIDC** human login (PKCE + `private_key_jwt`) and got the Okta dashboard
  tile launching it.
- **Fully decommissioned SAML**: removed `samlify`, `initSaml`, `/api/saml/*` routes (logout →
  `/api/logout`); frontend sign-in button → `/api/oidc/login`; `SAML_SUCCESS_REDIRECT` →
  `POST_LOGIN_REDIRECT`; rebuilt + redeployed the UI. (`samlify` still in `package.json` — optional `npm uninstall`.)
- Stood up the entire XAA chain: token-exchange grant, agent-as-client identity, regenerated
  signing key, resource-server connection + confidential client, custom AS scopes/claim/policy.
- **Confirmed the on-behalf-of flow returns live Okta data** (logs + users).

---

## Where we left off / NEXT STEPS (in priority order)

### 1. Prove the *deny* path — the actual security story  ⬅ highest value
We tested as **super-admin `skylar.barnes`**, who gets all `sdap.*`, so everything returned `200`.
To demonstrate "human ∩ agent":
- Create/identify a **restricted test admin** — e.g. a user in **only** the `sdap-log-reader`
  group (assuming the policy maps that group → `sdap.logs.read` only).
- Log in as them, then:
  - `GET /api/agent/okta/logs`  → expect **200**
  - a `sdap.act` / `sdap.users.manage` path → expect **403 `{need, granted}`**
- Also confirm the access token's **granted scope** reflects the user's entitlement, not just the
  agent's full grant. (We set the resource connection to "allow all scopes," so the *intersection*
  must come from the **custom AS access policy** reading the `sdap_entitlement` claim. Verify a
  log-reader's token does NOT contain `sdap.act`.)
- Note: `/api/agent/okta/*` only surfaces `granted` on a 403. To inspect granted scope on success,
  temporarily log `delegated.scope` in `api-server.js` or decode the access token.

### 2. The consent moment
Set the custom AS `sdap.*` scopes to **User consent = Required** (+ display name/description) for
the on-stage "user authorizes the agent" beat. Do this *after* confirming the flow, and remember the
back-channel exchange is silent — consent is pre-granted via the resource connection, not prompted
mid-exchange.

### 3. Optional cleanup / hardening
- Flip the SEAM call in `/api/agent/okta/*` from the **SSWS** token to the brokered
  `delegated.access_token` (true XAA, removes the static credential). See the SEAM comment in `api-server.js`.
- `npm uninstall samlify @authenio/samlify-xsd-schema-validator`.
- Consider a persistent session store so deploys don't log everyone out.

---

## How to pick it up (operational quickstart)

```bash
# 1. Confirm services are up
pm2 list                       # expect sdap-api (3201) + sdap-web online
curl -s http://localhost:3201/api/health
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3201/api/oidc/login   # expect 302

# 2. Log in (browser): click the Okta tile, OR visit
#    https://ai-admin-api.skylarbarnes.com/api/oidc/login
#    Grab the connect.sid cookie (DevTools → Application → Cookies → ai-admin-api…)
#    NOTE: any `pm2 restart sdap-api` wipes the session → must re-login.

# 3. Drive the on-behalf-of call with that cookie
CK='connect.sid=<paste>'
curl -s -b "$CK" "http://localhost:3201/api/agent/okta/logs?since=2026-05-30T00:00:00Z"
curl -s -b "$CK" "http://localhost:3201/api/agent/okta/users?limit=1"
```

**Outcome map:** `200` + data = full chain worked. `403 {need, granted}` = intersection denied
(the security story). `502 Token exchange failed` + `detail` = a hop failed (the `detail` names hop
1 vs 2 and the Okta error). `401` = no OIDC session (re-login).

**Useful Okta API reads** (token in `.env.local` `OKTA_API_TOKEN`):
- App: `GET /api/v1/apps/0oazd6ro1qbcFDGB21d7` (grant_types, `settings.oauthClient.jwks`)
- Custom AS: `GET /api/v1/authorizationServers/auszdlcnxzbhKo6OJ1d7`
- Org features: `GET /api/v1/features` (Cross App Access = ENABLED)
