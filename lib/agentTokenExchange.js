// Agent token exchange for "on-behalf-of" access (Okta Cross App Access / ID-JAG).
//
// Implements the two-hop flow from Okta's "Set up AI agent token exchange" guide:
//   Hop 1 (org authorization server):  user id_token  ->  ID-JAG
//   Hop 2 (custom authorization server): ID-JAG       ->  access token for the resource
//
// The agent authenticates to both token endpoints with private_key_jwt, signed by the
// agent's registered key (secrets/agent-private-key.json — kid must match the public JWK
// registered on the Okta app/agent).
//
// NOTE: env is read lazily inside functions (not at import time) because api-server.js
// calls dotenv.config() in its module body, which runs AFTER imports are resolved.

import { SignJWT, importJWK } from 'jose'
import { readFileSync } from 'fs'
import { randomUUID } from 'crypto'

function reqEnv(name) {
  const v = process.env[name]
  if (!v) {
    throw new Error(
      `${name} is not configured yet. See docs/okta-xaa-runbook.md for the Okta-side setup ` +
      `(custom authorization server, scopes/claims, resource connection).`
    )
  }
  return v
}

// ---- signing key (cached) ----
let _key = null
let _jwk = null
async function getSigningKey() {
  if (_key) return { key: _key, jwk: _jwk }
  const path = process.env.AGENT_PRIVATE_KEY_PATH || './secrets/agent-private-key.json'
  _jwk = JSON.parse(readFileSync(path, 'utf8'))
  if (!_jwk.d) throw new Error(`Agent key at ${path} has no private component (d) — it's a public key, not a signing key.`)
  _key = await importJWK(_jwk, 'RS256')
  return { key: _key, jwk: _jwk }
}

/**
 * Build a private_key_jwt client assertion for authenticating the agent to a token endpoint.
 * @param {object} opts
 * @param {string} opts.clientId  - the requesting app's client_id (iss + sub)
 * @param {string} opts.audience  - the token endpoint URL the assertion is presented to
 */
export async function signClientAssertion({ clientId, audience }) {
  const { key, jwk } = await getSigningKey()
  return await new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', kid: jwk.kid })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime('5m')
    .setJti(randomUUID())
    .sign(key)
}

/**
 * HOP 1 — exchange the signed-in user's id_token for an ID-JAG at the ORG auth server.
 * Returns the ID-JAG string (the response's access_token, issued_token_type=...:id-jag).
 */
export async function getIdJag({ idToken, scope }) {
  // The requesting client for XAA/ID-JAG is the AGENT (its own client_id), signed with the
  // agent-registration key — NOT the human sign-on app. Falls back to the sign-on app only
  // if AGENT_CLIENT_ID is unset.
  const clientId = process.env.AGENT_CLIENT_ID || reqEnv('OKTA_OIDC_CLIENT_ID')
  const orgUrl = reqEnv('OKTA_ORG_URL').replace(/\/$/, '')
  const tokenEndpoint = `${orgUrl}/oauth2/v1/token`
  const audience = reqEnv('RESOURCE_AS_ISSUER') // the resource app's authorization server

  const clientAssertion = await signClientAssertion({ clientId, audience: tokenEndpoint })

  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: idToken,
    subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
    requested_token_type: 'urn:ietf:params:oauth:token-type:id-jag',
    audience,
    scope: scope || process.env.AGENT_TOKEN_SCOPE || '',
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion,
  })

  const res = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
    body,
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(`ID-JAG exchange (hop 1) failed ${res.status}: ${JSON.stringify(data)}`)
  return data.access_token // the ID-JAG
}

/**
 * HOP 2 — exchange the ID-JAG for a resource access token at the CUSTOM auth server.
 * Returns the full token response ({ access_token, scope, token_type, expires_in, ... }).
 */
export async function exchangeIdJagForAccessToken({ idJag }) {
  // Hop 2 also authenticates as the AGENT (the requesting client), not the sign-on app.
  const clientId = process.env.AGENT_CLIENT_ID || reqEnv('OKTA_OIDC_CLIENT_ID')
  const issuer = reqEnv('RESOURCE_AS_ISSUER').replace(/\/$/, '')
  const tokenEndpoint = `${issuer}/v1/token`

  const clientAssertion = await signClientAssertion({ clientId, audience: tokenEndpoint })

  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: idJag,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion,
  })

  const res = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
    body,
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(`Access-token exchange (hop 2) failed ${res.status}: ${JSON.stringify(data)}`)
  return data
}

/**
 * Full on-behalf-of flow: id_token -> ID-JAG -> resource access token.
 * The returned token's `scope` reflects the effective (human ∩ agent) grant enforced by
 * the custom authorization server's access policy.
 */
export async function getDelegatedAccessToken({ idToken, scope }) {
  const idJag = await getIdJag({ idToken, scope })
  return await exchangeIdJagForAccessToken({ idJag })
}

/**
 * OPA vaulted-secret retrieval (Okta "secret" resource type — single hop at the ORG auth server).
 *
 * Exchanges the signed-in admin's id_token for a secret that is connected to this agent as a
 * Resource Connection in Okta Privileged Access. Per Okta's "AI agent token exchange (secret)"
 * guide this targets the ORG authorization server (NOT the custom AS) and asks for
 * requested_token_type = urn:okta:params:oauth:token-type:vaulted-secret.
 *
 * Does NOT throw on a non-2xx from Okta — returns { status, ok, data } so callers can surface
 * Okta's exact error (useful while converging on the right `resource` value).
 *
 * @param {object} opts
 * @param {string} opts.idToken    - the human admin's id_token (the subject_token)
 * @param {string} opts.resource   - resource-connection identifier configured for the secret
 * @param {string} [opts.scope]    - optional scope, if the connection requires one
 * @param {string} [opts.audience] - optional audience param, if the connection requires one
 * @returns {Promise<{status:number, ok:boolean, data:object}>}
 */
export async function getVaultedSecret({ idToken, resource, scope, audience }) {
  if (!idToken) throw new Error('getVaultedSecret: idToken (subject_token) is required')
  if (!resource) throw new Error('getVaultedSecret: resource (secret resource-connection id) is required')

  const clientId = process.env.AGENT_CLIENT_ID || reqEnv('OKTA_OIDC_CLIENT_ID')
  const orgUrl = reqEnv('OKTA_ORG_URL').replace(/\/$/, '')
  const tokenEndpoint = `${orgUrl}/oauth2/v1/token`

  const clientAssertion = await signClientAssertion({ clientId, audience: tokenEndpoint })

  const params = {
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: idToken,
    subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
    requested_token_type: 'urn:okta:params:oauth:token-type:vaulted-secret',
    resource,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion,
  }
  if (scope) params.scope = scope
  if (audience) params.audience = audience

  const res = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
    body: new URLSearchParams(params),
  })
  const data = await res.json().catch(() => ({}))
  return { status: res.status, ok: res.ok, data }
}
