// OIDC authorization-code login for human admins (PKCE + private_key_jwt client auth).
//
// Produces the user's id_token, which is the subject_token for hop 1 of the agent token
// exchange (see agentTokenExchange.js). Uses the org authorization server's discovery doc.
//
// Env (read lazily): OKTA_ORG_URL, OKTA_OIDC_CLIENT_ID, OKTA_OIDC_REDIRECT_URI, OIDC_SCOPES.

import { createHash, randomBytes } from 'crypto'
import { jwtVerify, createRemoteJWKSet } from 'jose'
import { signClientAssertion } from './agentTokenExchange.js'

function reqEnv(name) {
  const v = process.env[name]
  if (!v) throw new Error(`${name} is not configured. See docs/okta-xaa-runbook.md.`)
  return v
}

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// ---- discovery (cached) ----
let _meta = null
async function discovery() {
  if (_meta) return _meta
  const orgUrl = reqEnv('OKTA_ORG_URL').replace(/\/$/, '')
  const res = await fetch(`${orgUrl}/.well-known/openid-configuration`, { headers: { Accept: 'application/json' } })
  if (!res.ok) throw new Error(`OIDC discovery failed ${res.status}`)
  _meta = await res.json()
  return _meta
}

/** Generate a PKCE verifier + S256 challenge. */
export function makePkce() {
  const verifier = base64url(randomBytes(32))
  const challenge = base64url(createHash('sha256').update(verifier).digest())
  return { verifier, challenge }
}

/** Build the authorization-endpoint URL to redirect the user to. */
export async function buildAuthUrl({ state, nonce, codeChallenge }) {
  const meta = await discovery()
  const u = new URL(meta.authorization_endpoint)
  u.searchParams.set('client_id', reqEnv('OKTA_OIDC_CLIENT_ID'))
  u.searchParams.set('response_type', 'code')
  u.searchParams.set('scope', process.env.OIDC_SCOPES || 'openid profile email')
  u.searchParams.set('redirect_uri', reqEnv('OKTA_OIDC_REDIRECT_URI'))
  u.searchParams.set('state', state)
  u.searchParams.set('nonce', nonce)
  u.searchParams.set('code_challenge', codeChallenge)
  u.searchParams.set('code_challenge_method', 'S256')
  return u.toString()
}

/** Exchange the authorization code for tokens (id_token + access_token). */
export async function exchangeCode({ code, codeVerifier }) {
  const meta = await discovery()
  const tokenEndpoint = meta.token_endpoint
  const clientAssertion = await signClientAssertion({
    clientId: reqEnv('OKTA_OIDC_CLIENT_ID'),
    audience: tokenEndpoint,
  })

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: reqEnv('OKTA_OIDC_REDIRECT_URI'),
    code_verifier: codeVerifier,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion,
  })

  const res = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
    body,
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(`OIDC code exchange failed ${res.status}: ${JSON.stringify(data)}`)
  return data
}

/** Verify the id_token signature/claims and return its payload. */
export async function verifyIdToken(idToken, expectedNonce) {
  const meta = await discovery()
  const jwks = createRemoteJWKSet(new URL(meta.jwks_uri))
  const { payload } = await jwtVerify(idToken, jwks, {
    issuer: meta.issuer,
    audience: reqEnv('OKTA_OIDC_CLIENT_ID'),
  })
  if (expectedNonce && payload.nonce !== expectedNonce) throw new Error('OIDC nonce mismatch')
  return payload
}
