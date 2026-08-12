// Keep a fresh OIDC id_token in the express session for XAA / vaulted-secret exchanges.
// Session cookies last 12h but Okta id_tokens typically expire after ~1h.

import { decodeJwt } from 'jose'
import { refreshOidcTokens } from './oidc.js'

const EXPIRY_SKEW_SEC = 60

export function idTokenExpiresAt(idToken) {
  if (!idToken) return null
  try {
    const { exp } = decodeJwt(idToken)
    return typeof exp === 'number' ? exp * 1000 : null
  } catch {
    return null
  }
}

export function isIdTokenExpired(idToken, skewSec = EXPIRY_SKEW_SEC) {
  const expMs = idTokenExpiresAt(idToken)
  if (!expMs) return true
  return Date.now() >= expMs - skewSec * 1000
}

export function sessionIdTokenStatus(session) {
  const idToken = session?.id_token
  if (!idToken) return { present: false, expired: true, expiresAt: null }
  const expiresAt = idTokenExpiresAt(idToken)
  return {
    present: true,
    expired: isIdTokenExpired(idToken),
    expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
  }
}

/**
 * Return a valid id_token from the session, refreshing with refresh_token when possible.
 * @throws Error with code SESSION_ID_TOKEN_EXPIRED when re-login is required
 */
export async function ensureSessionIdToken(req) {
  const idToken = req.session?.id_token
  if (!idToken) {
    const err = new Error('No OIDC id_token — sign in via /api/oidc/login')
    err.code = 'SESSION_NO_ID_TOKEN'
    throw err
  }

  if (!isIdTokenExpired(idToken)) {
    return idToken
  }

  const refreshToken = req.session?.refresh_token
  if (!refreshToken) {
    const err = new Error(
      'Your Okta sign-in token expired (~1 hour). Sign out and sign in again to use agent tools ' +
      '(secret retrieval, delegated Okta API, access-request fulfillment).'
    )
    err.code = 'SESSION_ID_TOKEN_EXPIRED'
    throw err
  }

  const tokens = await refreshOidcTokens({ refreshToken })
  req.session.id_token = tokens.id_token
  if (tokens.refresh_token) req.session.refresh_token = tokens.refresh_token
  if (tokens.access_token) req.session.access_token = tokens.access_token
  req.session.id_token_expires_at = idTokenExpiresAt(tokens.id_token)
    ? new Date(idTokenExpiresAt(tokens.id_token)).toISOString()
    : null

  await new Promise((resolve, reject) => {
    req.session.save(err => (err ? reject(err) : resolve()))
  })

  return tokens.id_token
}
