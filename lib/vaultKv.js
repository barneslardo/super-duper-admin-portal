// Optional HashiCorp Vault KV v2 reader for secrets (e.g. Okta tenant API keys).
//
// Env:
//   VAULT_ADDR          e.g. https://vault.example.com:8200
//   VAULT_TOKEN         client token with read on the mount
//   VAULT_KV_MOUNT      defaults to "kv"  (secret at /v1/kv/data/{path})
//   VAULT_KV_PATH       e.g. Okta-Tenant  (maps to /v1/kv/data/Okta-Tenant)

export async function readKvV2Secret({ addr, token, mount = 'kv', path }) {
  if (!addr) throw new Error('VAULT_ADDR is not configured')
  if (!token) throw new Error('VAULT_TOKEN is not configured')
  if (!path) throw new Error('vault path is required')

  const base = addr.replace(/\/$/, '')
  const cleanPath = String(path).replace(/^\//, '')
  const url = `${base}/v1/${mount}/data/${cleanPath}`

  const res = await fetch(url, {
    headers: { 'X-Vault-Token': token, Accept: 'application/json' },
  })
  const text = await res.text()
  let body
  try { body = text ? JSON.parse(text) : null } catch { body = text }

  if (!res.ok) {
    const detail = typeof body === 'string' ? body : JSON.stringify(body)
    throw new Error(`Vault read ${url} failed ${res.status}: ${detail}`)
  }

  const data = body?.data?.data
  if (!data || typeof data !== 'object') {
    throw new Error(`Vault secret at ${mount}/data/${cleanPath} has no data object`)
  }
  return data
}

/** Load from env defaults (VAULT_ADDR, VAULT_TOKEN, VAULT_KV_MOUNT, VAULT_KV_PATH). */
export async function readKvFromEnv(overrides = {}) {
  return readKvV2Secret({
    addr: overrides.addr || process.env.VAULT_ADDR,
    token: overrides.token || process.env.VAULT_TOKEN,
    mount: overrides.mount || process.env.VAULT_KV_MOUNT || 'kv',
    path: overrides.path || process.env.VAULT_KV_PATH,
  })
}

/** Pick an Okta API token field from a vault secret object (common key names). */
export function pickOktaTokenFromSecret(secret) {
  if (!secret || typeof secret !== 'object') return null
  const keys = [
    'OKTA_API_TOKEN', 'okta_api_token', 'apiToken', 'api_token', 'token',
    'OKTA_ACCESS_REQUESTS_TOKEN', 'access_requests_token', 'ssws',
  ]
  for (const k of keys) {
    if (secret[k] && typeof secret[k] === 'string') return secret[k]
  }
  return null
}
