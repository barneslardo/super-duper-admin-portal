#!/usr/bin/env node
/**
 * Discover Okta Access Request catalog entries (v2) and suggest
 * OKTA_ACCESS_REQUEST_CATALOG_ENTRIES mapping for canonical action types.
 *
 * Usage: node scripts/discover-access-request-catalog.mjs
 *
 * Reads OKTA_ORG_URL + token from .env.local (or Vault if VAULT_* configured).
 */

import dotenv from 'dotenv'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { CANONICAL_ACTIONS } from '../lib/accessRequestActions.js'
import { readKvFromEnv, pickOktaTokenFromSecret } from '../lib/vaultKv.js'

const ACTION_KEYS = Object.keys(CANONICAL_ACTIONS)

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = join(__dirname, '..')
dotenv.config({ path: join(root, '.env.local') })
dotenv.config({ path: join(root, '.env') })

async function resolveToken() {
  if (process.env.VAULT_ADDR && process.env.VAULT_TOKEN && process.env.VAULT_KV_PATH) {
    const secret = await readKvFromEnv()
    const t = pickOktaTokenFromSecret(secret)
    if (t) return { token: t, source: `vault:${process.env.VAULT_KV_PATH}` }
    throw new Error('Vault secret has no recognized token field')
  }
  const token = process.env.OKTA_ACCESS_REQUESTS_TOKEN || process.env.OKTA_API_TOKEN
  if (!token) throw new Error('No Okta token in env or Vault')
  return { token, source: 'env' }
}

async function listCatalogEntries(org, token) {
  const entries = []
  let after = ''
  for (let page = 0; page < 20; page++) {
    const q = new URLSearchParams({ filter: 'not(parent pr)', limit: '100' })
    if (after) q.set('after', after)
    const res = await fetch(`${org}/governance/api/v2/catalogs/default/entries?${q}`, {
      headers: { Authorization: `SSWS ${token}`, Accept: 'application/json' },
    })
    const body = await res.json()
    if (!res.ok) throw new Error(`catalog list ${res.status}: ${JSON.stringify(body)}`)
    entries.push(...(body.data || []))
    const nextHref = body._links?.next?.href
    if (!nextHref) break
    after = new URL(nextHref, org).searchParams.get('after') || ''
    if (!after) break
  }
  return entries
}

async function listRequestTypes(org, token) {
  const res = await fetch(`${org}/governance/api/v1/request-types?limit=100`, {
    headers: { Authorization: `SSWS ${token}`, Accept: 'application/json' },
  })
  const body = await res.json()
  if (!res.ok) throw new Error(`request-types ${res.status}: ${JSON.stringify(body)}`)
  return body.data || []
}

function suggestMapping(entries) {
  const actionKeys = Object.keys(CANONICAL_ACTIONS)
  const mapping = {}
  const unmatched = []

  for (const action of actionKeys) {
    const needles = action.split('_')
    const hit = entries.find(e => {
      const hay = `${e.name || ''} ${e.description || ''}`.toLowerCase()
      return needles.every(n => hay.includes(n))
    })
    if (hit) mapping[action] = hit.id
    else unmatched.push(action)
  }

  return { mapping, unmatched }
}

function normalize(s) {
  return String(s || '').toLowerCase().replace(/[\s_-]+/g, '')
}

function suggestFromRequestTypes(types) {
  // v1 request types are NOT catalog entry ids — informational only
  return types.map(t => ({
    id: t.id,
    name: t.name,
    status: t.status,
    note: 'v1 request-type id — publish + link to access request condition to get a v2 cen… entry',
  }))
}

async function main() {
  const org = process.env.OKTA_ORG_URL?.replace(/\/$/, '')
  if (!org) throw new Error('OKTA_ORG_URL not set')

  const { token, source } = await resolveToken()
  console.log(`Token source: ${source}`)
  console.log(`Org: ${org}\n`)

  const entries = await listCatalogEntries(org, token)
  console.log(`Catalog entries (v2): ${entries.length}`)
  if (entries.length) {
    for (const e of entries) {
      console.log(`  ${e.id}\t${e.name}${e.requestable === false ? ' (not requestable)' : ''}`)
    }
  } else {
    console.log('  (empty — publish access request conditions in Okta Admin first)')
  }

  const types = await listRequestTypes(org, token)
  console.log(`\nRequest types (v1): ${types.length}`)
  for (const t of suggestFromRequestTypes(types)) {
    console.log(`  ${t.id}\t${t.name}\t[${t.status}]`)
  }

  const { mapping, unmatched } = suggestMapping(entries)
  console.log('\n--- Suggested OKTA_ACCESS_REQUEST_CATALOG_ENTRIES ---')
  if (Object.keys(mapping).length) {
    console.log(JSON.stringify(mapping, null, 2))
  } else {
    console.log('{}')
    console.log('\nNo automatic matches. After creating catalog entries in Okta, re-run this script.')
  }

  if (unmatched.length) {
    console.log('\nUnmatched actions (need manual catalog entry ids):')
    for (const a of unmatched) console.log(`  - ${a}`)
  }

  // If exactly one requestable catalog entry, suggest catch-all
  const requestable = entries.filter(e => e.requestable !== false)
  if (requestable.length === 1 && unmatched.length === ACTION_KEYS.length) {
    const only = requestable[0]
    const catchAll = Object.fromEntries(ACTION_KEYS.map(k => [k, only.id]))
    console.log('\n--- Optional catch-all (single catalog entry) ---')
    console.log(JSON.stringify(catchAll, null, 2))
  }
}

main().catch(err => {
  console.error(err.message || err)
  process.exit(1)
})
