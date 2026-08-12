// Execute a canonical privileged action against the Okta Management API after
// an access request is approved. Gated by prior approval record + delegated scope
// check (human ∩ agent); the API call uses OKTA_API_TOKEN like /api/agent/okta/*.

import { getDelegatedAccessToken } from './agentTokenExchange.js'
import { CANONICAL_ACTIONS } from './accessRequestActions.js'

function orgUrl() {
  const url = (process.env.OKTA_ORG_URL || '').replace(/\/$/, '')
  if (!url) throw new Error('OKTA_ORG_URL is not configured')
  return url
}

function mgmtToken() {
  const token = process.env.OKTA_API_TOKEN
  if (!token) throw new Error('OKTA_API_TOKEN is not configured')
  return token
}

function scopeForAction(actionType) {
  const userLifecycle = new Set([
    'suspend_user', 'unsuspend_user', 'activate_user', 'deactivate_user', 'reset_user_mfa', 'reset_user_password',
    'create_user',
  ])
  if (userLifecycle.has(actionType)) return 'sdap.users.manage'
  return 'sdap.act'
}

async function assertDelegatedScope({ idToken, actionType }) {
  if (!idToken) {
    if (process.env.DEMO_AUTH_BYPASS === 'true') return
    throw new Error('OIDC session required to execute approved actions on behalf of the admin')
  }
  const need = scopeForAction(actionType)
  const delegated = await getDelegatedAccessToken({ idToken })
  const granted = (delegated.scope || '').split(' ').filter(Boolean)
  if (!granted.includes(need)) {
    throw new Error(
      `Insufficient delegated scope to execute ${actionType}: need ${need}, granted ${granted.join(' ') || '(none)'}`
    )
  }
}

async function oktaMgmt({ method, path, body }) {
  const url = `${orgUrl()}/api/v1${path}`
  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `SSWS ${mgmtToken()}`,
      Accept: 'application/json',
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  let data
  try { data = text ? JSON.parse(text) : null } catch { data = text }
  return { ok: res.ok, status: res.status, data, oktaOperation: `${method} ${path}` }
}

async function resolveUserId(target) {
  const raw = target?.userId || target?.userLogin
  if (!raw) throw new Error('target.userId or target.userLogin is required')
  const value = String(raw).trim()
  if (value.startsWith('00u')) return value

  // Direct lookup by login (Okta accepts login as the path id when URL-encoded).
  const direct = await oktaMgmt({ method: 'GET', path: `/users/${encodeURIComponent(value)}` })
  if (direct.ok && direct.data?.id) return direct.data.id

  // Exact match via search expression (q= is prefix-only and misses full logins).
  const search = encodeURIComponent(`profile.login eq "${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`)
  const found = await oktaMgmt({ method: 'GET', path: `/users?search=${search}&limit=1` })
  if (found.ok && Array.isArray(found.data) && found.data[0]?.id) return found.data[0].id

  // Email fallback when login differs from email.
  if (value.includes('@')) {
    const emailSearch = encodeURIComponent(`profile.email eq "${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`)
    const byEmail = await oktaMgmt({ method: 'GET', path: `/users?search=${emailSearch}&limit=1` })
    if (byEmail.ok && Array.isArray(byEmail.data) && byEmail.data[0]?.id) return byEmail.data[0].id
  }

  const detail = typeof direct.data === 'object' ? direct.data?.errorSummary : direct.data
  throw new Error(`Could not resolve Okta user for "${value}"${detail ? `: ${detail}` : ''}`)
}

/**
 * Run the Okta Management API operation mapped to action.type.
 * @returns {Promise<{ ok: boolean, actionType: string, oktaOperation: string, status: number, result: string, detail?: unknown, error?: string }>}
 */
export async function executeAccessRequestAction({ action, idToken }) {
  const actionType = action?.type
  if (!actionType || !Object.prototype.hasOwnProperty.call(CANONICAL_ACTIONS, actionType)) {
    throw new Error(`Unknown or missing action.type: ${actionType}`)
  }

  await assertDelegatedScope({ idToken, actionType })

  const target = action.target || {}
  const parameters = action.parameters || {}

  let out
  switch (actionType) {
    case 'suspend_user':
      out = await oktaMgmt({ method: 'POST', path: `/users/${await resolveUserId(target)}/lifecycle/suspend` })
      break
    case 'unsuspend_user':
      out = await oktaMgmt({ method: 'POST', path: `/users/${await resolveUserId(target)}/lifecycle/unsuspend` })
      break
    case 'activate_user':
      out = await oktaMgmt({ method: 'POST', path: `/users/${await resolveUserId(target)}/lifecycle/activate` })
      break
    case 'deactivate_user':
      out = await oktaMgmt({ method: 'POST', path: `/users/${await resolveUserId(target)}/lifecycle/deactivate` })
      break
    case 'reset_user_mfa':
      out = await oktaMgmt({ method: 'POST', path: `/users/${await resolveUserId(target)}/lifecycle/reset_factors` })
      break
    case 'reset_user_password':
      out = await oktaMgmt({ method: 'POST', path: `/users/${await resolveUserId(target)}/lifecycle/expire_password` })
      break
    case 'create_user': {
      const profile = parameters.profile || target.profile || parameters
      if (!profile?.login && !profile?.email) throw new Error('create_user requires profile.login or profile.email')
      out = await oktaMgmt({
        method: 'POST',
        path: '/users?activate=false',
        body: { profile },
      })
      break
    }
    case 'add_user_to_group': {
      if (!target.groupId) throw new Error('add_user_to_group requires target.groupId')
      const userId = await resolveUserId(target)
      out = await oktaMgmt({ method: 'PUT', path: `/groups/${target.groupId}/users/${userId}` })
      break
    }
    case 'remove_user_from_group': {
      if (!target.groupId) throw new Error('remove_user_from_group requires target.groupId')
      const userId = await resolveUserId(target)
      out = await oktaMgmt({ method: 'DELETE', path: `/groups/${target.groupId}/users/${userId}` })
      break
    }
    case 'assign_app_to_user': {
      if (!target.appId) throw new Error('assign_app_to_user requires target.appId')
      const userId = await resolveUserId(target)
      out = await oktaMgmt({
        method: 'PUT',
        path: `/apps/${target.appId}/users/${userId}`,
        body: parameters.credentials ? { id: userId, credentials: parameters.credentials, scope: parameters.scope } : { id: userId },
      })
      break
    }
    case 'assign_admin_role': {
      if (!target.roleType) throw new Error('assign_admin_role requires target.roleType')
      const userId = await resolveUserId(target)
      out = await oktaMgmt({
        method: 'POST',
        path: `/users/${userId}/roles`,
        body: { type: target.roleType },
      })
      break
    }
    case 'update_policy_rule': {
      if (!target.policyId || !target.ruleId) throw new Error('update_policy_rule requires target.policyId and target.ruleId')
      out = await oktaMgmt({
        method: 'PUT',
        path: `/policies/${target.policyId}/rules/${target.ruleId}`,
        body: parameters,
      })
      break
    }
    case 'delete_group': {
      if (!target.groupId) throw new Error('delete_group requires target.groupId')
      out = await oktaMgmt({ method: 'DELETE', path: `/groups/${target.groupId}` })
      break
    }
    default:
      throw new Error(`No executor implemented for action "${actionType}"`)
  }

  return {
    ok: out.ok,
    actionType,
    oktaOperation: out.oktaOperation,
    status: out.status,
    result: out.ok ? 'success' : 'failed',
    detail: out.ok ? out.data : out.data,
    error: out.ok ? undefined : (typeof out.data === 'object' ? out.data?.errorSummary || JSON.stringify(out.data) : String(out.data)),
  }
}
