// Okta Identity Governance — Access Requests API v2 (direct, no Workflows hop).
//
// Creates privileged-action requests via:
//   POST {OKTA_ORG_URL}/governance/api/v2/requests
//
// Requires a token with scope okta.accessRequests.request.manage (ACCESS_REQUESTS_ADMIN).
// Set OKTA_ACCESS_REQUESTS_TOKEN, OKTA_API_TOKEN, or load from Vault:
//   VAULT_ADDR, VAULT_TOKEN, VAULT_KV_PATH=Okta-Tenant
//
// Each canonical action.type maps to an OIG catalog entry id (cen…) via
// OKTA_ACCESS_REQUEST_CATALOG_ENTRIES JSON, e.g.:
//   {"suspend_user":"cenabc...","reset_user_mfa":"cendef..."}
//
// Optional requester input field ids (approval-sequence fields in Okta):
//   OKTA_ACCESS_REQUEST_FIELD_JUSTIFICATION
//   OKTA_ACCESS_REQUEST_FIELD_DESCRIPTION
//   OKTA_ACCESS_REQUEST_FIELD_TARGET_USER   (OKTA_USER_ID type; or uses reserved OKTA_REQUESTED_FOR)
//
// Env is read lazily — api-server.js loads dotenv after imports resolve.

import { randomUUID } from 'crypto'
import { CANONICAL_ACTIONS, normalizeActionType } from './accessRequestActions.js'
import { readKvFromEnv, pickOktaTokenFromSecret } from './vaultKv.js'

export { CANONICAL_ACTIONS, normalizeActionType }

let _resolvedToken = null

function reqEnv(name) {
  const v = process.env[name]
  if (!v) throw new Error(`${name} is not configured`)
  return v
}

function orgUrl() {
  const url = (process.env.OKTA_ORG_URL || '').replace(/\/$/, '')
  if (!url) throw new Error('OKTA_ORG_URL is not configured')
  return url
}

async function accessRequestsToken() {
  if (_resolvedToken) return _resolvedToken

  if (process.env.VAULT_ADDR && process.env.VAULT_TOKEN && process.env.VAULT_KV_PATH) {
    const secret = await readKvFromEnv()
    const fromVault = pickOktaTokenFromSecret(secret)
    if (fromVault) {
      _resolvedToken = fromVault
      return _resolvedToken
    }
    throw new Error(
      `Vault secret at ${process.env.VAULT_KV_MOUNT || 'kv'}/data/${process.env.VAULT_KV_PATH} ` +
      'has no recognized Okta token field (expected OKTA_API_TOKEN, apiToken, token, etc.)'
    )
  }

  const token = process.env.OKTA_ACCESS_REQUESTS_TOKEN || process.env.OKTA_API_TOKEN
  if (!token) {
    throw new Error(
      'OKTA_ACCESS_REQUESTS_TOKEN (or OKTA_API_TOKEN, or VAULT_* for kv/Okta-Tenant) is not configured'
    )
  }
  _resolvedToken = token
  return _resolvedToken
}

function governanceBase() {
  return `${orgUrl()}/governance/api/v2`
}

function governanceV1Base() {
  return `${orgUrl()}/governance/api/v1`
}

function hasCatalogEntries() {
  const raw = process.env.OKTA_ACCESS_REQUEST_CATALOG_ENTRIES
  if (!raw) return false
  try {
    const map = JSON.parse(raw)
    return map && typeof map === 'object' && Object.keys(map).length > 0
  } catch {
    return false
  }
}

function requestTypeId() {
  return process.env.OKTA_ACCESS_REQUEST_REQUEST_TYPE_ID || null
}

function parseCatalogEntries() {
  const raw = process.env.OKTA_ACCESS_REQUEST_CATALOG_ENTRIES
  if (!raw) {
    throw new Error(
      'OKTA_ACCESS_REQUEST_CATALOG_ENTRIES is not configured — JSON map of action.type -> catalog entryId (cen…)'
    )
  }
  try {
    const map = JSON.parse(raw)
    if (!map || typeof map !== 'object') throw new Error('must be a JSON object')
    return map
  } catch (e) {
    throw new Error(`OKTA_ACCESS_REQUEST_CATALOG_ENTRIES is invalid JSON: ${e.message}`)
  }
}

function catalogEntryIdFor(actionType) {
  const map = parseCatalogEntries()
  const entryId = map[actionType]
  if (!entryId) {
    throw new Error(
      `No catalog entryId configured for action "${actionType}" — add it to OKTA_ACCESS_REQUEST_CATALOG_ENTRIES`
    )
  }
  return entryId
}

function resolveRequestedForExternalId({ principal, target, actionType }) {
  const mode = (process.env.OKTA_ACCESS_REQUEST_REQUESTED_FOR || 'actor').toLowerCase()
  if (mode === 'target') {
    const userActions = new Set([
      'suspend_user', 'unsuspend_user', 'activate_user', 'deactivate_user', 'reset_user_mfa', 'reset_user_password',
      'add_user_to_group', 'remove_user_from_group', 'assign_app_to_user', 'assign_admin_role',
    ])
    if (userActions.has(actionType) && target?.userId) return target.userId
  }
  return principal.id
}

function buildRequesterFieldValues({ justification, description, target, correlationId, parameters }) {
  const fields = []

  const justField = process.env.OKTA_ACCESS_REQUEST_FIELD_JUSTIFICATION
  if (justField && justification) {
    fields.push({ id: justField, type: 'TEXT', value: String(justification) })
  }

  const descField = process.env.OKTA_ACCESS_REQUEST_FIELD_DESCRIPTION
  if (descField && description) {
    fields.push({ id: descField, type: 'TEXT', value: String(description) })
  }

  const targetField = process.env.OKTA_ACCESS_REQUEST_FIELD_TARGET_USER
  if (target?.userId) {
    if (targetField) {
      fields.push({ id: targetField, type: 'OKTA_USER_ID', value: target.userId })
    } else {
      fields.push({ id: 'OKTA_REQUESTED_FOR', type: 'OKTA_USER_ID', value: target.userId })
    }
  }

  const corrField = process.env.OKTA_ACCESS_REQUEST_FIELD_CORRELATION_ID
  if (corrField && correlationId) {
    fields.push({ id: corrField, type: 'TEXT', value: correlationId })
  }

  const extraRaw = process.env.OKTA_ACCESS_REQUEST_EXTRA_FIELDS
  if (extraRaw) {
    try {
      const extra = JSON.parse(extraRaw)
      if (Array.isArray(extra)) fields.push(...extra)
    } catch {
      console.warn('[access-request] OKTA_ACCESS_REQUEST_EXTRA_FIELDS is invalid JSON — skipping')
    }
  }

  if (parameters && typeof parameters === 'object' && Object.keys(parameters).length) {
    const paramsField = process.env.OKTA_ACCESS_REQUEST_FIELD_PARAMETERS
    if (paramsField) {
      fields.push({ id: paramsField, type: 'TEXT', value: JSON.stringify(parameters) })
    }
  }

  return fields.length ? fields : undefined
}

async function oktaGovernanceFetch(path, { method = 'GET', body, apiVersion = 'v2' } = {}) {
  const base = apiVersion === 'v1' ? governanceV1Base() : governanceBase()
  const url = `${base}${path}`
  const token = await accessRequestsToken()
  const headers = {
    Accept: 'application/json',
    Authorization: `SSWS ${token}`,
  }
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  const res = await fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })

  const text = await res.text()
  let data
  try { data = text ? JSON.parse(text) : null } catch { data = text }

  if (!res.ok) {
    const detail = typeof data === 'string' ? data : JSON.stringify(data)
    throw new Error(`Okta Access Requests API ${method} ${path} failed ${res.status}: ${detail}`)
  }
  return { status: res.status, data }
}

function buildV1Subject({ canonicalType, description, target }) {
  const parts = [`[${canonicalType}]`, description]
  if (target?.userLogin || target?.userId) parts.push(`target=${target.userLogin || target.userId}`)
  return parts.join(' ').slice(0, 500)
}

/** Recover action payload from v1 request subject when server cache was lost. */
export function parseActionFromV1Subject(subject) {
  if (!subject) return null
  const m = String(subject).match(/^\[([a-z_]+)\]\s*(.+?)(?:\s+target=(.+))?$/i)
  if (!m) return null
  const type = m[1].toLowerCase()
  const description = m[2].trim()
  const targetRaw = m[3]?.trim()
  const target = {}
  if (targetRaw) {
    if (targetRaw.startsWith('00u')) target.userId = targetRaw
    else target.userLogin = targetRaw
  }
  return { type, description, target, parameters: {} }
}

function v1ApprovalComplete(approvals) {
  return (approvals || []).some(a => {
    const s = String(a.status || '').toUpperCase()
    return s === 'APPROVED' || s === 'COMPLETED'
  })
}

/** POST /governance/api/v1/requests — used when v2 catalog entries (cen…) are not yet available. */
async function createAccessRequestV1({
  principal,
  canonicalType,
  description,
  justification,
  target,
  correlationId,
  parameters,
  requesterFieldValues,
}) {
  const requestTypeId = reqEnv('OKTA_ACCESS_REQUEST_REQUEST_TYPE_ID')
  const payload = {
    requestTypeId,
    subject: buildV1Subject({ canonicalType, description, target }),
    requesterUserIds: [principal.id],
    requesterFieldValues: requesterFieldValues?.map(f => ({
      id: f.id,
      value: f.value,
      ...(f.values ? { values: f.values } : {}),
    })) || [],
  }

  const { status: httpStatus, data: oktaResponse } = await oktaGovernanceFetch('/requests', {
    method: 'POST',
    body: payload,
    apiVersion: 'v1',
  })

  return {
    status: oktaResponse?.requestStatus === 'OPEN' ? 'pending_approval' : String(oktaResponse?.requestStatus || 'pending_approval').toLowerCase(),
    requestId: oktaResponse?.id || null,
    oktaResponse,
    httpStatus,
    apiVersion: 'v1',
    requestTypeId,
    correlationId,
    subject: payload.subject,
    justification,
    parameters,
  }
}

function mapV1StatusToPortal(data) {
  const rs = String(data?.requestStatus || '').toUpperCase()
  const approvals = data?.approvals || []
  if (rs === 'OPEN') {
    if (approvals.some(a => String(a.status).toUpperCase() === 'DENIED')) return 'denied'
    if (v1ApprovalComplete(approvals)) return 'approved_pending_grant'
    return 'pending_approval'
  }
  // v1 "RESOLVED" / CLOSED / COMPLETED = approved in Okta; portal still must run the API op.
  if (rs === 'RESOLVED' || rs === 'CLOSED' || rs === 'COMPLETED') {
    if (approvals.some(a => String(a.status).toUpperCase() === 'DENIED')) return 'denied'
    return 'approved_pending_grant'
  }
  if (rs === 'CANCELLED' || rs === 'CANCELED') return 'cancelled'
  return rs ? rs.toLowerCase() : 'unknown'
}

export const TERMINAL_ACCESS_REQUEST_STATUSES = new Set([
  'denied', 'rejected', 'cancelled', 'canceled', 'expired',
  'approved_executed', 'approved_execution_failed', 'closed', 'completed',
])

export function isAccessRequestTerminal(status) {
  return TERMINAL_ACCESS_REQUEST_STATUSES.has(String(status || '').toLowerCase())
}

function mapOktaStatusToPortal(okta) {
  const status = okta?.status
  const grant = okta?.grantStatus
  const approval = okta?.requestApproval?.status

  if (status === 'DENIED' || status === 'REJECTED' || approval === 'DENIED') return 'denied'
  if (status === 'EXPIRED') return 'expired'
  if (status === 'CANCELED') return 'cancelled'
  if (status === 'APPROVED') {
    if (grant === 'FAILED') return 'approved_execution_failed'
    if (grant === 'GRANTED') return 'approved_executed'
    return 'approved_pending_grant'
  }
  if (status === 'SUBMITTED' || status === 'PENDING') return 'pending_approval'
  return status ? String(status).toLowerCase() : 'unknown'
}

function requestUrlFromLinks(okta) {
  const self = okta?._links?.self?.href
  if (self) return self
  return `${orgUrl()}/admin/access-requests`
}

/**
 * POST /governance/api/v2/requests — create an access request for a privileged admin action.
 */
export async function createAccessRequest({
  user,
  action,
  actionType,
  description,
  justification,
  target,
  parameters,
  agentContext,
}) {
  if (!action || !description) throw new Error('action and description are required')

  const principal = {
    id: user.id,
    login: user.login || user.email,
    email: user.email,
    name: user.name,
  }

  const { type: canonicalType, recognized } = normalizeActionType(action)
  const category = actionType || CANONICAL_ACTIONS[canonicalType] || 'destructive'
  const correlationId = randomUUID()
  const requestedAt = new Date().toISOString()
  const just = justification || `Requested via SDAP agent by ${principal.email || principal.login || principal.id}`
  const fieldValues = buildRequesterFieldValues({
    justification: just,
    description,
    target,
    correlationId,
    parameters,
  })

  // v2 catalog (cen…) when mapped; otherwise v1 request type (published Agent Action Request).
  if (!hasCatalogEntries()) {
    if (!requestTypeId()) {
      throw new Error(
        'Configure OKTA_ACCESS_REQUEST_CATALOG_ENTRIES (v2 cen… ids) or OKTA_ACCESS_REQUEST_REQUEST_TYPE_ID (v1)'
      )
    }
    const v1 = await createAccessRequestV1({
      principal,
      canonicalType,
      description,
      justification: just,
      target,
      correlationId,
      parameters,
      requesterFieldValues: fieldValues,
    })
    return {
      status: v1.status,
      requestId: v1.requestId,
      requestRef: v1.requestId,
      correlationId,
      actionType: canonicalType,
      recognized,
      requester: principal,
      requestTypeId: v1.requestTypeId,
      note:
        'Access request created via Okta Governance API v1 (request type). Pending approval in Okta Access Requests.',
      links: { requestUrl: `${orgUrl()}/admin/access-requests` },
      oktaResponse: v1.oktaResponse,
      httpStatus: v1.httpStatus,
      apiVersion: 'v1',
      agentContext: agentContext || null,
      requestedAt,
      action: {
        type: canonicalType,
        category,
        description,
        target: target || null,
        parameters: parameters || {},
        ...(recognized ? {} : { recognized: false }),
      },
    }
  }

  const entryId = catalogEntryIdFor(canonicalType)

  const requestedForExternalId = resolveRequestedForExternalId({ principal, target, actionType: canonicalType })

  const payload = {
    requestedBy: { type: 'OKTA_USER', externalId: principal.id },
    requestedFor: { type: 'OKTA_USER', externalId: requestedForExternalId },
    requested: { type: 'CATALOG_ENTRY', entryId },
    requesterFieldValues: fieldValues,
  }

  const { status: httpStatus, data: oktaResponse } = await oktaGovernanceFetch('/requests', {
    method: 'POST',
    body: payload,
  })

  const requestId = oktaResponse?.id || null
  const portalStatus = mapOktaStatusToPortal(oktaResponse) || 'pending_approval'

  return {
    status: portalStatus,
    requestId,
    requestRef: requestId,
    correlationId,
    actionType: canonicalType,
    recognized,
    requester: principal,
    catalogEntryId: entryId,
    requestedFor: { type: 'OKTA_USER', externalId: requestedForExternalId },
    note:
      'Access request created via Okta Governance API v2. Pending approval in Okta Access Requests — ' +
      'Okta executes the mapped operation on approval, not the portal.',
    links: { requestUrl: requestUrlFromLinks(oktaResponse) },
    oktaResponse,
    httpStatus,
    agentContext: agentContext || null,
    requestedAt,
    action: {
      type: canonicalType,
      category,
      description,
      target: target || null,
      parameters: parameters || {},
      ...(recognized ? {} : { recognized: false }),
    },
  }
}

/** GET /governance/api/v2/requests/{requestId} (falls back to v1). */
export async function getAccessRequest(requestId) {
  if (!requestId) throw new Error('requestId is required')
  try {
    const { data } = await oktaGovernanceFetch(`/requests/${encodeURIComponent(requestId)}`)
    const portalStatus = mapOktaStatusToPortal(data)
    return {
      requestId: data.id,
      status: portalStatus,
      terminal: isAccessRequestTerminal(portalStatus),
      oktaStatus: data.status,
      grantStatus: data.grantStatus || null,
      requestApproval: data.requestApproval || null,
      links: { requestUrl: requestUrlFromLinks(data) },
      oktaResponse: data,
      updatedAt: data.lastUpdated || new Date().toISOString(),
      apiVersion: 'v2',
    }
  } catch {
    const { data } = await oktaGovernanceFetch(`/requests/${encodeURIComponent(requestId)}`, { apiVersion: 'v1' })
    const portalStatus = mapV1StatusToPortal(data)
    return {
      requestId: data.id,
      status: portalStatus,
      terminal: isAccessRequestTerminal(portalStatus),
      oktaStatus: data.requestStatus,
      grantStatus: null,
      requestApproval: data.approvals || null,
      links: { requestUrl: `${orgUrl()}/admin/access-requests` },
      oktaResponse: data,
      updatedAt: data.lastUpdated || new Date().toISOString(),
      apiVersion: 'v1',
    }
  }
}
