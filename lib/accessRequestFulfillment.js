// After an access request is approved, execute the mapped Okta operation when Okta
// does not auto-fulfill (v1 request types, or v2 without grant completion).

import { executeAccessRequestAction } from './executeAccessRequestAction.js'
import { isAccessRequestTerminal, parseActionFromV1Subject } from './oktaAccessRequests.js'

const fulfilling = new Set()

export function buildAccessRequestRecord(createResult) {
  return {
    status: createResult.status,
    correlationId: createResult.correlationId || null,
    action: createResult.action || null,
    requesterId: createResult.requester?.id || null,
    apiVersion: createResult.apiVersion || null,
    description: createResult.action?.description || null,
    updatedAt: new Date().toISOString(),
    execution: null,
  }
}

export function hydrateActionFromLive(cached, live) {
  const base = cached || {}
  if (base.action?.type) return base
  const parsed = parseActionFromV1Subject(live?.oktaResponse?.subject)
  if (!parsed) return base
  return { ...base, action: parsed }
}

export function shouldFulfillAccessRequest(cached, live) {
  if (process.env.OKTA_EXECUTE_APPROVED_ACCESS_REQUESTS === 'false') return false
  const record = hydrateActionFromLive(cached, live)
  if (!record?.action?.type) return false
  const prior = record.execution || cached?.execution
  if (prior?.performed && prior?.ok !== false) return false

  const status = live.status

  // Approved in Okta but grant/operation not completed — portal executes.
  if (status === 'approved_pending_grant' || status === 'resolved') return true

  // Legacy v1 mapping before RESOLVED fix
  if (live.apiVersion === 'v1' && status === 'approved_executed') {
    const okta = live.oktaResponse || {}
    const rs = String(okta.requestStatus || '').toUpperCase()
    return rs === 'CLOSED' || rs === 'COMPLETED' || rs === 'RESOLVED' || v1ApprovalFromOkta(okta)
  }

  // v2: only portal-fulfill when Okta did not grant (catalog misconfigured / empty grant).
  if (live.apiVersion === 'v2' && status === 'approved_executed' && live.grantStatus !== 'GRANTED') {
    return true
  }

  return false
}

function v1ApprovalFromOkta(okta) {
  return (okta?.approvals || []).some(a => {
    const s = String(a.status || '').toUpperCase()
    return s === 'APPROVED' || s === 'COMPLETED'
  })
}

/**
 * If the request is approved and not yet executed, run the Okta operation once.
 * Mutates the cached record in accessRequestStatus.
 */
export async function maybeFulfillApprovedRequest(requestId, live, { idToken, accessRequestStatus }) {
  let cached = accessRequestStatus.get(requestId) || {}
  cached = hydrateActionFromLive(cached, live)
  if (cached.action?.type) accessRequestStatus.set(requestId, cached)

  if (!shouldFulfillAccessRequest(cached, live)) return null
  if (fulfilling.has(requestId)) return cached.execution

  fulfilling.add(requestId)
  try {
    console.log(`[access-request fulfill] ${requestId} action=${cached.action.type}`)
    const result = await executeAccessRequestAction({ action: cached.action, idToken })
    const execution = {
      performed: true,
      ok: result.ok,
      oktaOperation: result.oktaOperation,
      result: result.result,
      status: result.status,
      detail: result.detail,
      error: result.error || null,
      at: new Date().toISOString(),
    }
    const portalStatus = result.ok ? 'approved_executed' : 'approved_execution_failed'
    accessRequestStatus.set(requestId, {
      ...cached,
      status: portalStatus,
      execution,
      updatedAt: new Date().toISOString(),
    })
    console.log(`[access-request fulfill] ${requestId} -> ${portalStatus} (${result.oktaOperation})`)
    return execution
  } catch (e) {
    const execution = {
      performed: true,
      ok: false,
      result: 'failed',
      error: e.message,
      at: new Date().toISOString(),
    }
    accessRequestStatus.set(requestId, {
      ...cached,
      status: 'approved_execution_failed',
      execution,
      updatedAt: new Date().toISOString(),
    })
    console.error(`[access-request fulfill] ${requestId} failed:`, e.message)
    return execution
  } finally {
    fulfilling.delete(requestId)
  }
}

export function portalStatusAfterFulfillment(cached, live, execution) {
  if (execution?.performed || cached?.execution?.performed) {
    return cached?.status || (execution?.ok ? 'approved_executed' : 'approved_execution_failed')
  }
  return live.status
}

export function isTerminalAfterFulfillment(status) {
  return isAccessRequestTerminal(status)
}
