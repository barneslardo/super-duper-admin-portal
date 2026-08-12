// @deprecated — access requests now go directly to Okta Governance API v2 (lib/oktaAccessRequests.js).
// This module re-exports for backward compatibility with older imports.

export {
  CANONICAL_ACTIONS,
  normalizeActionType,
  createAccessRequest,
  getAccessRequest,
} from './oktaAccessRequests.js'

/** @deprecated Workflows invoke is no longer used for access requests. */
export async function invokeAccessRequest() {
  throw new Error('invokeAccessRequest is deprecated — access requests use Okta Governance API v2 directly')
}

/** @deprecated Workflows resume is no longer used for access requests. */
export async function resumeAccessRequest() {
  throw new Error('resumeAccessRequest is deprecated — access requests use Okta Governance API v2 directly')
}
