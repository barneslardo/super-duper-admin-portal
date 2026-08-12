// Canonical privileged-action taxonomy for human-in-the-loop access requests.
// Each action.type maps to an OIG catalog entry (cen…) configured in Okta Access Requests.
// Keep in sync with docs/access-request-flo-contract.md §4.

export const CANONICAL_ACTIONS = {
  suspend_user: 'destructive',
  unsuspend_user: 'creative',
  activate_user: 'creative',
  deactivate_user: 'destructive',
  reset_user_mfa: 'destructive',
  reset_user_password: 'destructive',
  create_user: 'creative',
  add_user_to_group: 'creative',
  remove_user_from_group: 'destructive',
  assign_app_to_user: 'creative',
  assign_admin_role: 'creative',
  update_policy_rule: 'destructive',
  delete_group: 'destructive',
}

/** Normalize free-form action strings to snake_case enum keys. */
export function normalizeActionType(action) {
  const norm = String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_')
  return { type: norm, recognized: Object.prototype.hasOwnProperty.call(CANONICAL_ACTIONS, norm) }
}
