// lib/directoryRoster.js — deterministic "who is in X and when did they last log in" answers.
//
// Questions like "which Super Admins have never logged in" are DIRECTORY questions (user profile
// lastLogin / status), not log-window questions. This module resolves a group by exact name, id or
// prefix (never a fuzzy "closest match"), or an admin role via the Role Assignment API, and returns
// every member with lastLogin/status plus neverLoggedIn / inactive / active buckets.

const clip = (s, n = 120) => { s = String(s ?? ''); return s.length > n ? s.slice(0, n - 1) + '…' : s }

function client({ oktaBase, token }) {
  const base = String(oktaBase || '').replace(/\/$/, '')
  const headers = { Authorization: `SSWS ${token}`, Accept: 'application/json' }
  return async function get(path, { pages = 10 } = {}) {
    const out = []
    let url = `${base}/api/v1${path}`
    let n = 0
    while (url && n < pages) {
      const res = await fetch(url, { headers })
      const text = await res.text()
      let data; try { data = JSON.parse(text) } catch { data = text }
      if (!res.ok) throw new Error(`Okta ${path.split('?')[0]} ${res.status}: ${clip(data?.errorSummary || text, 160)}`)
      n++
      if (Array.isArray(data)) out.push(...data)
      else return data // object responses (single user, iam assignees) are not list-paginated here
      const m = (res.headers.get('link') || '').match(/<([^>]+)>;\s*rel="next"/)
      url = m ? m[1] : null
    }
    return out
  }
}

const ROLE_TYPES = ['SUPER_ADMIN', 'ORG_ADMIN', 'APP_ADMIN', 'USER_ADMIN', 'HELP_DESK_ADMIN', 'GROUP_MEMBERSHIP_ADMIN', 'READ_ONLY_ADMIN', 'API_ACCESS_MANAGEMENT_ADMIN', 'REPORT_ADMIN', 'MOBILE_ADMIN', 'GROUP_ADMIN', 'ACCESS_CERTIFICATIONS_ADMIN', 'ACCESS_REQUESTS_ADMIN', 'CUSTOM']

/** Normalise a role phrase ("super admins", "Super Administrator") to an Okta role type. */
export function normalizeRole(s) {
  const t = String(s || '').trim().toUpperCase().replace(/[\s-]+/g, '_').replace(/S$/, '')
  if (!t) return null
  if (ROLE_TYPES.includes(t)) return t
  if (/SUPER/.test(t)) return 'SUPER_ADMIN'
  if (/ORG/.test(t)) return 'ORG_ADMIN'
  if (/APP/.test(t)) return 'APP_ADMIN'
  if (/HELP/.test(t)) return 'HELP_DESK_ADMIN'
  if (/READ/.test(t)) return 'READ_ONLY_ADMIN'
  if (/REPORT/.test(t)) return 'REPORT_ADMIN'
  if (/GROUP_MEMBER/.test(t)) return 'GROUP_MEMBERSHIP_ADMIN'
  if (/GROUP/.test(t)) return 'GROUP_ADMIN'
  if (/USER/.test(t)) return 'USER_ADMIN'
  return t
}

/**
 * Resolve a group. Accepts an id (00g…), an exact name, or a name prefix. Returns
 * { group, exact, candidates } — when there is no exact match the caller must ASK, not guess.
 */
export async function resolveGroup(cfg, nameOrId) {
  const get = client(cfg)
  const key = String(nameOrId || '').trim()
  if (!key) return { group: null, exact: false, candidates: [] }
  if (/^00g[\w-]{10,}$/i.test(key)) {
    const g = await get(`/groups/${encodeURIComponent(key)}`)
    return { group: pickGroup(g), exact: true, candidates: [] }
  }
  const lower = key.toLowerCase()
  let list = await get(`/groups?q=${encodeURIComponent(key)}&limit=50`, { pages: 1 })
  if (!Array.isArray(list) || list.length === 0) {
    // q= is a prefix search on the name; fall back to a case-insensitive substring scan of all groups.
    const all = await get('/groups?limit=200', { pages: 5 })
    list = (Array.isArray(all) ? all : []).filter(g => String(g.profile?.name || '').toLowerCase().includes(lower))
  }
  const exactHits = list.filter(g => String(g.profile?.name || '').toLowerCase() === lower)
  if (exactHits.length === 1) return { group: pickGroup(exactHits[0]), exact: true, candidates: [] }
  if (list.length === 1) return { group: pickGroup(list[0]), exact: false, candidates: [pickGroup(list[0])] }
  return { group: null, exact: false, candidates: list.slice(0, 12).map(pickGroup) }
}

function pickGroup(g) {
  return g && g.id ? { id: g.id, name: g.profile?.name || null, type: g.type || null, description: g.profile?.description || undefined } : null
}

/** Members of a group with the fields needed for login questions. */
export async function groupMembers(cfg, groupId, { max = 1000 } = {}) {
  const get = client(cfg)
  const users = await get(`/groups/${encodeURIComponent(groupId)}/users?limit=200`, { pages: Math.ceil(max / 200) })
  return (Array.isArray(users) ? users : []).slice(0, max).map(pickUser)
}

/** Users holding an admin role (direct or via a group), from the Role Assignment API. */
export async function roleAssignees(cfg, roleType, { max = 200 } = {}) {
  const get = client(cfg)
  const ids = []
  let next = '/iam/assignees/users'
  while (next && ids.length < max) {
    const page = await get(next)
    for (const v of page?.value || []) ids.push(v.id)
    const nl = page?.nextLink || page?._links?.next?.href
    next = nl ? String(nl).replace(/^.*\/api\/v1/, '') : null
  }
  const out = []
  for (const id of ids.slice(0, max)) {
    const [user, roles] = await Promise.all([get(`/users/${id}`), get(`/users/${id}/roles`)])
    const held = (Array.isArray(roles) ? roles : []).filter(r => r.status !== 'INACTIVE')
    const match = roleType ? held.filter(r => r.type === roleType || r.label === roleType) : held
    if (!match.length) continue
    out.push({
      ...pickUser(user),
      roles: match.map(r => `${r.type}${r.assignmentType === 'GROUP' ? ' (via group ' + (r._links?.assignee?.href || '').split('/').pop() + ')' : ' (direct)'}`),
    })
  }
  return out
}

function pickUser(u) {
  return {
    id: u.id, name: [u.profile?.firstName, u.profile?.lastName].filter(Boolean).join(' ') || u.profile?.login,
    login: u.profile?.login, email: u.profile?.email !== u.profile?.login ? u.profile?.email : undefined,
    status: u.status, created: u.created, activated: u.activated || null, lastLogin: u.lastLogin || null, lastUpdated: u.lastUpdated,
  }
}

/** Bucket users by login recency. inactiveDays defaults to 30. */
export function buildRoster(users, { inactiveDays = 30, now = Date.now() } = {}) {
  const day = 864e5
  const rows = users.map(u => {
    const last = u.lastLogin ? Date.parse(u.lastLogin) : null
    return { ...u, daysSinceLogin: last ? Math.floor((now - last) / day) : null }
  }).sort((a, b) => (b.lastLogin || '').localeCompare(a.lastLogin || '') || String(a.name).localeCompare(String(b.name)))
  const compact = r => ({ name: r.name, login: r.login, status: r.status, lastLogin: r.lastLogin ? r.lastLogin.replace(/\.\d+Z$/, 'Z') : 'never', daysSinceLogin: r.daysSinceLogin ?? undefined, created: (r.created || '').slice(0, 10), ...(r.roles ? { roles: r.roles } : {}) })
  const neverLoggedIn = rows.filter(r => !r.lastLogin).map(compact)
  const inactive = rows.filter(r => r.lastLogin && r.daysSinceLogin >= inactiveDays).map(compact)
  const active = rows.filter(r => r.lastLogin && r.daysSinceLogin < inactiveDays).map(compact)
  const byStatus = {}
  for (const r of rows) byStatus[r.status] = (byStatus[r.status] || 0) + 1
  return {
    total: rows.length, byStatus, inactiveDays,
    counts: { neverLoggedIn: neverLoggedIn.length, inactive: inactive.length, active: active.length },
    neverLoggedIn, inactive, active,
    notes: [
      'lastLogin/status come from the user profile (all time), not from a log window.',
      'PROVISIONED = created but never activated; DEPROVISIONED = deactivated; STAGED = not yet provisioned.',
    ],
  }
}

/**
 * One call for the chat tool: { group } or { role }; optional inactiveDays.
 * Returns { resolved, roster } or { needsClarification, candidates }.
 */
export async function directoryRoster(cfg, { group, role, inactiveDays = 30 } = {}) {
  if (group) {
    const r = await resolveGroup(cfg, group)
    if (!r.group) return { needsClarification: true, query: group, candidates: r.candidates, hint: r.candidates.length ? 'No exact group-name match. Ask the admin which of these candidates they mean (or for the 00g… id); do not guess.' : 'No group matched. Ask the admin for the exact name or the 00g… group id.' }
    const users = await groupMembers(cfg, r.group.id)
    const roles = await client(cfg)(`/groups/${r.group.id}/roles`).catch(() => [])
    return { resolved: { kind: 'group', ...r.group, exactMatch: r.exact, adminRoles: (Array.isArray(roles) ? roles : []).map(x => x.type) }, roster: buildRoster(users, { inactiveDays }) }
  }
  if (role) {
    const type = normalizeRole(role)
    const users = await roleAssignees(cfg, type)
    return { resolved: { kind: 'role', role: type, source: 'Role Assignment API (/iam/assignees/users + /users/{id}/roles), direct and group-derived' }, roster: buildRoster(users, { inactiveDays }) }
  }
  return { error: 'Pass group (name or 00g… id) or role (e.g. SUPER_ADMIN).' }
}
