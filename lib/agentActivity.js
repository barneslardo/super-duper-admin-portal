// lib/agentActivity.js — deterministic pre-digest of the Okta System Log for the admin chat agent.
//
// Why: small models (gemma4) cannot reliably compose Okta filter expressions or read hundreds of
// 3 KB JSON events. This module fetches a time window, classifies every event into a tier
// (agent / privileged / infra / routine / service), attributes each agent event to the human it
// acted for, and returns a compact, pre-narrated report the model only has to paraphrase.
//
// OPA (Okta Privileged Access) audit events arrive in the same System Log as `pam.*` eventTypes,
// so "Okta and OPA logs" are one feed with two prefixes.

// Okta-run infrastructure principals. They authenticate with jwt-bearer / client_credentials and
// would otherwise look like "agents". Extend with ACTIVITY_INFRA_PRINCIPALS="name1,name2".
const INFRA_PRINCIPALS = [
  /^Active Directory Agent$/i, /^OPS Agent$/i, /^Okta Privileged Access Connector$/i,
  /^Okta IGA Connector$/i, /^Okta Access Requests OAuth$/i, /^Okta Inbox$/i,
  /^Okta Workflows/i, /^Okta Integrations$/i, /^telemetry-okta-poller$/i,
  ...String(process.env.ACTIVITY_INFRA_PRINCIPALS || '').split(',').map(s => s.trim()).filter(Boolean)
    .map(s => new RegExp(`^${s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i')),
]

// Names that mark a non-human principal as an AI agent / agent tooling when Okta's own
// signals (actor.type=Agent, subjectProfile=ai_agent, id_jag, ciba, agent_gateway.*) are absent.
const AGENT_NAME_HINTS = /claude|agent|hermes|nesh|echo|claw|helper|copilot|assistant|bot\b|gateway for local/i

const ROUTINE_PREFIXES = [
  'user.session.', 'user.authentication.', 'policy.evaluate_sign_on', 'app.oauth2.authorize',
  'app.oauth2.as.authorize', 'security.request.blocked', 'system.push.send_factor_verify_push',
]
const INFRA_PREFIXES = [
  'system.import.', 'system.agent.', 'application.provision.', 'system.email.', 'directory.',
  'application.user_membership.', 'workflows.', 'inline_hook.', 'application.cache.',
  'app.user_management.', 'system.client.rate_limit', 'application.configuration.',
]
const PRIVILEGED_PREFIXES = [
  'pam.', 'user.lifecycle.', 'user.account.', 'user.mfa.', 'policy.', 'application.lifecycle.',
  'app.oauth2.client.', 'app.oauth2.credentials.', 'app.oauth2.admin.consent', 'security.',
  'access.request.', 'group.', 'resource.', 'device.enrollment', 'device.lifecycle', 'device.user',
  'system.idp.', 'user.realm.', 'application.', 'system.api_token.', 'system.org.',
]

const GRANT_CIBA = 'urn:openid:params:grant-type:ciba'
const GRANT_TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
const GRANT_JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer'

const dd = ev => ev?.debugContext?.debugData || {}
const targets = ev => Array.isArray(ev?.target) ? ev.target : []
const targetOf = (ev, type) => targets(ev).find(t => t?.type === type) || null
const isInfraName = name => INFRA_PRINCIPALS.some(re => re.test(String(name || '')))
const shortIso = iso => (iso || '').replace(/\.\d+Z$/, 'Z')
const clip = (s, n = 90) => { s = String(s ?? ''); return s.length > n ? s.slice(0, n - 1) + '…' : s }
const scopesOf = ev => String(dd(ev).grantedScopes || dd(ev).requestedScopes || '').split(/[,\s]+/).filter(Boolean)

/** Human the event is about: a User actor, else the first User target, else an id_jag subject. */
export function humanOf(ev) {
  const a = ev?.actor
  if (a?.type === 'User' && /^00u/.test(a.id || '')) return { id: a.id, name: a.displayName || a.alternateId, login: a.alternateId }
  const t = targetOf(ev, 'User')
  if (t && /^00u/.test(t.id || '')) return { id: t.id, name: t.displayName || t.alternateId, login: t.alternateId }
  const jag = targetOf(ev, 'id_jag')
  if (jag?.detailEntry?.subject) return { id: jag.detailEntry.subject, name: jag.detailEntry.subject, login: null }
  return null
}

/** Non-human principal (agent, client app, connector) for the event, if any. */
export function principalOf(ev) {
  const a = ev?.actor
  if (!a) return null
  if (a.type === 'Agent' || a.type === 'PublicClientApp' || a.type === 'ServicePrincipal' || a.type === 'SystemPrincipal') {
    return { id: a.id, name: a.displayName || a.alternateId || a.id, type: a.type, profile: a.detailEntry?.subjectProfile || null }
  }
  return null
}

/**
 * Classify one System Log event.
 * tier: agent | privileged | infra | routine | service | other
 * mode (agent tier only): interactive (on behalf of a human) | autonomous (workload identity)
 */
export function classifyEvent(ev) {
  const et = ev?.eventType || ''
  const g = dd(ev).grantType || ''
  const p = principalOf(ev)
  const human = humanOf(ev)
  const infra = p ? isInfraName(p.name) : false
  const agentSignal =
    ev?.actor?.type === 'Agent' ||
    p?.profile === 'ai_agent' ||
    et.startsWith('agent_gateway.') ||
    et === 'app.oauth2.token.grant.id_jag' ||
    Boolean(targetOf(ev, 'id_jag')) ||
    g === GRANT_CIBA || g === GRANT_TOKEN_EXCHANGE ||
    (et === 'device.custom_push.send_notification' && /\/bc\/authorize/.test(dd(ev).requestUri || dd(ev).url || '')) ||
    (et.startsWith('access.request.') && /^\[[a-z_]+\]/.test(targets(ev).map(t => t?.displayName || '').join(' ')))

  if (!infra && agentSignal) {
    const mode = human || g === GRANT_CIBA || Boolean(targetOf(ev, 'id_jag')) ? 'interactive' : 'autonomous'
    return { tier: 'agent', mode, kind: agentKind(ev, g), human, principal: p }
  }
  if (!infra && p && AGENT_NAME_HINTS.test(p.name) && (g === 'client_credentials' || g === GRANT_JWT_BEARER || et.startsWith('app.oauth2.'))) {
    // e.g. Claw Directory Agent / Echo-Infra / claude-tenant-reader minting their own tokens, or
    // Claude Code (MCP clients) refreshing its MCP OAuth token.
    return { tier: 'agent', mode: human ? 'interactive' : 'autonomous', kind: agentKind(ev, g), human, principal: p }
  }
  if (infra || INFRA_PREFIXES.some(x => et.startsWith(x))) return { tier: 'infra', kind: et, human, principal: p }
  if (ROUTINE_PREFIXES.some(x => et.startsWith(x))) return { tier: 'routine', kind: et, human, principal: p }
  if (et.startsWith('app.oauth2.') && (g === 'authorization_code' || g === 'refresh_token' || g === '' )) {
    // Browser SSO token issuance for ordinary apps is routine unless a non-human principal did it.
    if (!p || ev?.actor?.type === 'User') return { tier: 'routine', kind: et, human, principal: p }
    return { tier: 'service', kind: et, human, principal: p }
  }
  if (PRIVILEGED_PREFIXES.some(x => et.startsWith(x))) return { tier: 'privileged', kind: et, human, principal: p }
  if (p && !human) return { tier: 'service', kind: et, human, principal: p }
  return { tier: 'other', kind: et, human, principal: p }
}

function agentKind(ev, g) {
  const et = ev?.eventType || ''
  if (et.startsWith('agent_gateway.')) return 'mcp_tool_call'
  if (et === 'device.custom_push.send_notification') return 'ciba_push'
  if (g === GRANT_CIBA) return ev.outcome?.result === 'SUCCESS' ? 'ciba_token' : 'ciba_poll'
  if (et === 'app.oauth2.token.grant.id_jag') return 'id_jag_issued'
  if (targetOf(ev, 'id_jag')) return 'id_jag_redeemed'
  if (g === GRANT_TOKEN_EXCHANGE) return 'token_exchange'
  if (et.startsWith('access.request.')) return 'access_request'
  if (g === 'client_credentials') return 'workload_token'
  if (g === GRANT_JWT_BEARER) return 'workload_token'
  if (g === 'refresh_token') return 'token_refresh'
  return et
}

/** One-line English rendering of an event (≤ ~170 chars) that a small model can paraphrase. */
export function describeEvent(ev, cls = classifyEvent(ev)) {
  const t = shortIso(ev.published)
  const ok = ev.outcome?.result || '?'
  const okTxt = ok === 'SUCCESS' ? '' : ` [${ok}${ev.outcome?.reason ? ': ' + ev.outcome.reason : ''}]`
  const ip = ev.client?.ipAddress ? ` from ${ev.client.ipAddress}` : ''
  const ua = ev.client?.userAgent?.rawUserAgent ? ` (ua ${clip(ev.client.userAgent.rawUserAgent, 28)})` : ''
  const who = cls.human?.name || null
  const P = cls.principal?.name || ev.actor?.displayName || 'unknown'
  const d = dd(ev)
  const sc = scopesOf(ev)
  const scTxt = sc.length ? ` scopes=${clip(sc.join(' '), 70)}` : ''
  switch (cls.kind) {
    case 'ciba_push':
      return `${t} CIBA approval push sent to ${who || 'user'} via ${d.authenticatorName || 'custom authenticator'}/${d.pushProviderName || d.pushProviderType || 'push'}${d.risk ? ' risk=' + clip(d.risk, 40) : ''}${okTxt}${ip}`
    case 'ciba_token':
      return `${t} ${P} obtained a token FOR ${who || 'user'} via CIBA (human approved on phone)${scTxt}${ip}${ua}`
    case 'ciba_poll':
      return `${t} ${P} polled CIBA for ${who || 'user'}${okTxt}${ip}`
    case 'id_jag_issued':
      return `${t} ${P} (${cls.principal?.profile || 'agent'}) was issued an ID-JAG for ${who || 'user'} (XAA hop 1)${scTxt}${ip}`
    case 'id_jag_redeemed':
      return `${t} ${P} redeemed an ID-JAG for ${who || 'user'} → delegated access token (XAA hop 2)${scTxt}${ip}${ua}`
    case 'token_exchange':
      return `${t} ${P} token-exchange${who ? ' on behalf of ' + who : ''}${d.tokenExchangeType ? ' (' + d.tokenExchangeType + ')' : ''}${d.resource ? ' resource=' + clip(d.resource, 50) : ''}${scTxt}${okTxt}${ip}${ua}`
    case 'mcp_tool_call': {
      const vs = targetOf(ev, 'VIRTUAL_MCP_SERVER')?.displayName, ts = targetOf(ev, 'TARGET_MCP_SERVER')?.displayName
      return `${t} Agent ${P} called an MCP tool via Okta Agent Gateway${vs ? ' ' + vs : ''}${ts ? ' → ' + ts : ''}${d.toolName ? ' tool=' + d.toolName : ''}${okTxt}`
    }
    case 'access_request':
      return `${t} ${ev.eventType.replace('access.request.', 'access request ')} by ${who || P}: ${clip(targets(ev).map(x => x?.displayName).filter(Boolean).join(' | '), 80)}${okTxt}`
    case 'workload_token':
      return `${t} ${P} minted its own token (${d.grantType === 'client_credentials' ? 'client_credentials' : 'jwt-bearer'}, autonomous)${scTxt}${okTxt}${ip}${ua}`
    case 'token_refresh':
      return `${t} ${P} refreshed a token${who ? ' for ' + who : ''}${d.resource ? ' resource=' + clip(d.resource, 50) : ''}${ip}${ua}`
  }
  const et = ev.eventType || ''
  if (et === 'pam.user_creds.issue') return `${t} OPA issued server credentials to ${who || P} for ${d.serverHostnames || 'server'}${d.mfaChallengeCompleted === 'true' ? ' (MFA ok)' : ''}${d.clientIp ? ' from ' + d.clientIp : ip}${ua}`
  if (et === 'pam.server.ssh_login') return `${t} OPA SSH login as ${d.unixUserName || ev.actor?.displayName} on ${targetOf(ev, 'Server')?.displayName || 'server'}${d.fromAddress ? ' from ' + d.fromAddress : ''}${okTxt}`
  if (et === 'pam.secret.reveal') return `${t} OPA secret REVEALED by ${who || P}: ${targetOf(ev, 'Secret Path')?.displayName || targetOf(ev, 'Secret')?.displayName || 'secret'}${okTxt}${ip}`
  if (et === 'pam.auth_token.issue') return `${t} OPA web session token for ${who || P} (team ${d.teamName || '?'})${ip}`
  if (et.startsWith('pam.')) return `${t} OPA ${ev.displayMessage || et} by ${who || P}: ${clip(targets(ev).map(x => x?.displayName).filter(Boolean).join(' | '), 70)}${okTxt}`
  const tg = targets(ev).filter(x => x?.displayName && x.type !== 'access_token' && x.type !== 'id_token').map(x => `${x.type}:${x.displayName}`)
  return `${t} ${et} by ${who || P}${tg.length ? ' → ' + clip(tg.join(', '), 80) : ''}${okTxt}${ip}`
}

/** Compact projection of a raw event for ad-hoc log queries (≈250 bytes instead of ≈3 KB). */
export function compactEvent(ev) {
  const cls = classifyEvent(ev)
  const d = dd(ev)
  const out = {
    t: shortIso(ev.published), eventType: ev.eventType, outcome: ev.outcome?.result,
    tier: cls.tier, kind: cls.kind !== ev.eventType ? cls.kind : undefined,
    actor: ev.actor ? `${ev.actor.type}:${ev.actor.displayName || ev.actor.alternateId || ev.actor.id}` : undefined,
    user: cls.human?.name || undefined,
    ip: ev.client?.ipAddress || undefined,
    ua: ev.client?.userAgent?.rawUserAgent ? clip(ev.client.userAgent.rawUserAgent, 40) : undefined,
    grantType: d.grantType || undefined, scopes: scopesOf(ev).join(' ') || undefined,
    target: targets(ev).filter(x => x?.displayName && !/token/i.test(x.type)).slice(0, 4).map(x => `${x.type}:${x.displayName}`).join(' | ') || undefined,
    reason: ev.outcome?.reason || undefined,
    opa: d.serverHostnames || d.unixUserName || undefined,
    summary: describeEvent(ev, cls),
  }
  for (const k of Object.keys(out)) if (out[k] === undefined) delete out[k]
  return out
}

/**
 * Fetch a bounded window of the System Log (since..until ⇒ Okta returns ASC order and a finite
 * `next` chain). Pages until exhausted, maxPages or maxEvents. Read-only.
 */
export async function fetchOktaLogs({ oktaBase, token, since, until, filter, q, limit = 1000, maxPages = 16, maxEvents = 16000, sortOrder = 'DESCENDING' }) {
  const base = String(oktaBase || '').replace(/\/$/, '')
  const params = new URLSearchParams()
  params.set('since', since)
  params.set('until', until || new Date().toISOString())
  params.set('limit', String(Math.min(1000, Math.max(1, limit))))
  params.set('sortOrder', sortOrder) // DESCENDING: when the cap hits, the OLDEST events are the ones dropped
  if (filter) params.set('filter', filter)
  if (q) params.set('q', q)
  let url = `${base}/api/v1/logs?${params.toString()}`
  const events = []
  let pages = 0, truncated = false
  while (url && pages < maxPages) {
    const res = await fetch(url, { headers: { Authorization: `SSWS ${token}`, Accept: 'application/json' } })
    const text = await res.text()
    if (!res.ok) {
      let detail = text; try { detail = JSON.parse(text)?.errorSummary || text } catch {}
      throw new Error(`Okta /logs ${res.status}: ${clip(detail, 200)}`)
    }
    const page = JSON.parse(text)
    pages++
    if (!Array.isArray(page) || page.length === 0) break
    events.push(...page)
    if (events.length >= maxEvents) { truncated = true; break }
    const link = res.headers.get('link') || ''
    const m = link.match(/<([^>]+)>;\s*rel="next"/)
    url = m ? m[1] : null
    if (page.length < Math.min(1000, limit)) break
  }
  if (url && pages >= maxPages) truncated = true
  const times = events.map(e => e.published).filter(Boolean).sort()
  return { events, pages, truncated, coveredFrom: times[0] || null, coveredTo: times[times.length - 1] || null }
}

const byTime = (a, b) => String(a.published).localeCompare(String(b.published))
const inc = (m, k) => { m[k] = (m[k] || 0) + 1 }
const topN = (m, n) => Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => ({ name: k, count: v }))
const hhmm = iso => shortIso(iso).slice(11)

// Step family: hop 1 + hop 2 of an XAA exchange are one step; repeated identical steps collapse.
function familyOf(cls, ev) {
  const k = cls.kind
  if (k === 'id_jag_issued' || k === 'id_jag_redeemed') return 'xaa'
  if (k === 'access_request' || k === 'ciba_push') return `${k}:${ev.uuid || ev.published}` // never merged
  return k
}

/**
 * Collapse runs of the same step (same principal, human, family) whose events are ≤ 30 min apart
 * into one line with "×N" so a six-call agent session reads as one sentence, not twelve.
 * items: [{ t, key, family, kind, line, principal, human, scopes, ip, fail }]
 */
function coalesce(items, gapMs = 30 * 60 * 1000) {
  const groups = [], byKey = new Map()
  for (const it of items) {
    const tt = Date.parse(it.t)
    let g = byKey.get(it.key)
    if (!g || tt - g.lastT > gapMs) {
      g = { ...it, firstT: tt, lastT: tt, last: it.t, n: 0, fails: 0, kinds: {}, scopes: new Set(), ips: new Set() }
      groups.push(g); byKey.set(it.key, g)
    }
    g.n++; g.lastT = tt; g.last = it.t; if (it.fail) g.fails++; inc(g.kinds, it.kind)
    ;(it.scopes || []).forEach(s => g.scopes.add(s)); if (it.ip) g.ips.add(it.ip)
  }
  return groups.map(g => {
    if (g.n === 1) return g.line
    const scopes = g.scopes.size ? ` scopes=${clip([...g.scopes].join(' '), 70)}` : ''
    const ips = g.ips.size ? ` from ${[...g.ips].slice(0, 2).join(',')}` : ''
    const fails = g.fails ? `, ${g.fails} failed` : ''
    if (g.family === 'xaa') {
      return `${shortIso(g.t)}–${hhmm(g.last)} ${g.principal} acted FOR ${g.human || 'user'} via XAA/ID-JAG delegation (issued ×${g.kinds.id_jag_issued || 0}, redeemed ×${g.kinds.id_jag_redeemed || 0}${fails})${scopes}${ips}`
    }
    return `${g.line} ×${g.n} through ${hhmm(g.last)}${fails}`
  })
}

/**
 * Build the compact report. `detail` = 'brief' (small models, target ≤ 8 KB) | 'full' (≤ 16 KB).
 * `user` (optional) restricts chains/lines to humans whose name/login/id contains it.
 */
export function buildActivityReport(events, { since, until, detail = 'full', user = null, fetched = {} } = {}) {
  const brief = detail === 'brief'
  const big = events.length > 5000 // week-sized windows: keep the digest readable for small models
  const LIM = brief ? (big ? { lines: 14, chains: 4, chainTl: 7, priv: 8, anomalies: 8, users: 5, auto: 8 } : { lines: 18, chains: 5, chainTl: 10, priv: 8, anomalies: 8, users: 5, auto: 8 }) : { lines: 45, chains: 12, chainTl: 25, priv: 25, anomalies: 20, users: 12, auto: 20 }
  const evs = [...events].sort(byTime).map(ev => ({ ev, cls: classifyEvent(ev) }))
  const userMatch = h => !user || (h && [h.name, h.login, h.id].some(x => x && String(x).toLowerCase().includes(String(user).toLowerCase())))

  const counts = { total: evs.length, agent: 0, agentInteractive: 0, agentAutonomous: 0, privileged: 0, infra: 0, routine: 0, service: 0, other: 0, failures: 0 }
  const autonomous = {}, infra = {}, routineByUser = {}, servicePrincipals = {}, agentsSeen = {}
  const interactiveItems = [], privItems = [], anomalies = [], mcpItems = [], cibaApprovals = []
  const people = {} // every human with any event: sign-ins / privileged / agent / OPA counts
  let ev = null
  const person = (h, k) => { if (!h) return; const key = h.id || h.login || h.name; const p = people[key] = people[key] || { name: h.name, logins: new Set(), signIns: 0, privileged: 0, agentUse: 0, opa: 0, last: '' }; if (h.login) p.logins.add(h.login); p[k]++; if (ev.published > p.last) p.last = ev.published }
  const chains = new Map()
  const chainFor = h => {
    const key = h.id || h.name
    if (!chains.has(key)) chains.set(key, { user: h.name, login: h.login || undefined, agents: {}, opaServers: {}, cibaApprovals: 0, accessRequests: 0, ips: {}, items: [] })
    return chains.get(key)
  }
  const recentCreds = [] // attribute anonymous OPA ssh logins to a recent credential issue from the same IP

  for (const { ev: _ev, cls } of evs) {
    ev = _ev
    const et = ev.eventType || ''
    const d = dd(ev)
    if (cls.tier === 'agent' && cls.mode === 'interactive') person(cls.human, 'agentUse')
    else if (cls.tier === 'privileged') person(cls.human, et.startsWith('pam.') ? 'opa' : 'privileged')
    else if (cls.tier === 'routine') person(cls.human, 'signIns')
    // CHALLENGE (DPoP nonce, step-up prompts) and CIBA 'pending' polls are normal protocol traffic, not failures.
    const fail = /^(FAILURE|DENY)$/.test(ev.outcome?.result || '') && !/^(ciba_authorization_pending|authorization_pending|slow_down)$/.test(ev.outcome?.reason || '')
    if (fail) counts.failures++
    counts[cls.tier] = (counts[cls.tier] || 0) + 1
    const pname = cls.principal?.name
    const ip = ev.client?.ipAddress
    const item = () => ({ t: ev.published, key: `${pname || ''}|${cls.human?.id || cls.human?.name || ''}|${familyOf(cls, ev)}`, family: familyOf(cls, ev), kind: cls.kind, line: describeEvent(ev, cls), principal: pname, human: cls.human?.name, scopes: scopesOf(ev), ip, fail })

    if (cls.tier === 'agent') {
      if (pname) inc(agentsSeen, pname)
      if (cls.mode === 'autonomous') {
        counts.agentAutonomous++
        const k = `${pname || 'unknown'} · ${cls.kind}${d.grantType ? ' · ' + d.grantType.replace('urn:ietf:params:oauth:grant-type:', '') : ''}`
        autonomous[k] = autonomous[k] || { principal: pname || 'unknown', kind: cls.kind, grantType: (d.grantType || '').replace('urn:ietf:params:oauth:grant-type:', '') || undefined, count: 0, failures: 0, ips: {}, first: ev.published, last: ev.published, scopes: scopesOf(ev).slice(0, 8).join(' ') || undefined }
        const a = autonomous[k]; a.count++; if (fail) a.failures++; if (ip) inc(a.ips, ip); a.last = ev.published
        if (fail && anomalies.length < LIM.anomalies) anomalies.push(describeEvent(ev, cls))
        continue
      }
      counts.agentInteractive++
      if (!userMatch(cls.human)) continue
      if (cls.kind === 'ciba_poll') { if (fail) anomalies.push(describeEvent(ev, cls)); continue }
      if (cls.kind === 'token_refresh') { if (cls.human) { const c = chainFor(cls.human); if (pname) { c.agents[pname] = c.agents[pname] || { kinds: {}, scopes: new Set(), first: ev.published, last: ev.published, ips: {} }; const a = c.agents[pname]; inc(a.kinds, cls.kind); scopesOf(ev).forEach(s => a.scopes.add(s)); a.last = ev.published; if (ip) inc(a.ips, ip) } } continue } // counted in agents[], not narrated
      const it = item()
      if (cls.kind === 'mcp_tool_call') mcpItems.push(it)
      else if (cls.kind === 'ciba_push') cibaApprovals.push(it.line)
      else interactiveItems.push(it)
      if (fail && anomalies.length < LIM.anomalies) anomalies.push(it.line)
      if (d.risk && /HIGH/.test(d.risk) && anomalies.length < LIM.anomalies) anomalies.push(`risk HIGH: ${it.line}`)
      if (cls.human) {
        const c = chainFor(cls.human)
        if (pname) { c.agents[pname] = c.agents[pname] || { kinds: {}, scopes: new Set(), first: ev.published, last: ev.published, ips: {} }; const a = c.agents[pname]; inc(a.kinds, cls.kind); scopesOf(ev).forEach(s => a.scopes.add(s)); a.last = ev.published; if (ip) inc(a.ips, ip) }
        if (cls.kind === 'ciba_push') c.cibaApprovals++
        if (cls.kind === 'access_request') c.accessRequests++
        if (ip) inc(c.ips, ip)
        c.items.push(it)
      }
      continue
    }

    if (cls.tier === 'privileged') {
      if (!userMatch(cls.human)) continue
      if (et.startsWith('pam.')) {
        // OPA: fold into the human's chain so "SSH'd via OPA to X" sits next to the agent activity.
        let h = cls.human
        if (et === 'pam.user_creds.issue' && h) recentCreds.push({ t: Date.parse(ev.published), ip: d.clientIp || ip, h, host: d.serverHostnames })
        if (et === 'pam.server.ssh_login' && !h && d.fromAddress) {
          const t0 = Date.parse(ev.published)
          const m = [...recentCreds].reverse().find(r => r.ip === d.fromAddress && t0 - r.t < 15 * 60 * 1000)
          if (m) h = m.h
        }
        const it = item()
        if (h) {
          it.key = `opa|${h.id || h.name}|${et}|${d.unixUserName || ''}|${d.serverHostnames || targetOf(ev, 'Server')?.displayName || ''}`
          const c = chainFor(h)
          const host = d.serverHostnames || targetOf(ev, 'Server')?.displayName
          if (host && (et === 'pam.user_creds.issue' || et === 'pam.server.ssh_login')) inc(c.opaServers, host)
          if (et !== 'pam.auth_token.issue') c.items.push(it)
        }
        if (et === 'pam.secret.reveal' || et === 'pam.server.ssh_login' || et === 'pam.user_creds.issue') privItems.push(it)
      } else {
        const it = item(); it.key = `${cls.human?.id || pname || ''}|${et}|${targets(ev).map(x => x?.displayName).join(',')}`; privItems.push(it)
      }
      if (fail && anomalies.length < LIM.anomalies) anomalies.push(describeEvent(ev, cls))
      continue
    }

    if (cls.tier === 'infra') { inc(infra, pname || et.split('.').slice(0, 2).join('.')); continue }
    if (cls.tier === 'routine') { inc(routineByUser, cls.human?.name || 'unknown'); continue }
    if (cls.tier === 'service') {
      inc(servicePrincipals, pname || 'unknown')
      if ((fail || /unknown client/i.test(pname || '')) && anomalies.length < LIM.anomalies) anomalies.push(describeEvent(ev, cls))
      continue
    }
  }

  const chainList = [...chains.values()].map(c => ({
    user: c.user, login: c.login,
    agents: Object.entries(c.agents).map(([name, a]) => ({ agent: name, actions: a.kinds, scopes: [...a.scopes].slice(0, 10).join(' ') || undefined, from: Object.keys(a.ips).slice(0, 3).join(',') || undefined, first: shortIso(a.first), last: shortIso(a.last) })),
    opaServers: Object.keys(c.opaServers).length ? c.opaServers : undefined,
    cibaApprovals: c.cibaApprovals || undefined, accessRequests: c.accessRequests || undefined,
    sourceIps: Object.keys(c.ips).slice(0, 4).join(',') || undefined,
    timeline: coalesce(c.items.sort((a, b) => a.t.localeCompare(b.t))).slice(-LIM.chainTl),
  })).sort((a, b) => b.timeline.length - a.timeline.length).slice(0, LIM.chains)

  const interactiveLines = coalesce(interactiveItems)
  const routineTotal = Object.values(routineByUser).reduce((a, b) => a + b, 0)
  const report = {
    window: { since, until, hours: since && until ? Math.round((Date.parse(until) - Date.parse(since)) / 36e5 * 10) / 10 : undefined },
    fetched: { events: counts.total, ...fetched },
    headline: {
      aiAgentEvents: counts.agent, humanDrivenAgentEvents: counts.agentInteractive, autonomousWorkloadEvents: counts.agentAutonomous,
      privilegedHumanEvents: counts.privileged, oktaInfrastructureEvents: counts.infra, routineSignInEvents: counts.routine, failures: counts.failures,
      agentsSeen: topN(agentsSeen, 12).map(x => `${x.name} (${x.count})`),
    },
    humanDrivenAgentActivity: interactiveLines.length > LIM.lines ? [...interactiveLines.slice(-LIM.lines), `(+${interactiveLines.length - LIM.lines} earlier steps omitted — see chainsByHuman or narrow with user=/since=)`] : interactiveLines,
    cibaApprovals: cibaApprovals.slice(-LIM.priv),
    mcpToolCalls: coalesce(mcpItems).slice(-LIM.priv),
    autonomousWorkloads: Object.values(autonomous).sort((a, b) => b.count - a.count).slice(0, LIM.auto).map(a => ({ ...a, ips: Object.keys(a.ips).slice(0, 3).join(','), first: shortIso(a.first), last: shortIso(a.last) })),
    chainsByHuman: chainList,
    privilegedHumanActivity: coalesce(privItems).slice(-LIM.priv),
    anomalies: [...new Set(anomalies)].slice(0, LIM.anomalies),
    routineSignIns: { total: routineTotal, users: Object.keys(routineByUser).length, byUser: topN(routineByUser, brief ? 40 : 80).map(x => `${x.name}:${x.count}`).join(', ') },
    peopleSeen: Object.values(people).sort((a, b) => (b.signIns + b.privileged + b.agentUse + b.opa) - (a.signIns + a.privileged + a.agentUse + a.opa)).slice(0, brief ? 40 : 80).map(p => `${p.name}${p.logins.size ? ' <' + [...p.logins].join(', ') + '>' : ''}: signIns ${p.signIns}, privileged ${p.privileged}, agentUse ${p.agentUse}, opa ${p.opa}, last ${shortIso(p.last)}`),
    warnings: fetched.truncated ? [`Event cap reached: only the most recent ${counts.total} events were analysed, covering ${shortIso(fetched.coveredFrom)} to ${shortIso(fetched.coveredTo)} — NOT the full window since ${shortIso(since)}. Say so, and narrow with since/until or user= for the earlier part.`] : [],
    oktaInfrastructure: topN(infra, brief ? 5 : 10),
    otherServicePrincipals: topN(servicePrincipals, brief ? 5 : 10),
    notes: [
      'OPA (Okta Privileged Access) audit = the pam.* events in this same System Log.',
      'Active Directory Agent / OPS Agent / OPA & IGA connectors are Okta infrastructure, NOT AI agents.',
      'humanDrivenAgentActivity = an AI agent acted on behalf of a signed-in human (ID-JAG/XAA, CIBA, token-exchange, Agent Gateway). "×N" = the same step repeated N times.',
      'autonomousWorkloads = non-human identities minting their own tokens (client_credentials / jwt-bearer) with no human in the loop.',
      'peopleSeen lists EVERY person with any event in the window; someone absent from it had no Okta/OPA events at all in the window (that is not the same as never having logged in — use directory_roster for lastLogin).',
    ],
  }
  if (brief) { delete report.oktaInfrastructure; delete report.otherServicePrincipals; report.notes = [report.notes[0], report.notes[1], report.notes[4]] }
  return report
}
