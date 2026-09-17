import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import morgan from 'morgan'
import session from 'express-session'
import cookieParser from 'cookie-parser'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { randomUUID, createHmac, timingSafeEqual } from 'crypto'
import { getDelegatedAccessToken, getVaultedSecret } from './lib/agentTokenExchange.js'
import { makePkce, buildAuthUrl, exchangeCode, verifyIdToken } from './lib/oidc.js'
import { createAccessRequest, getAccessRequest, isAccessRequestTerminal } from './lib/oktaAccessRequests.js'
import {
  buildAccessRequestRecord,
  maybeFulfillApprovedRequest,
  portalStatusAfterFulfillment,
} from './lib/accessRequestFulfillment.js'
import { AccessRequestStore } from './lib/accessRequestStore.js'
import { dataDir } from './lib/dataDir.js'
import { ensureSessionIdToken, idTokenExpiresAt, sessionIdTokenStatus } from './lib/sessionIdToken.js'
import fileStoreFactory from 'session-file-store'
import { mountMcpRoutes } from './lib/mcpHttp.js'
import { fetchOktaLogs, buildActivityReport, compactEvent } from './lib/agentActivity.js'
import { directoryRoster } from './lib/directoryRoster.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

dotenv.config({ path: join(__dirname, '.env.local') })
dotenv.config({ path: join(__dirname, '.env') })

console.log('RAW DEMO_AUTH_BYPASS from process.env =', JSON.stringify(process.env.DEMO_AUTH_BYPASS))

const app = express()
const PORT = process.env.API_PORT || 3201

// Trust proxy for reverse proxy / pm2 setups
app.set('trust proxy', 1)

// Middleware
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'https://ai-admin.skylarbarnes.com',
    process.env.WEB_ORIGIN,
  ].filter(Boolean),
  credentials: true,
}))
// Capture the raw body so the flo-callback route can HMAC-verify the exact bytes Okta signed.
app.use(express.json({ limit: '2mb', verify: (req, _res, buf) => { req.rawBody = buf } }))
app.use(cookieParser())
app.use(morgan('combined'))

// File-backed access-request cache — action payloads + status survive restarts.
const accessRequestStatus = new AccessRequestStore()
const FileStore = fileStoreFactory(session)
const sessionStore = new FileStore({
  path: join(dataDir(), 'sessions'),
  ttl: 60 * 60 * 12, // 12 hours (seconds)
  retries: 0,
  logFn: () => {},
})

async function resolveAccessRequestStatus(requestId, req) {
  const cached = accessRequestStatus.get(requestId)
  const live = await getAccessRequest(requestId)
  let idToken = null
  try {
    idToken = await ensureSessionIdToken(req)
  } catch (e) {
    if (e.code === 'SESSION_ID_TOKEN_EXPIRED' || e.code === 'SESSION_NO_ID_TOKEN') {
      // Still return live Okta status; skip fulfillment until admin re-authenticates.
    } else {
      throw e
    }
  }
  const execution = idToken
    ? await maybeFulfillApprovedRequest(requestId, live, { idToken, accessRequestStatus })
    : null
  const updated = accessRequestStatus.get(requestId) || cached || {}
  const status = portalStatusAfterFulfillment(updated, live, execution)
  const record = {
    ...updated,
    status,
    oktaStatus: live.oktaStatus,
    grantStatus: live.grantStatus ?? null,
    requestApproval: live.requestApproval ?? null,
    links: live.links,
    correlationId: updated.correlationId || cached?.correlationId || null,
    execution: updated.execution || execution || null,
    updatedAt: new Date().toISOString(),
    source: 'okta',
    terminal: isAccessRequestTerminal(status),
    apiVersion: live.apiVersion,
  }
  accessRequestStatus.set(requestId, record)
  return { requestId, ...record }
}

function shutdownPersist() {
  accessRequestStatus.flush()
}

process.on('SIGINT', () => { shutdownPersist(); process.exit(0) })
process.on('SIGTERM', () => { shutdownPersist(); process.exit(0) })

// Sessions (file-backed — survive api-server restarts)
app.use(session({
  name: 'sdap.sid',
  store: sessionStore,
  secret: process.env.SESSION_SECRET || 'dev-only-insecure-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',   // must be true when using https://
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    domain: process.env.COOKIE_DOMAIN || undefined,  // '.skylarbarnes.com' for ai-admin ↔ ai-admin-api
    maxAge: 1000 * 60 * 60 * 12, // 12 hours
  },
}))

// Auth gate for privileged endpoints. Honors DEMO_AUTH_BYPASS, otherwise
// requires an established session (set by the OIDC callback).
function requireAuth(req, res, next) {
  if (process.env.DEMO_AUTH_BYPASS === 'true') return next()
  if (req.session?.user) return next()
  return res.status(401).json({ error: 'Not authenticated' })
}

// ----------------------
// Health
// ----------------------
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'sdap-api',
    org: 'sledai.oktapreview.com',
    demoBypass: process.env.DEMO_AUTH_BYPASS === 'true',
    llm: {
      gateway: llmGatewayConfigured(),
      defaultModel: resolveChatModel().id,
    },
    persistence: {
      dataDir: dataDir(),
      accessRequestRecords: accessRequestStatus.size(),
      sessionsDir: join(dataDir(), 'sessions'),
    },
  })
})

app.get('/api/auth/me', (req, res) => {
  if (process.env.DEMO_AUTH_BYPASS === 'true') {
    return res.json({
      user: { id: 'demo-1', email: 'alex.rivera@sledai.com', name: 'Alex Rivera', role: 'Super Admin (Demo Bypass)' },
      authMode: 'DEMO_BYPASS',
    })
  }
  if (req.session?.user) {
    const tokenStatus = sessionIdTokenStatus(req.session)
    return res.json({
      user: req.session.user,
      authMode: (req.session.user.authMethod || 'oidc').toUpperCase(),
      idToken: tokenStatus,
      needsReauth: tokenStatus.expired,
      hasRefreshToken: Boolean(req.session.refresh_token),
    })
  }
  res.status(401).json({ error: 'Not authenticated' })
})

// ----------------------
// Chat models. Every model goes through the OpenAI-compatible LLM gateway
// (LiteLLM), which tracks usage per demo site. gemma4 is self-hosted; grok-4.3
// is xAI. Public: the splash/UI calls this before authentication. The entry
// flagged `default` is CHAT_DEFAULT_MODEL, which the UI preselects.
// ----------------------
const CHAT_MODELS = [
  { id: 'gemma4', label: 'Gemma 4 (self-hosted)', provider: 'litellm' },
  { id: 'grok-4.3', label: 'Grok 4.3 (xAI)', provider: 'litellm' },
]

function llmGatewayConfigured() {
  return Boolean(process.env.LLM_BASE_URL && process.env.LLM_API_KEY)
}

// Resolve strictly against CHAT_MODELS: an unknown model is ignored, so a
// crafted request can't reach anything else.
function resolveChatModel(requested) {
  const found = CHAT_MODELS.find(m => m.id === requested)
  if (requested && !found) {
    console.warn(`[chat] ignoring requested model "${requested}" — allowed: ${CHAT_MODELS.map(m => m.id).join(', ')}`)
  }
  return found
    ?? CHAT_MODELS.find(m => m.id === (process.env.CHAT_DEFAULT_MODEL || 'gemma4'))
    ?? CHAT_MODELS[0]
}

app.get('/api/available-models', (req, res) => {
  const defaultId = resolveChatModel().id
  res.json(llmGatewayConfigured() ? CHAT_MODELS.map(m => ({ ...m, default: m.id === defaultId })) : [])
})

// Shared XAA gate for chat tools and the activity route: valid session id_token ->
// delegated (human ∩ agent) token -> required scope. Returns {error,...} or {ok, granted}.
async function requireDelegatedScope(req, need) {
  let idToken
  try {
    idToken = await ensureSessionIdToken(req)
  } catch (e) {
    return { error: e.message, reauth: e.code === 'SESSION_ID_TOKEN_EXPIRED' || e.code === 'SESSION_NO_ID_TOKEN' }
  }
  let delegated
  try {
    delegated = await getDelegatedAccessToken({ idToken })
  } catch (e) {
    const reauth = /subject_token|invalid.*token/i.test(e.message)
    return {
      error: `Token exchange failed: ${e.message}`,
      ...(reauth ? { reauth: true, hint: 'Sign out and sign in again — your Okta id_token may have expired.' } : {}),
    }
  }
  const granted = (delegated.scope || '').split(' ').filter(Boolean)
  if (!granted.includes(need)) return { error: `Insufficient delegated scope — need ${need}, granted: ${granted.join(', ')}` }
  return { ok: true, granted, delegated }
}

function parseActivityWindow({ hours, since, until }) {
  const h = Math.min(168, Math.max(0.25, Number(hours) || 24))
  const u = until ? new Date(String(until)) : new Date()
  const s = since ? new Date(String(since)) : new Date(u.getTime() - h * 36e5)
  if (isNaN(s) || isNaN(u) || s >= u) return { error: 'Invalid window — since must be before until (ISO-8601, e.g. 2026-09-17T00:00:00Z).' }
  return { since: s.toISOString(), until: u.toISOString() }
}

async function runActivityReport({ since, until, detail, user }) {
  const { events, pages, truncated, coveredFrom, coveredTo } = await fetchOktaLogs({
    oktaBase: (process.env.OKTA_ORG_URL || '').replace(/\/$/, ''),
    token: process.env.OKTA_API_TOKEN,
    since, until,
  })
  return buildActivityReport(events, { since, until, detail, user: user || null, fetched: { pages, truncated, coveredFrom, coveredTo } })
}

const oktaCfg = () => ({ oktaBase: (process.env.OKTA_ORG_URL || '').replace(/\/$/, ''), token: process.env.OKTA_API_TOKEN })

// ----------------------
// Chat proxy to the LLM gateway
// ----------------------
app.post('/api/chat', requireAuth, async (req, res) => {
  // `provider` from older clients is ignored; everything goes through the gateway.
  const { messages = [], model } = req.body || {}

  const sessionUser = req.session?.user || {}

  const systemPrompt = [
    'You are the Okta Admin AI Agent for the Super Duper Admin Portal (sledai.oktapreview.com).',
    `You are operating on behalf of the signed-in administrator: ${sessionUser.name || 'unknown'} (${sessionUser.email || 'unknown'}).`,
    '',
    'IDENTITY & ACCESS — you are a registered Okta AI Agent (ID: wlpzd73wrostoEGIn1d7). You have',
    'delegated access to this org via Cross App Access (XAA / ID-JAG token exchange). This means',
    'you can make REAL API calls to the Okta org on behalf of the signed-in admin, scoped to the',
    'intersection of your granted scopes and the admin\'s entitlements. You are NOT limited to',
    'giving advice — you can retrieve live data.',
    '',
    'YOUR DELEGATED SCOPES (via the custom authorization server):',
    '  sdap.logs.read        — read the Okta System Log',
    '  sdap.users.read       — read users and their profiles',
    '  sdap.users.manage     — manage (update/suspend/unsuspend) users',
    '  sdap.act              — perform privileged agent actions',
    '',
    'AVAILABLE API ROUTES — call these via HTTP to the portal backend:',
    '',
    '  GET  /api/agent/okta/logs?since=<ISO8601>&until=<ISO8601>&filter=<expression>&limit=<n>',
    '       Fetches the Okta System Log on behalf of the signed-in admin. Uses the full XAA',
    '       token-exchange chain. "since" defaults to the last 24h if omitted.',
    '       Example: /api/agent/okta/logs?since=2026-05-30T00:00:00Z&limit=50',
    '',
    '  GET  /api/agent/okta/activity?hours=24&user=<login>&detail=brief|full',
    '       Pre-digested activity report (same data as the tenant_activity_report tool).',
    '  GET  /api/agent/okta/roster?group=<name|00g id>|role=SUPER_ADMIN&inactiveDays=30',
    '       Group/role membership with lastLogin + status (same data as the directory_roster tool).',
    '',
    '  GET  /api/agent/okta/me   (alias: /api/agent/registry)',
    '       Returns this agent\'s own Okta registration: client ID, org, granted scopes, app',
    '       profile, and (if AGENT_USER_ID is set) the agent\'s Okta service-account user.',
    '       Does NOT require an OIDC session — uses the portal\'s SSWS token directly.',
    '',
    '  GET  /api/agent/okta/users?limit=<n>&search=<expr>&filter=<expr>',
    '       Lists users from the org on behalf of the signed-in admin.',
    '',
    '  GET  /api/agent/okta/users/<userId>',
    '       Fetches a single Okta user by ID or login (XAA-gated, on behalf of the admin).',
    '',
    '  GET  /api/agent/okta/authorizationServers',
    '       Lists all custom authorization servers in the org.',
    '',
    '  GET  /api/agent/okta/authorizationServers/<authServerId>',
    '       Fetches a specific authorization server by ID.',
    '       Known auth server IDs in this org:',
    '         auszblykhlQkrnOmA1d7  (org authorization server)',
    '         auszhhgej85Ef57BT1d7',
    '         auszad6sd3mZh1jVA1d7  (SDAP custom resource authorization server)',
    '',
    '  GET  /api/agent/okta/authorizationServers/<authServerId>/scopes',
    '       Lists all custom scopes defined on an authorization server.',
    '       Example: /api/agent/okta/authorizationServers/auszad6sd3mZh1jVA1d7/scopes',
    '',
    '  GET  /api/agent/okta/authorizationServers/<authServerId>/claims',
    '       Lists all claims defined on an authorization server.',
    '',
    '  GET  /api/agent/okta/authorizationServers/<authServerId>/policies',
    '       Lists access policies on an authorization server.',
    '',
    '  GET  /api/okta/logs?since=<ISO8601>     (falls back to SSWS token — use agent routes above',
    '  GET  /api/okta/users?limit=<n>           when acting on behalf of the admin)',
    '',
    'HOW TO USE THEM: When the admin asks you to review logs, investigate activity, look up users,',
    'or report on agent/automated activity, you MUST fetch the data yourself by calling the',
    'appropriate /api/agent/okta/* route. Do not tell the admin to check themselves — retrieve the',
    'data and analyse it directly. Present findings clearly: summarise what you found, call out',
    'anomalies, and flag anything suspicious.',
    '',
    'ACTIVITY QUESTIONS — ALWAYS START WITH THE tenant_activity_report TOOL. For any broad or',
    'vague question ("what\'s going on in the tenant today", "anything interesting", "who is using',
    'agents", "what did the agents do", "show me AI/agent activity", "what ran overnight",',
    '"summarise the last N hours", "what has <user> been doing") call tenant_activity_report FIRST',
    '(hours=24 unless the admin said otherwise; pass user=<name or login> when they name a person).',
    'It reads the Okta System Log AND the OPA audit (pam.* events live in the same log), classifies',
    'every event and returns a pre-digested JSON report. Do NOT page through raw /logs for these',
    'questions. Use fetch_okta_data only afterwards, to drill into one user, client or event type.',
    '',
    'DIRECTORY QUESTIONS ARE NOT LOG QUESTIONS. "Who has / has not logged in", "never logged in",',
    '"last login", "inactive", "not activated", "who is in group X / who are the Super Admins" are',
    'answered from the user profile (lastLogin, status) via the directory_roster tool — pass',
    'group=<exact name or 00g… id> or role=SUPER_ADMIN (any Okta admin role). Never answer these',
    'from a log window: absence from a 7-day report only means no events in that window. If',
    'directory_roster returns needsClarification, list the candidate groups and ASK which one —',
    'never pick a "closest match". "Super Admins" with no group named = role=SUPER_ADMIN.',
    '',
    'REPORT HONESTY: if the activity report has a non-empty warnings[] (event cap reached), state',
    'the covered time range in your first sentence. peopleSeen lists every person with any event in',
    'the window — check it before saying someone "did not appear". When asked about one person, call',
    'tenant_activity_report again with user=<login> rather than reasoning from the summary.',
    '',
    'PRIORITY ORDER when reporting activity (highest first — lead with 1, keep 5 to one sentence):',
    '  1. humanDrivenAgentActivity + chainsByHuman — an AI agent acting FOR a human: XAA / ID-JAG',
    '     delegation, CIBA push approvals, token-exchange, Okta Agent Gateway MCP tool calls,',
    '     agent-created access requests, plus that human\'s OPA server access (creds issued / SSH).',
    '  2. anomalies — failures, HIGH risk, unknown clients, denied exchanges.',
    '  3. autonomousWorkloads — non-human identities minting their own tokens (client_credentials /',
    '     jwt-bearer) with no human in the loop. One line per principal with the count.',
    '  4. privilegedHumanActivity — lifecycle / policy / secret-reveal changes made by admins.',
    '  5. routineSignIns — ordinary SSO / MFA logins. Give the total in ONE sentence, never a list.',
    '  6. oktaInfrastructure — AD Agent, OPS Agent, OPA/IGA connectors, imports. Only if asked.',
    '',
    'HOW TO NARRATE A CHAIN: walk chainsByHuman[].timeline in time order and name the human, the',
    'agent, the mechanism (XAA/ID-JAG, CIBA, token-exchange, Agent Gateway), the scopes and the',
    'source IP, quoting timestamps as given. Example: "Skylar Barnes was issued OPA credentials for',
    'claude-home (MFA ok) at 21:32Z; Claude Code CIBA then obtained a token for Skylar via CIBA',
    '(approved on the phone) with scopes mcp.access mcp.write; Agent Claude-CLI-EC2 then called an',
    'MCP tool through the Agent Gateway." A "×N" suffix means the same step repeated N times.',
    'When asked to "walk me through" / "what did <user> do": reproduce that person\'s',
    'chainsByHuman[].timeline as a numbered list in time order (one step per line, keep the',
    'timestamps), then add one or two sentences of interpretation. Do not regroup it by category.',
    'Wording rules: OPA always means Okta Privileged Access (never "open source"); "workload token"',
    'means a token minted by a non-human identity; refer to people by name (no assumed pronouns);',
    'never invent numbers — every count you state must appear in the tool result.',
    '',
    'IDENTIFYING AGENTS vs HUMANS vs INFRASTRUCTURE in raw events (for drill-downs):',
    '  • actor.type "Agent" or actor.detailEntry.subjectProfile "ai_agent" = registered Okta AI agent',
    '  • target type "id_jag" / eventType app.oauth2.token.grant.id_jag = XAA delegation (agent FOR user)',
    '  • debugData.grantType urn:openid:params:grant-type:ciba = CIBA (human approved on their phone)',
    '  • debugData.grantType …grant-type:token-exchange = on-behalf-of exchange',
    '  • eventType agent_gateway.* = Okta Agent Gateway MCP tool calls (actor is the agent)',
    '  • device.custom_push.send_notification with requestUri /bc/authorize = CIBA approval push',
    '  • pam.* = OPA audit: pam.user_creds.issue (server creds, debugData.serverHostnames),',
    '    pam.server.ssh_login (target Server), pam.secret.reveal, pam.auth_token.issue',
    '  • "Active Directory Agent", "OPS Agent", "Okta Privileged Access Connector", "Okta IGA',
    '    Connector" are Okta infrastructure — NEVER call them AI agents. system.agent.ad.* = AD agent.',
    '  • client_credentials / jwt-bearer with no User target = autonomous workload identity',
    '',
    'RAW LOG FILTERS for fetch_okta_data (copy exactly; combine clauses with " and " / " or "):',
    '  /logs?since=<ISO>&sortOrder=DESCENDING&limit=100&filter=actor.type eq "Agent"',
    '  /logs?since=<ISO>&sortOrder=DESCENDING&limit=100&filter=eventType eq "app.oauth2.token.grant.id_jag"',
    '  /logs?since=<ISO>&sortOrder=DESCENDING&limit=100&filter=debugContext.debugData.grantType eq "urn:openid:params:grant-type:ciba"',
    '  /logs?since=<ISO>&sortOrder=DESCENDING&limit=100&filter=eventType sw "pam."',
    '  /logs?since=<ISO>&sortOrder=DESCENDING&limit=100&filter=eventType sw "agent_gateway."',
    '  /logs?since=<ISO>&sortOrder=DESCENDING&limit=100&filter=actor.alternateId eq "<login>" or target.alternateId eq "<login>"',
    '  /logs results come back compacted: one object per event with a ready-made "summary" line.',
    '',
    'PRIVILEGED ACTIONS — when the admin asks you to perform a DESTRUCTIVE action (suspend/unsuspend/activate/deactivate',
    'or deactivate a user, reset MFA, delete something, change a sign-on/policy rule) OR a CREATIVE',
    'action (create a user/group, assign an app or admin role, add a policy), do NOT call the Okta API',
    'directly and do NOT use fetch_okta_data for it. Instead call the request_access tool with a clear',
    'description of exactly what should happen and the target. That creates an Okta Access Request',
    'via the Governance API for the signed-in admin. It is NOT auto-approved: tell the admin the',
    'request was submitted and is PENDING their approval in Okta Access Requests (or MS Teams).',
    'Always include the requestId returned by the tool.',
    '',
    'ACCESS REQUEST STATUS — Okta does not push callbacks to this portal. To learn whether a',
    'request was approved, denied, or completed, call check_access_request_status with the',
    'requestId. Do this when the admin asks ("was it approved?", "check the request", "any update")',
    'or when following up on a request you created earlier in the conversation. Report the status',
    'clearly; if still pending_approval, remind them to approve in Okta Access Requests. Never',
    'claim an action was performed until status is approved_executed and execution.performed is true.',
    'After approval, the portal automatically executes the requested Okta operation (suspend user,',
    'reset MFA, etc.) — you do not call fetch_okta_data for writes. Confirm success from the',
    'execution field in the status response.',
    '',
    'Read-only requests (logs, users, authorization servers) still use fetch_okta_data. Always state',
    'when you are acting on the admin\'s behalf vs. giving advice. Be concise, accurate, security-minded.',
    '',
    'PRIVILEGED SECRETS (Okta Privileged Access / OPA) — you have a vaulted secret connected to your',
    `agent registration as a Resource Connection${process.env.OPA_SECRET_NAME ? `: "${process.env.OPA_SECRET_NAME}"` : ''}.`,
    'When the admin asks you to RETRIEVE, USE, or ACT WITH that secret, call the retrieve_okta_secret',
    'tool. The server performs an OAuth token exchange on the ORG authorization server',
    '(requested_token_type = urn:okta:params:oauth:token-type:vaulted-secret) on behalf of the',
    'signed-in admin and returns the vaulted credential from OPA. Access is the intersection of your',
    'connection and the admin\'s entitlement — if the admin is not entitled, the exchange is denied.',
    'Treat the secret as sensitive: use it for exactly what the admin asked; do not print the raw',
    'secret value back unless the admin explicitly asks to see it.',
  ].join('\n')

  const fullMessages = [
    { role: 'system', content: systemPrompt },
    ...messages
  ]

  // Tool definition — sent to the LLM gateway in OpenAI function-calling shape
  const OKTA_TOOL = {
    name: 'fetch_okta_data',
    description: [
      'Fetch live data from the Okta org on behalf of the signed-in admin via the delegated',
      'agent token-exchange (XAA). Use this for System Log, users, or any other Okta resource.',
      'The path is relative to /api/agent/okta — e.g. "/logs?since=2026-05-30T00:00:00Z&limit=50",',
      '"/users?limit=20", "/users/<userId>", "/me" (agent identity),',
      '"/authorizationServers", "/authorizationServers/<id>",',
      '"/authorizationServers/<id>/scopes", "/authorizationServers/<id>/claims",',
      '"/authorizationServers/<id>/policies". The server handles auth.',
    ].join(' '),
    input_schema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Path + query string relative to /api/agent/okta (must start with /). E.g. "/logs?since=2026-05-30T00:00:00Z&limit=50", "/authorizationServers/auszad6sd3mZh1jVA1d7/scopes", "/authorizationServers/auszblykhlQkrnOmA1d7/claims"',
        },
        method: {
          type: 'string',
          enum: ['GET'],
          description: 'HTTP method — only GET is supported for now.',
          default: 'GET',
        },
      },
      required: ['path'],
    },
  }

  // Tool the model calls for DESTRUCTIVE / CREATIVE actions instead of executing them. Creates an
  // Okta Access Request directly via Governance API v2 (no Workflows hop).
  const ACCESS_REQUEST_TOOL = {
    name: 'request_access',
    description: [
      'Request a DESTRUCTIVE or CREATIVE Okta action that the admin asked you to perform — e.g.',
      'suspend/unsuspend/activate/deactivate a user, reset MFA, delete a resource, change a sign-on/policy',
      'rule, create a user/group, or assign an app or admin role. Do NOT perform such actions with',
      'fetch_okta_data; call this tool instead. It creates an Okta Access Request via the Governance',
      'API v2 for the signed-in admin — PENDING approval in Okta Access Requests / MS Teams. It is NOT',
      'auto-approved. Use fetch_okta_data only for read-only GETs.',
    ].join(' '),
    input_schema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: [
            'suspend_user', 'unsuspend_user', 'activate_user', 'deactivate_user', 'reset_user_mfa', 'reset_user_password',
            'create_user', 'add_user_to_group', 'remove_user_from_group', 'assign_app_to_user',
            'assign_admin_role', 'update_policy_rule', 'delete_group',
          ],
          description: 'The canonical action to request. Must be one of the enum values (snake_case). Okta performs the mapped operation on approval.',
        },
        actionType: {
          type: 'string',
          enum: ['destructive', 'creative'],
          description: 'destructive = modifies/removes/disables; creative = creates/grants something new. If omitted it is derived from the action.',
        },
        description: {
          type: 'string',
          description: 'One-line human-readable summary of exactly what will be done, including the target. E.g. "Suspend Okta user jane.doe@sledai.com".',
        },
        justification: {
          type: 'string',
          description: "The admin's stated reason for the request. If none was given, summarise why it was requested.",
        },
        target: {
          type: 'object',
          description: 'What the action targets. Provide the fields the action needs (see the action enum): userId for user actions; groupId for group membership; appId for app assignment; roleType for admin-role grants; policyId+ruleId for policy changes.',
          properties: {
            userId: { type: 'string', description: 'Okta user id (00u…) or login the action targets.' },
            userLogin: { type: 'string', description: 'User login/email, if known (helps resolve the target in Okta).' },
            groupId: { type: 'string', description: 'Okta group id, for add/remove group membership or delete_group.' },
            appId: { type: 'string', description: 'Okta app id (0oa…), for assign_app_to_user.' },
            roleType: { type: 'string', description: 'Admin role type (e.g. USER_ADMIN, SUPER_ADMIN), for assign_admin_role.' },
            policyId: { type: 'string', description: 'Policy id, for update_policy_rule.' },
            ruleId: { type: 'string', description: 'Policy rule id, for update_policy_rule.' },
          },
        },
        parameters: {
          type: 'object',
          description: 'Action-specific extra fields, e.g. create_user profile {firstName,lastName,email,login}, or policy rule changes.',
        },
      },
      required: ['action', 'description'],
    },
  }

  const ACCESS_REQUEST_STATUS_TOOL = {
    name: 'check_access_request_status',
    description: [
      'Poll Okta Governance API for the current status of an access request created earlier via',
      'request_access. Pass the requestId (e.g. 6a36f6a6…). Returns status (pending_approval,',
      'approved_executed, denied, etc.), terminal flag, and raw Okta fields. Use when the admin',
      'asks whether a request was approved or wants an update — not immediately after submit.',
    ].join(' '),
    input_schema: {
      type: 'object',
      properties: {
        requestId: {
          type: 'string',
          description: 'The access request id returned by request_access.',
        },
      },
      required: ['requestId'],
    },
  }

  // Tool the model calls to retrieve a vaulted secret connected to the agent in Okta Privileged
  // Access (OPA). Runs the secret token-exchange (org AS, vaulted-secret) on behalf of the admin.
  const SECRET_TOOL = {
    name: 'retrieve_okta_secret',
    description: [
      'Retrieve a vaulted secret from Okta Privileged Access (OPA) that is connected to this agent',
      'as a Resource Connection, on behalf of the signed-in admin. Use this when the admin asks you',
      'to fetch, use, or act with the connected secret',
      process.env.OPA_SECRET_NAME ? `(named "${process.env.OPA_SECRET_NAME}").` : '.',
      'The server performs the OAuth token exchange (org authorization server, vaulted-secret token',
      'type) and returns the credential. You normally do not need any arguments.',
    ].join(' '),
    input_schema: {
      type: 'object',
      properties: {
        purpose: {
          type: 'string',
          description: 'Optional: what the admin wants the secret for (recorded for audit/logging).',
        },
      },
      required: [],
    },
  }

  // Pre-digested activity report — the deterministic path for "what's going on" questions so a
  // small model never has to compose Okta filters or read hundreds of raw events.
  const ACTIVITY_TOOL = {
    name: 'tenant_activity_report',
    description: [
      'FIRST CHOICE for any broad question about what is happening in the tenant ("what\'s going on',
      'today", "who is using which agents", "what did the agents / workloads do", "what has <user>',
      'done", "summarise the last N hours", "anything suspicious"). Reads the Okta System Log AND the',
      'OPA audit (pam.* events) for the window on behalf of the signed-in admin, classifies every',
      'event and returns a compact JSON report: humanDrivenAgentActivity (AI agents acting for humans',
      'via XAA/ID-JAG, CIBA, token-exchange, Agent Gateway), chainsByHuman (per person: agents used,',
      'OPA servers reached, CIBA approvals, timeline), autonomousWorkloads, anomalies,',
      'privilegedHumanActivity and aggregated routineSignIns. Prefer this over paging raw /logs.',
    ].join(' '),
    input_schema: {
      type: 'object',
      properties: {
        hours: { type: 'number', description: 'Look-back window in hours (default 24, max 168). Ignored when since is given.' },
        since: { type: 'string', description: 'Optional ISO-8601 start, e.g. 2026-09-17T00:00:00Z' },
        until: { type: 'string', description: 'Optional ISO-8601 end (default: now)' },
        user: { type: 'string', description: 'Optional: restrict to one person (name, login or Okta user id substring)' },
        detail: { type: 'string', enum: ['brief', 'full'], description: 'brief = shorter report (default for small models)' },
      },
      required: [],
    },
  }

  // Directory roster — deterministic "who is in X and when did they last log in" answers.
  const ROSTER_TOOL = {
    name: 'directory_roster',
    description: [
      'Membership + last-login roster from the DIRECTORY (user profile lastLogin/status, all time).',
      'Use for: who has / has not logged in, never logged in, last login, inactive for N days, not',
      'activated, members of a group, holders of an admin role ("which Super Admins…" → role=SUPER_ADMIN).',
      'Pass group=<exact name or 00g… id> OR role=<SUPER_ADMIN|ORG_ADMIN|APP_ADMIN|USER_ADMIN|…>.',
      'Returns neverLoggedIn / inactive / active buckets with name, login, status, lastLogin,',
      'daysSinceLogin. If the group name is ambiguous it returns needsClarification + candidates:',
      'show them and ask — do not guess. Not for "what happened" questions (use tenant_activity_report).',
    ].join(' '),
    input_schema: {
      type: 'object',
      properties: {
        group: { type: 'string', description: 'Group name (exact, case-insensitive) or 00g… id' },
        role: { type: 'string', description: 'Admin role type, e.g. SUPER_ADMIN, ORG_ADMIN, APP_ADMIN, USER_ADMIN, HELP_DESK_ADMIN, READ_ONLY_ADMIN' },
        inactiveDays: { type: 'number', description: 'Threshold for the "inactive" bucket (default 30)' },
      },
      required: [],
    },
  }

  // All tools (sent in OpenAI function-calling shape).
  const ALL_TOOLS = [ACTIVITY_TOOL, ROSTER_TOOL, OKTA_TOOL, ACCESS_REQUEST_TOOL, ACCESS_REQUEST_STATUS_TOOL, SECRET_TOOL]

  // Small models get the brief report and tighter raw-log caps.
  const smallModel = /gemma/i.test(resolveChatModel(model).id)

  const pendingAccessRequests = []

  // Execute a tool call from the model by hitting the local agent route in-process.
  // The session cookie is already on req, so we can call getDelegatedAccessToken directly.
  async function runTool(toolName, toolInput) {
    if (toolName === 'request_access') {
      const user = req.session?.user
      if (!user) return { error: 'No OIDC session — the admin must sign in before privileged actions can be requested.' }
      try {
        const result = await createAccessRequest({
          user,
          action: toolInput.action,
          actionType: toolInput.actionType,
          description: toolInput.description,
          justification: toolInput.justification,
          target: toolInput.target,
          parameters: toolInput.parameters,
          agentContext: { agentId: process.env.AGENT_CLIENT_ID || null, model: model || null, conversationId: null },
        })
        if (result.requestId) {
          accessRequestStatus.set(result.requestId, buildAccessRequestRecord(result))
          pendingAccessRequests.push({
            requestId: result.requestId,
            status: result.status,
            actionType: result.actionType,
            description: toolInput.description,
            action: result.action,
          })
        }
        return result
      } catch (e) {
        return { error: `Access request failed: ${e.message}` }
      }
    }

    if (toolName === 'check_access_request_status') {
      const requestId = toolInput?.requestId
      if (!requestId) return { error: 'requestId is required' }
      try {
        const record = await resolveAccessRequestStatus(requestId, req)
        const idx = pendingAccessRequests.findIndex(p => p.requestId === requestId)
        const entry = {
          requestId,
          status: record.status,
          actionType: idx >= 0 ? pendingAccessRequests[idx].actionType : record.action?.type,
          execution: record.execution,
        }
        if (idx >= 0) pendingAccessRequests[idx] = { ...pendingAccessRequests[idx], ...entry }
        else pendingAccessRequests.push(entry)
        return record
      } catch (e) {
        return { error: `Status check failed: ${e.message}` }
      }
    }

    if (toolName === 'retrieve_okta_secret') {
      const resource = process.env.OPA_SECRET_RESOURCE
      if (!resource) return { error: 'No OPA secret resource configured (set OPA_SECRET_RESOURCE).' }
      try {
        const idToken = await ensureSessionIdToken(req)
        const out = await getVaultedSecret({ idToken, resource })
        if (!out.ok) {
          const msg = out.data?.error_description || out.data?.errorSummary || out.data?.error || JSON.stringify(out.data)
          const reauth = /subject_token|invalid.*token/i.test(String(msg))
          return {
            error: `Secret exchange failed (${out.status}): ${msg}`,
            detail: out.data,
            ...(reauth ? { reauth: true, hint: 'Sign out and sign in again — your Okta id_token may have expired.' } : {}),
          }
        }
        return { ok: true, name: process.env.OPA_SECRET_NAME || null, resource, secret: out.data }
      } catch (e) {
        return {
          error: `Secret retrieval failed: ${e.message}`,
          ...(e.code === 'SESSION_ID_TOKEN_EXPIRED' || e.code === 'SESSION_NO_ID_TOKEN' ? { reauth: true } : {}),
        }
      }
    }

    if (toolName === 'tenant_activity_report') {
      const gate = await requireDelegatedScope(req, 'sdap.logs.read')
      if (gate.error) return gate
      const win = parseActivityWindow(toolInput || {})
      if (win.error) return win
      const detail = toolInput?.detail === 'brief' || toolInput?.detail === 'full' ? toolInput.detail : (smallModel ? 'brief' : 'full')
      try {
        const report = await runActivityReport({ ...win, detail, user: toolInput?.user })
        console.log(`[AGENT TOOL] tenant_activity_report ${win.since}..${win.until} -> ${report.fetched?.events} events, ${JSON.stringify(report).length} bytes (${detail})`)
        return report
      } catch (e) {
        return { error: `Activity report failed: ${e.message}` }
      }
    }

    if (toolName === 'directory_roster') {
      const gate = await requireDelegatedScope(req, 'sdap.users.read')
      if (gate.error) return gate
      try {
        const out = await directoryRoster(oktaCfg(), { group: toolInput?.group, role: toolInput?.role, inactiveDays: Number(toolInput?.inactiveDays) || 30 })
        console.log(`[AGENT TOOL] directory_roster ${JSON.stringify({ group: toolInput?.group, role: toolInput?.role })} -> ${out.roster ? out.roster.total + ' users' : (out.needsClarification ? 'needs clarification' : 'error')}`)
        return out
      } catch (e) {
        return { error: `Directory roster failed: ${e.message}` }
      }
    }

    if (toolName !== 'fetch_okta_data') return { error: `Unknown tool: ${toolName}` }
    const rawPath = toolInput.path || '/'
    const oktaPath = rawPath.replace(/^\/api\/agent\/okta/, '') // strip prefix if model added it

    // /me (and /registry alias) — agent's own identity, no XAA needed
    if (oktaPath === '/me' || oktaPath === '/registry' || oktaPath === '') {
      const oktaBase = (process.env.OKTA_ORG_URL || '').replace(/\/$/, '')
      const token = process.env.OKTA_API_TOKEN
      const clientId = process.env.AGENT_CLIENT_ID || process.env.OKTA_OIDC_CLIENT_ID
      const [oktaApp, oktaUser] = await Promise.all([
        clientId
          ? fetch(`${oktaBase}/api/v1/apps/${clientId}`, {
              headers: { 'Authorization': `SSWS ${token}`, 'Accept': 'application/json' },
            }).then(r => r.json()).catch(() => null)
          : Promise.resolve(null),
        process.env.AGENT_USER_ID
          ? fetch(`${oktaBase}/api/v1/users/${process.env.AGENT_USER_ID}`, {
              headers: { 'Authorization': `SSWS ${token}`, 'Accept': 'application/json' },
            }).then(r => r.json()).catch(() => null)
          : Promise.resolve(null),
      ])
      return {
        agent: {
          clientId: clientId || null,
          org: oktaBase,
          label: oktaApp?.label || oktaApp?.name || 'SDAP Agent',
          status: oktaApp?.status || null,
          scopes: (process.env.AGENT_TOKEN_SCOPE || '').split(' ').filter(Boolean),
          resourceServer: process.env.RESOURCE_AS_ISSUER || null,
          secrets: process.env.OPA_SECRET_RESOURCE
            ? [{ name: process.env.OPA_SECRET_NAME || 'secret', resource: process.env.OPA_SECRET_RESOURCE, type: 'okta-pam-vaulted-secret', via: 'token-exchange:vaulted-secret' }]
            : [],
          oktaApp: oktaApp || null,
          oktaUser: oktaUser || null,
        },
      }
    }

    const need = requiredScopeFor('GET', oktaPath.split('?')[0])

    let idToken
    try {
      idToken = await ensureSessionIdToken(req)
    } catch (e) {
      return {
        error: e.message,
        reauth: e.code === 'SESSION_ID_TOKEN_EXPIRED' || e.code === 'SESSION_NO_ID_TOKEN',
      }
    }

    let delegated
    try {
      delegated = await getDelegatedAccessToken({ idToken })
    } catch (e) {
      const reauth = /subject_token|invalid.*token/i.test(e.message)
      return {
        error: `Token exchange failed: ${e.message}`,
        ...(reauth ? { reauth: true, hint: 'Sign out and sign in again — your Okta id_token may have expired.' } : {}),
      }
    }

    const granted = (delegated.scope || '').split(' ').filter(Boolean)
    if (!granted.includes(need)) {
      return { error: `Insufficient delegated scope — need ${need}, granted: ${granted.join(', ')}` }
    }

    const oktaBase = (process.env.OKTA_ORG_URL || '').replace(/\/$/, '')
    const token = process.env.OKTA_API_TOKEN
    try {
      const oktaRes = await fetch(`${oktaBase}/api/v1${oktaPath}`, {
        headers: { 'Authorization': `SSWS ${token}`, 'Accept': 'application/json' },
      })
      const text = await oktaRes.text()
      let data
      try { data = JSON.parse(text) } catch { data = text }
      if (/^\/logs/.test(oktaPath) && Array.isArray(data)) {
        // Raw events are ~3 KB each; hand the model one compact line per event instead.
        const cap = smallModel ? 40 : 150
        const events = data.slice(0, cap).map(compactEvent)
        return {
          status: oktaRes.status, count: data.length, returned: events.length, truncated: data.length > cap,
          ...(data.length > cap ? { hint: 'Narrow with filter= or a shorter window; or call tenant_activity_report.' } : {}),
          events,
        }
      }
      return { status: oktaRes.status, data }
    } catch (e) {
      return { error: `Okta API call failed: ${e.message}` }
    }
  }

  try {
    let content = ''

    if (!llmGatewayConfigured()) throw new Error('No LLM gateway configured. Set LLM_BASE_URL and LLM_API_KEY in .env.local and restart.')
    const chosen = resolveChatModel(model)
    const tools = ALL_TOOLS.map(t => ({
      type: 'function',
      function: { name: t.name, description: t.description, parameters: t.input_schema },
    }))
    const endpoint = `${process.env.LLM_BASE_URL.replace(/\/+$/, '')}/chat/completions`
    let loopMessages = [...fullMessages]
    for (let round = 0; round < 5; round++) {
      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'Authorization': `Bearer ${process.env.LLM_API_KEY}` },
        body: JSON.stringify({ model: chosen.id, messages: loopMessages, tools, max_tokens: 4096 }),
      })
      if (!resp.ok) throw new Error(`LLM gateway error ${resp.status}: ${await resp.text()}`)
      const data = await resp.json()
      const choice = data.choices?.[0]
      if (choice?.finish_reason !== 'tool_calls' || !choice?.message?.tool_calls?.length) {
        content = choice?.message?.content || 'No response from the model'; break
      }
      loopMessages.push(choice.message)
      const toolMsgs = []
      for (const tc of choice.message.tool_calls) {
        let input; try { input = JSON.parse(tc.function.arguments) } catch { input = {} }
        console.log(`[AGENT TOOL] ${tc.function.name}(${tc.function.arguments})`)
        const result = await runTool(tc.function.name, input)
        toolMsgs.push({ role: 'tool', tool_call_id: tc.id, content: JSON.stringify(result) })
      }
      loopMessages.push(...toolMsgs)
    }

    res.json({ content, model: chosen.id, provider: chosen.provider, pendingAccessRequests })

  } catch (err) {
    console.error('LLM proxy error:', err.message)
    res.status(500).json({ error: err.message })
  }
})

// ----------------------
// Okta Management API proxy (server holds the SSWS token).
// Anything under /api/okta/... is forwarded to {OKTA_ORG_URL}/api/v1/...
// e.g. GET /api/okta/users?limit=20  ->  {org}/api/v1/users?limit=20
// ----------------------
app.all(/^\/api\/okta\/.*/, requireAuth, async (req, res) => {
  const oktaBase = (process.env.OKTA_ORG_URL || process.env.OKTA_API_DOMAIN || '').replace(/\/$/, '')
  const token = process.env.OKTA_API_TOKEN

  if (!oktaBase || !token) {
    return res.status(503).json({ error: 'Okta API not configured (set OKTA_ORG_URL and OKTA_API_TOKEN)' })
  }

  // Strip the /api/okta prefix; keep the rest of the path + query string
  const oktaPath = req.originalUrl.replace(/^\/api\/okta/, '')
  const url = `${oktaBase}/api/v1${oktaPath}`

  try {
    const oktaRes = await fetch(url, {
      method: req.method,
      headers: {
        'Authorization': `SSWS ${token}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: ['POST', 'PUT', 'PATCH'].includes(req.method) ? JSON.stringify(req.body) : undefined,
    })

    const text = await oktaRes.text()
    let data
    try { data = JSON.parse(text) } catch { data = text }

    res.status(oktaRes.status).json(data)
  } catch (e) {
    res.status(502).json({ error: 'Failed to reach Okta', detail: e.message })
  }
})

// ----------------------
// Quick actions -> fire approval webhook (Okta Workflows / custom approval)
// ----------------------
app.post('/api/actions/:actionId', requireAuth, async (req, res) => {
  const { actionId } = req.params
  const { requestedBy, targetUserId, reason } = req.body || {}

  const webhookUrl = process.env.APPROVAL_WEBHOOK_URL
  if (webhookUrl) {
    try {
      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: actionId,
          requestedBy,
          targetUserId,
          reason,
          timestamp: new Date().toISOString(),
          portal: 'super-duper-admin-portal',
        }),
      })
    } catch (e) {
      console.warn('Webhook failed (non-fatal in demo):', e.message)
    }
  }

  // Return nice response for the UI
  res.json({
    success: true,
    action: actionId,
    status: 'submitted',
    message: 'Action submitted for approval via Okta workflow (demo)',
    requestId: 'req_' + Date.now(),
  })
})

// ======================
// Privileged-action access request — POST /governance/api/v2/requests (Okta IGA v2).
// NOT auto-approved: the admin approves out-of-band in Okta Access Requests / MS Teams.
// Requires a real OIDC session so requestedBy is the signed-in admin.
// ======================
app.post('/api/agent/access-request', requireAuth, async (req, res) => {
  const user = req.session?.user
  if (!user) {
    return res.status(401).json({ error: 'OIDC session required — sign in so the requester/approver identity is known.' })
  }
  const { action, actionType, description, justification, target, parameters } = req.body || {}
  if (!action || !description) {
    return res.status(400).json({ error: 'action and description are required' })
  }
  try {
    const result = await createAccessRequest({
      user, action, actionType, description, justification, target, parameters,
      agentContext: { agentId: process.env.AGENT_CLIENT_ID || null, model: null, conversationId: null },
    })
    if (result.requestId) accessRequestStatus.set(result.requestId, buildAccessRequestRecord(result))
    res.json(result)
  } catch (e) {
    res.status(502).json({ error: 'Access request failed', detail: e.message })
  }
})

// ======================
// Access-request status map + flo callback (closed-loop, contract §3.3).
// The Workflows flo POSTs terminal status here (approved_executed | approved_execution_failed |
// denied | expired | cancelled), signed with HMAC-SHA256 over the RAW body using FLO_CALLBACK_SECRET
// (header `X-Flo-Signature: sha256=<hex>`). The portal NEVER executes the action — it only records
// what Okta did. Status is in-memory (ephemeral; see contract §9 for persistence as a follow-up).
// ======================
function verifyFloSignature(rawBuf, header) {
  const secret = process.env.FLO_CALLBACK_SECRET
  if (!secret) return { ok: false, reason: 'FLO_CALLBACK_SECRET not configured' }
  if (!header || typeof header !== 'string') return { ok: false, reason: 'missing X-Flo-Signature' }
  const provided = header.replace(/^sha256=/i, '').trim()
  const expected = createHmac('sha256', secret).update(rawBuf).digest('hex')
  const a = Buffer.from(provided, 'hex')
  const b = Buffer.from(expected, 'hex')
  if (a.length !== b.length || !timingSafeEqual(a, b)) return { ok: false, reason: 'signature mismatch' }
  return { ok: true }
}

app.post('/api/agent/access-request/callback', (req, res) => {
  // req.rawBody is the exact bytes (captured by the express.json verify hook). The flo MUST send
  // Content-Type: application/json so the body is captured and parsed.
  if (!req.rawBody || !req.rawBody.length) {
    return res.status(400).json({ error: 'Empty body or non-JSON content-type (send application/json)' })
  }
  const sig = verifyFloSignature(req.rawBody, req.get('X-Flo-Signature'))
  if (!sig.ok) {
    console.warn('[access-request callback] rejected:', sig.reason)
    return res.status(401).json({ error: 'Invalid or missing flo signature', detail: sig.reason })
  }
  const payload = req.body || {}
  const requestId = payload.requestId || payload.v1?.requestId
  if (!requestId) return res.status(400).json({ error: 'requestId is required' })
  const record = {
    status: payload.status || 'unknown',
    correlationId: payload.correlationId || null,
    decision: payload.decision || null,
    execution: payload.execution || null,
    completedAt: payload.completedAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }
  accessRequestStatus.merge(requestId, record)
  console.log(`[access-request callback] ${requestId} -> ${record.status}`)
  res.json({ ok: true, requestId, recorded: record.status })
})

// Restore action context after server restart (client persists action in localStorage).
app.post('/api/agent/access-request/:requestId/context', requireAuth, (req, res) => {
  const { requestId } = req.params
  const { action, correlationId, description } = req.body || {}
  if (!action?.type) return res.status(400).json({ error: 'action.type is required' })
  const prev = accessRequestStatus.get(requestId) || {}
  const record = accessRequestStatus.merge(requestId, {
    action,
    correlationId: correlationId || prev.correlationId || null,
    description: description || prev.description || null,
  })
  res.json({ ok: true, requestId, record })
})

// Read the latest status for a request — polls Okta, auto-executes approved actions when configured.
app.get('/api/agent/access-request/:requestId/status', requireAuth, async (req, res) => {
  const { requestId } = req.params
  const cached = accessRequestStatus.get(requestId)
  try {
    const record = await resolveAccessRequestStatus(requestId, req)
    const tokenStatus = sessionIdTokenStatus(req.session)
    return res.json({
      ...record,
      ...(tokenStatus.expired ? { needsReauth: true, idTokenExpired: true } : {}),
    })
  } catch (e) {
    if (cached) {
      return res.json({
        requestId,
        ...cached,
        source: 'cache',
        terminal: isAccessRequestTerminal(cached.status),
        pollError: e.message,
      })
    }
    return res.status(404).json({ error: 'Request not found', requestId, detail: e.message })
  }
})

// ======================
// Logout — destroys the session
// ======================
app.get('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('[AUTH] Logout error:', err)
      return res.status(500).json({ error: 'Failed to log out' })
    }
    const webRoot = process.env.POST_LOGIN_REDIRECT || 'https://ai-admin.skylarbarnes.com/'
    res.redirect(webRoot)
  })
})

// ======================
// OIDC login (human admin) — yields the id_token used as the token-exchange subject
// ======================
app.get('/api/oidc/login', async (req, res) => {
  try {
    const state = randomUUID()
    const nonce = randomUUID()
    const { verifier, challenge } = makePkce()
    req.session.oidc = { state, nonce, verifier }
    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()))

    const url = await buildAuthUrl({ state, nonce, codeChallenge: challenge })
    res.redirect(url)
  } catch (err) {
    console.error('[OIDC] login error:', err.message)
    res.status(500).send('OIDC login failed: ' + err.message)
  }
})

app.get('/api/oidc/callback', async (req, res) => {
  try {
    const { code, state } = req.query
    const saved = req.session.oidc
    if (!saved || !state || state !== saved.state) {
      console.error('[OIDC] state mismatch', {
        hasSession: Boolean(req.session),
        hasOidc: Boolean(saved),
        queryState: state,
        savedState: saved?.state,
      })
      const webRoot = process.env.POST_LOGIN_REDIRECT || 'https://ai-admin.skylarbarnes.com/'
      const qs = new URLSearchParams({ error: 'oidc_state', message: 'Session expired or crossed with another app — clear cookies and try again' })
      return res.redirect(`${webRoot}?${qs.toString()}`)
    }

    const tokens = await exchangeCode({ code, codeVerifier: saved.verifier })
    const claims = await verifyIdToken(tokens.id_token, saved.nonce)

    // Establish session (same shape requireAuth + /api/auth/me expect)
    req.session.user = {
      id: claims.sub,
      email: claims.email || claims.preferred_username,
      name: claims.name || claims.email || claims.preferred_username,
      login: claims.preferred_username || claims.email,
      attributes: claims,
      authMethod: 'oidc',
    }
    // Keep tokens for agent token exchange (id_token expires ~1h; refresh_token when offline_access granted)
    req.session.id_token = tokens.id_token
    if (tokens.refresh_token) req.session.refresh_token = tokens.refresh_token
    if (tokens.access_token) req.session.access_token = tokens.access_token
    const expMs = idTokenExpiresAt(tokens.id_token)
    req.session.id_token_expires_at = expMs ? new Date(expMs).toISOString() : null
    delete req.session.oidc
    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()))

    console.log('[OIDC] Login successful for:', req.session.user.email)
    const successRedirect = process.env.POST_LOGIN_REDIRECT || 'http://localhost:3200/'
    return res.redirect(successRedirect)
  } catch (err) {
    console.error('[OIDC] callback error:', err.message)
    res.status(401).send('OIDC authentication failed: ' + err.message)
  }
})

// ======================
// Agent identity routes — return the agent's own Okta registration / registry entry.
// These do NOT use XAA: the agent is reading its own config, not acting on behalf of a human.
// Must be registered before the /api/agent/okta/* catch-all.
// ======================
app.get(['/api/agent/okta/me', '/api/agent/registry'], requireAuth, async (req, res) => {
  const oktaBase = (process.env.OKTA_ORG_URL || process.env.OKTA_API_DOMAIN || '').replace(/\/$/, '')
  const token = process.env.OKTA_API_TOKEN
  const clientId = process.env.AGENT_CLIENT_ID || process.env.OKTA_OIDC_CLIENT_ID

  if (!oktaBase || !token) return res.status(503).json({ error: 'Okta API not configured' })

  try {
    const fetches = []

    const appPromise = clientId
      ? fetch(`${oktaBase}/api/v1/apps/${clientId}`, {
          headers: { 'Authorization': `SSWS ${token}`, 'Accept': 'application/json' },
        }).then(r => r.json()).catch(() => null)
      : Promise.resolve(null)

    const agentUserId = process.env.AGENT_USER_ID
    const userPromise = agentUserId
      ? fetch(`${oktaBase}/api/v1/users/${agentUserId}`, {
          headers: { 'Authorization': `SSWS ${token}`, 'Accept': 'application/json' },
        }).then(r => r.json()).catch(() => null)
      : Promise.resolve(null)

    const [oktaApp, oktaUser] = await Promise.all([appPromise, userPromise])

    res.json({
      agent: {
        clientId: clientId || null,
        org: oktaBase,
        label: oktaApp?.label || oktaApp?.name || 'SDAP Agent',
        status: oktaApp?.status || null,
        scopes: (process.env.AGENT_TOKEN_SCOPE || '').split(' ').filter(Boolean),
        resourceServer: process.env.RESOURCE_AS_ISSUER || null,
        secrets: process.env.OPA_SECRET_RESOURCE
          ? [{ name: process.env.OPA_SECRET_NAME || 'secret', resource: process.env.OPA_SECRET_RESOURCE, type: 'okta-pam-vaulted-secret', via: 'token-exchange:vaulted-secret' }]
          : [],
        oktaApp: oktaApp || null,
        oktaUser: oktaUser || null,
      },
    })
  } catch (e) {
    res.status(502).json({ error: 'Failed to fetch agent identity from Okta', detail: e.message })
  }
})

// ======================
// Pre-digested activity report — same classifier the chat agent uses (lib/agentActivity.js).
// XAA-gated exactly like /api/agent/okta/logs (needs sdap.logs.read for the signed-in admin).
// ======================
app.get('/api/agent/okta/activity', requireAuth, async (req, res) => {
  const gate = await requireDelegatedScope(req, 'sdap.logs.read')
  if (gate.error) return res.status(gate.reauth ? 401 : 403).json(gate)
  const win = parseActivityWindow(req.query)
  if (win.error) return res.status(400).json(win)
  try {
    const report = await runActivityReport({
      ...win,
      detail: req.query.detail === 'brief' ? 'brief' : 'full',
      user: req.query.user ? String(req.query.user) : null,
    })
    res.json(report)
  } catch (e) {
    res.status(502).json({ error: 'Activity report failed', detail: e.message })
  }
})

app.get('/api/agent/okta/roster', requireAuth, async (req, res) => {
  const gate = await requireDelegatedScope(req, 'sdap.users.read')
  if (gate.error) return res.status(gate.reauth ? 401 : 403).json(gate)
  if (!req.query.group && !req.query.role) return res.status(400).json({ error: 'Pass group=<name|00g id> or role=<SUPER_ADMIN|…>' })
  try {
    res.json(await directoryRoster(oktaCfg(), { group: req.query.group ? String(req.query.group) : undefined, role: req.query.role ? String(req.query.role) : undefined, inactiveDays: Number(req.query.inactiveDays) || 30 }))
  } catch (e) {
    res.status(502).json({ error: 'Directory roster failed', detail: e.message })
  }
})

// ======================
// OPA vaulted-secret retrieval via agent token exchange (Okta "secret" resource type).
// Exchanges the signed-in admin's id_token for a secret connected to the agent in Okta
// Privileged Access. Pass {resource} in the body to override OPA_SECRET_RESOURCE while testing.
// ======================
app.post('/api/agent/secret', requireAuth, async (req, res) => {
  const resource = (req.body && req.body.resource) || process.env.OPA_SECRET_RESOURCE
  if (!resource) {
    return res.status(400).json({ error: 'No secret resource configured — set OPA_SECRET_RESOURCE or pass {resource} in the body' })
  }
  const scope = req.body?.scope
  const audience = req.body?.audience
  try {
    const idToken = await ensureSessionIdToken(req)
    const out = await getVaultedSecret({ idToken, resource, scope, audience })
    return res.status(out.ok ? 200 : 502).json({ resource, status: out.status, ...out.data })
  } catch (e) {
    const status = e.code === 'SESSION_ID_TOKEN_EXPIRED' || e.code === 'SESSION_NO_ID_TOKEN' ? 401 : 500
    return res.status(status).json({ error: e.message, reauth: status === 401, code: e.code || null })
  }
})

// ======================
// Delegated (on-behalf-of) Okta access via agent token exchange (XAA / ID-JAG)
// Mirror of /api/okta/* but authorized by the human ∩ agent intersection rather than
// a static token. Requires an OIDC session (id_token).
// ======================
function requiredScopeFor(method, oktaPath) {
  if (/^\/logs/.test(oktaPath)) return 'sdap.logs.read'
  if (/^\/users/.test(oktaPath)) return method === 'GET' ? 'sdap.users.read' : 'sdap.users.manage'
  if (/^\/authorizationServers/.test(oktaPath)) return 'sdap.act'
  return 'sdap.act'
}

app.all(/^\/api\/agent\/okta\/.*/, requireAuth, async (req, res) => {
  let idToken
  try {
    idToken = await ensureSessionIdToken(req)
  } catch (e) {
    return res.status(401).json({
      error: e.message,
      reauth: true,
      code: e.code || null,
    })
  }

  const oktaPath = req.originalUrl.replace(/^\/api\/agent\/okta/, '')
  const need = requiredScopeFor(req.method, oktaPath.split('?')[0])

  let delegated
  try {
    delegated = await getDelegatedAccessToken({ idToken })
  } catch (e) {
    const reauth = /subject_token|invalid.*token/i.test(e.message)
    return res.status(reauth ? 401 : 502).json({
      error: 'Token exchange failed',
      detail: e.message,
      ...(reauth ? { reauth: true } : {}),
    })
  }

  // Enforce the effective (human ∩ agent) scope the custom AS granted
  const granted = (delegated.scope || '').split(' ').filter(Boolean)
  if (!granted.includes(need)) {
    return res.status(403).json({
      error: 'Insufficient delegated scope',
      need,
      granted,
      hint: "The intersection of the agent's grants and the signed-in admin's entitlements does not include this scope.",
    })
  }

  // SEAM: with the call authorized on-behalf-of the human, perform it against Okta.
  // In the full XAA model the Okta Management API is itself an XAA resource, called with
  // `delegated.access_token`. Until that resource connection exists, we make the call with
  // the app's configured Okta credential — now GATED by the human∩agent authorization above.
  // See docs/okta-xaa-runbook.md to flip this to the brokered token.
  const oktaBase = (process.env.OKTA_ORG_URL || process.env.OKTA_API_DOMAIN || '').replace(/\/$/, '')
  const token = process.env.OKTA_API_TOKEN
  if (!oktaBase || !token) return res.status(503).json({ error: 'Okta API not configured' })

  try {
    const oktaRes = await fetch(`${oktaBase}/api/v1${oktaPath}`, {
      method: req.method,
      headers: {
        'Authorization': `SSWS ${token}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: ['POST', 'PUT', 'PATCH'].includes(req.method) ? JSON.stringify(req.body) : undefined,
    })
    const text = await oktaRes.text()
    let data
    try { data = JSON.parse(text) } catch { data = text }
    res.status(oktaRes.status).json(data)
  } catch (e) {
    res.status(502).json({ error: 'Failed to reach Okta', detail: e.message })
  }
})

// OAuth-protected HTTP MCP endpoint (registrable in Okta MCP Servers)
mountMcpRoutes(app)

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✓ SDAP API server running on http://0.0.0.0:${PORT}`)
  console.log(`  Demo auth bypass: ${process.env.DEMO_AUTH_BYPASS === 'true'}`)
  console.log(`  OIDC client configured: ${!!process.env.OKTA_OIDC_CLIENT_ID}`)
  console.log(`  LLM gateway configured: ${llmGatewayConfigured()} (default model: ${resolveChatModel().id})`)
  console.log(`  Okta token present: ${!!process.env.OKTA_API_TOKEN}`)
})
