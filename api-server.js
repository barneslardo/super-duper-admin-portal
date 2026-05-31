import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import morgan from 'morgan'
import session from 'express-session'
import cookieParser from 'cookie-parser'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import saml from 'samlify'
import validator from '@authenio/samlify-xsd-schema-validator'

saml.setSchemaValidator(validator)

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

dotenv.config({ path: join(__dirname, '.env.local') })
dotenv.config({ path: join(__dirname, '.env') })

console.log('RAW DEMO_AUTH_BYPASS from process.env =', JSON.stringify(process.env.DEMO_AUTH_BYPASS))

const app = express()
const PORT = process.env.API_PORT || 3201

// Trust proxy for reverse proxy / pm2 setups
app.set('trust proxy', 1)

// ======================
// SAML (samlify) setup
// ======================
let idp = null
let sp = null
let samlEnabled = false

function initSaml() {
  const entryPoint = process.env.SAML_ENTRY_POINT
  const issuer = process.env.SAML_ISSUER
  const cert = process.env.SAML_CERT
  const spEntityId = process.env.SAML_SP_ENTITY_ID || 'super-duper-admin-portal'
  const acsUrl = process.env.SAML_SP_ACS_URL

  console.log('  [SAML DEBUG] SAML_SP_ACS_URL       =', process.env.SAML_SP_ACS_URL)
  console.log('  [SAML DEBUG] SAML_SUCCESS_REDIRECT =', process.env.SAML_SUCCESS_REDIRECT)
  console.log('  [SAML DEBUG] Effective spEntityId  =', spEntityId)
  console.log('  [SAML DEBUG] Effective acsUrl      =', acsUrl)

  if (!entryPoint || !cert) {
    console.log('  SAML: Not fully configured (missing SAML_ENTRY_POINT or SAML_CERT). Using DEMO_AUTH_BYPASS or manual login.')
    return
  }

  // Clean and format the certificate (defensive against multi-line or malformed certs in .env)
  let cleanCert = ''
  if (cert) {
    cleanCert = cert
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\\n/g, '')
      .replace(/[\r\n\s]+/g, '')
      .match(/.{1,64}/g)
      ?.join('\n') || ''
  }

  const formattedCert = `-----BEGIN CERTIFICATE-----\n${cleanCert}\n-----END CERTIFICATE-----`

  if (!cleanCert || cleanCert.length < 100) {
    console.error('  SAML: Certificate appears invalid or empty after cleaning. SAML will be disabled.')
    return
  }

  try {
    idp = saml.IdentityProvider({
      entityID: issuer,
      singleSignOnService: [
        {
          Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
          Location: entryPoint
        },
        {
          Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
          Location: entryPoint
        }
      ],
      signingCert: formattedCert,
    })

    sp = saml.ServiceProvider({
      entityID: spEntityId,
      assertionConsumerService: [{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: acsUrl,
      }],
      // Okta usually doesn't require signed AuthnRequests
      wantAuthnRequestsSigned: false,
    })

    samlEnabled = true
    console.log('  SAML: Initialized successfully (IdP-initiated mode)')
    console.log(`    ACS URL: ${acsUrl}`)
    console.log(`    SP Entity ID: ${spEntityId}`)
  } catch (err) {
    console.error('  SAML initialization failed:', err.message)
  }
}

initSaml()

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
app.use(express.json({ limit: '2mb' }))
app.use(cookieParser())
app.use(morgan('combined'))

// Sessions (demo until full SAML)
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-only-insecure-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',   // must be true when using https://
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    domain: process.env.COOKIE_DOMAIN || undefined,  // e.g. '.skylarbarnes.com' if needed for cross-subdomain
    maxAge: 1000 * 60 * 60 * 12, // 12 hours
  },
}))

// Auth gate for privileged endpoints. Honors DEMO_AUTH_BYPASS, otherwise
// requires an established SAML session (this is what the ACS handler sets up).
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
      openai: !!process.env.OPENAI_API_KEY,
      anthropic: !!process.env.ANTHROPIC_API_KEY,
      grok: !!process.env.GROK_API_KEY,
    },
  })
})

app.get('/api/auth/me', (req, res) => {
  if (process.env.DEMO_AUTH_BYPASS === 'true') {
    return res.json({
      user: { id: 'demo-1', email: 'alex.rivera@sledai.com', name: 'Alex Rivera', role: 'Super Admin (SAML JIT)' },
      authMode: 'DEMO_BYPASS',
    })
  }
  if (req.session?.user) {
    return res.json({ user: req.session.user, authMode: 'SAML' })
  }
  res.status(401).json({ error: 'Not authenticated' })
})

// ----------------------
// Available models (only those we have keys for). Public: the splash/UI
// calls this before authentication to populate the model picker.
// ----------------------
app.get('/api/available-models', (req, res) => {
  const models = []

  if (process.env.OPENAI_API_KEY) {
    models.push(
      { id: 'gpt-4o', label: 'GPT-4o (OpenAI)', provider: 'openai' },
      { id: 'gpt-4o-mini', label: 'GPT-4o mini (OpenAI)', provider: 'openai' }
    )
  }

  if (process.env.GROK_API_KEY) {
    models.push(
      { id: 'grok-4.3', label: 'Grok 4.3 (xAI)', provider: 'grok' }
    )
  }

  if (process.env.ANTHROPIC_API_KEY) {
    models.push(
      { id: 'claude-3-5-sonnet-20241022', label: 'Claude 3.5 Sonnet (Anthropic)', provider: 'anthropic' },
      { id: 'claude-3-5-haiku-20241022', label: 'Claude 3.5 Haiku (Anthropic)', provider: 'anthropic' }
    )
  }

  res.json(models)
})

// ----------------------
// Chat proxy to the configured LLM provider
// ----------------------
app.post('/api/chat', requireAuth, async (req, res) => {
  const { messages = [], model, provider } = req.body || {}

  const systemPrompt = [
    'You are the Okta Admin Assistant for the Super Duper Admin Portal, operating against the',
    'sledai.oktapreview.com Okta organization. You help administrators with user lifecycle,',
    'sign-on and MFA policies, troubleshooting access issues, and reviewing system log / sign-in',
    'events. Be concise, accurate, and security-minded.',
    '',
    'Any destructive or privileged action (suspending users, resetting MFA factors, changing',
    'policies) must go through the portal approval workflow rather than being performed directly —',
    'explain that flow instead of claiming you executed it. If you are unsure or lack the data,',
    'say so plainly.',
  ].join('\n')

  const fullMessages = [
    { role: 'system', content: systemPrompt },
    ...messages
  ]

  try {
    let content = ''

    if (provider === 'anthropic' && process.env.ANTHROPIC_API_KEY) {
      const resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': process.env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: model || 'claude-3-5-sonnet-20241022',
          max_tokens: 2000,
          system: systemPrompt,
          messages: messages.filter(m => m.role !== 'system'),
        }),
      })
      if (!resp.ok) {
        const errorText = await resp.text()
        console.error('Anthropic API error:', resp.status, errorText)
        throw new Error(`Anthropic error ${resp.status}: ${errorText}`)
      }
      const data = await resp.json()
      content = data.content?.[0]?.text || 'No response from Claude'

    } else if (provider === 'grok' && process.env.GROK_API_KEY) {
      const resp = await fetch('https://api.x.ai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'Authorization': `Bearer ${process.env.GROK_API_KEY}`,
        },
        body: JSON.stringify({
          model: model || 'grok-4.3',
          messages: fullMessages,
          max_tokens: 2000,
        }),
      })
      if (!resp.ok) {
        const errorText = await resp.text()
        console.error('Grok API error:', resp.status, errorText)
        throw new Error(`Grok error ${resp.status}: ${errorText}`)
      }
      const data = await resp.json()
      content = data.choices?.[0]?.message?.content || 'No response from Grok'

    } else {
      // Default: OpenAI
      if (!process.env.OPENAI_API_KEY) {
        throw new Error('No LLM API keys configured on server. Add OPENAI_API_KEY (or ANTHROPIC/GROK) to .env and restart.')
      }
      const resp = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
        },
        body: JSON.stringify({
          model: model || 'gpt-4o',
          messages: fullMessages,
          temperature: 0.4,
          max_tokens: 1800,
        }),
      })
      if (!resp.ok) {
        const errorText = await resp.text()
        console.error('OpenAI API error:', resp.status, errorText)
        throw new Error(`OpenAI error ${resp.status}: ${errorText}`)
      }
      const data = await resp.json()
      content = data.choices?.[0]?.message?.content || 'No response'
    }

    res.json({ content, model, provider: provider || 'openai' })

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
// SAML endpoints
// ======================

// Assertion Consumer Service - Okta POSTs the SAML response here
app.post('/api/saml/acs', async (req, res) => {
  if (!samlEnabled || !sp || !idp) {
    return res.status(503).json({ error: 'SAML not configured' })
  }

  try {
    const { extract } = await sp.parseLoginResponse(idp, 'post', req)

    console.log('[SAML] Login successful for:', extract.attributes?.email || extract.nameID)

    // Build a user object from the assertion (customize attributes as needed)
    const user = {
      id: extract.nameID,
      email: extract.attributes?.email || extract.nameID,
      name: extract.attributes?.firstName && extract.attributes?.lastName
        ? `${extract.attributes.firstName} ${extract.attributes.lastName}`
        : extract.attributes?.displayName || extract.nameID,
      login: extract.attributes?.login || extract.nameID,
      // You can expose more attributes here for the frontend
      attributes: extract.attributes || {},
      authMethod: 'saml',
      samlSessionIndex: extract.sessionIndex,
    }

    // Establish session (this is what requireAuth and /api/auth/me look for)
    req.session.user = user

    // Save session before redirect
    await new Promise((resolve, reject) => {
      req.session.save(err => err ? reject(err) : resolve())
    })

    // Redirect back to the web UI (IdP-initiated flow)
    const successRedirect = process.env.SAML_SUCCESS_REDIRECT || `http://localhost:3200/`
    return res.redirect(successRedirect)

  } catch (err) {
    console.error('[SAML] ACS error:', err.message)
    // In production you would show a nice error page
    res.status(401).send(`SAML authentication failed: ${err.message}`)
  }
})

// Optional: SP-initiated login (redirects user to Okta)
app.get('/api/saml/login', (req, res) => {
  if (!samlEnabled || !sp || !idp) {
    return res.status(503).json({ error: 'SAML not configured' })
  }

  try {
    const { context } = sp.createLoginRequest(idp, 'redirect')
    return res.redirect(context)
  } catch (err) {
    console.error('[SAML] createLoginRequest failed:', err.message)
    return res.status(500).send('Failed to initiate SAML login. Please try again or contact an administrator.')
  }
})

// Logout - destroys the session (simple but effective for now)
app.get('/api/saml/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('[SAML] Logout error:', err)
      return res.status(500).json({ error: 'Failed to log out' })
    }
    // Redirect back to the web app root (splash will show)
    const webRoot = process.env.SAML_SUCCESS_REDIRECT || 'https://ai-admin.skylarbarnes.com/'
    res.redirect(webRoot)
  })
})

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✓ SDAP API server running on http://0.0.0.0:${PORT}`)
  console.log(`  Demo auth bypass: ${process.env.DEMO_AUTH_BYPASS === 'true'}`)
  console.log(`  SAML enabled: ${samlEnabled}`)
  console.log(`  LLM keys present (boolean): OpenAI=${!!process.env.OPENAI_API_KEY} Anthropic=${!!process.env.ANTHROPIC_API_KEY} Grok=${!!process.env.GROK_API_KEY}`)
  console.log(`  Okta token present: ${!!process.env.OKTA_API_TOKEN}`)
})
