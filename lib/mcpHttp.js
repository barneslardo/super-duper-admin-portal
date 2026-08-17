/**
 * OAuth-protected HTTP MCP endpoint for the Super Duper Admin Portal.
 *
 * The portal already ships a stdio MCP server (mcp-server/index.js) for desktop
 * clients. That transport can't be registered in Okta's MCP Server catalog,
 * which needs an HTTPS resource URL publishing RFC 9728 metadata — so this adds
 * the HTTP face of the same three tools.
 *
 * The difference that matters: every call here must present an access token from
 * the Super Duper Admin authorization server, and each tool declares the sdap.*
 * scope that authorizes it. The stdio server trusts whoever can run the process.
 */
import { randomUUID } from 'crypto'
import { createRemoteJWKSet, jwtVerify } from 'jose'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  isInitializeRequest,
} from '@modelcontextprotocol/sdk/types.js'

const ISSUER = (process.env.RESOURCE_AS_ISSUER || '').replace(/\/$/, '')
const API_PUBLIC_URL = (process.env.API_PUBLIC_URL || 'https://ai-admin-api.skylarbarnes.com').replace(/\/$/, '')
const RESOURCE_URL = process.env.MCP_RESOURCE_URL || `${API_PUBLIC_URL}/mcp`
const API_BASE = `http://127.0.0.1:${process.env.API_PORT || 3201}`

const SCOPES_SUPPORTED = [
  'sdap.users.read',
  'sdap.users.manage',
  'sdap.logs.read',
  'sdap.act',
  'sdap.workflow.invoke',
]

/** Tool → the scopes that authorize it. Any one is sufficient. */
const TOOLS = [
  {
    name: 'sdap_chat',
    description:
      'Ask the Super Duper Admin assistant a question about the Okta org (users, groups, logs, policies).',
    requiredScopes: ['sdap.users.read', 'sdap.act'],
    inputSchema: {
      type: 'object',
      properties: {
        message: { type: 'string', description: 'The question to ask' },
        model: { type: 'string', description: 'Optional model override' },
      },
      required: ['message'],
    },
  },
  {
    name: 'sdap_trigger_action',
    description:
      'Trigger an administrative action (suspend, unsuspend, reset password, etc). Actions that require approval enter the Okta access-request flow rather than executing immediately.',
    requiredScopes: ['sdap.act', 'sdap.users.manage'],
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'Action id, e.g. suspend_user' },
        targetUserId: { type: 'string' },
        reason: { type: 'string' },
      },
      required: ['action'],
    },
  },
  {
    name: 'sdap_okta_request',
    description:
      'Read from the Okta Management API through the portal backend. Write methods additionally require sdap.users.manage.',
    requiredScopes: ['sdap.users.read', 'sdap.logs.read'],
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Okta API path, e.g. /api/v1/users?limit=5' },
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'DELETE'] },
        body: { type: 'object' },
      },
      required: ['path'],
    },
  },
]

let jwks = null
function getJwks() {
  if (!jwks && ISSUER) jwks = createRemoteJWKSet(new URL(`${ISSUER}/v1/keys`))
  return jwks
}

function scopesFrom(payload) {
  if (Array.isArray(payload.scp)) return payload.scp.map(String)
  if (typeof payload.scp === 'string') return payload.scp.split(' ')
  if (typeof payload.scope === 'string') return payload.scope.split(' ')
  return []
}

async function verifyBearer(req) {
  const header = req.headers.authorization
  if (!header?.startsWith('Bearer ')) return { ok: false, reason: 'An access token is required' }
  const set = getJwks()
  if (!set) return { ok: false, reason: 'RESOURCE_AS_ISSUER is not configured' }
  try {
    const { payload } = await jwtVerify(header.slice(7), set, {
      issuer: ISSUER,
      audience: [RESOURCE_URL, `${API_PUBLIC_URL}/mcp`],
    })
    return {
      ok: true,
      scopes: scopesFrom(payload),
      subject: payload.sub,
      email: typeof payload.email === 'string' ? payload.email : undefined,
    }
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : 'Token verification failed' }
  }
}

function prmBody() {
  return {
    resource: RESOURCE_URL,
    authorization_servers: [ISSUER],
    scopes_supported: SCOPES_SUPPORTED,
    bearer_methods_supported: ['header'],
    resource_name: 'Super Duper Admin Portal',
    resource_documentation: 'https://ai-admin.skylarbarnes.com',
    mcp_protocol_version: '2025-03-26',
  }
}

async function callInternal(path, init) {
  const resp = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
  })
  const text = await resp.text()
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

function buildServer(auth) {
  const server = new Server(
    { name: 'super-duper-admin-portal', version: '1.0.0' },
    { capabilities: { tools: {} } }
  )

  const allowed = TOOLS.filter(
    (t) => auth.scopes.includes('sdap.admin') || t.requiredScopes.some((s) => auth.scopes.includes(s))
  )

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: allowed.map((t) => ({
      name: t.name,
      description: `${t.description} (authorized by ${t.requiredScopes.join(' or ')})`,
      inputSchema: t.inputSchema,
    })),
  }))

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const tool = TOOLS.find((t) => t.name === request.params.name)
    const args = request.params.arguments || {}

    if (!tool) {
      return { content: [{ type: 'text', text: `Unknown tool: ${request.params.name}` }], isError: true }
    }
    if (!tool.requiredScopes.some((s) => auth.scopes.includes(s))) {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                error: 'insufficient_scope',
                tool: tool.name,
                requiredScopes: tool.requiredScopes,
                presentedScopes: auth.scopes,
                userMessage: `This token does not carry ${tool.requiredScopes.join(' or ')}, so ${tool.name} is not available to it.`,
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      }
    }

    if (tool.name === 'sdap_chat') {
      const data = await callInternal('/api/chat', {
        method: 'POST',
        body: JSON.stringify({
          messages: [{ role: 'user', content: args.message }],
          model: args.model || 'gpt-4o',
        }),
      })
      return { content: [{ type: 'text', text: data?.content ?? JSON.stringify(data) }] }
    }

    if (tool.name === 'sdap_trigger_action') {
      const data = await callInternal(`/api/actions/${args.action}`, {
        method: 'POST',
        body: JSON.stringify({
          targetUserId: args.targetUserId,
          reason: args.reason,
          requestedBy: auth.email || `mcp:${auth.subject}`,
        }),
      })
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] }
    }

    // sdap_okta_request
    const method = (args.method || 'GET').toUpperCase()
    if (method !== 'GET' && !auth.scopes.includes('sdap.users.manage')) {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'insufficient_scope',
              requiredScopes: ['sdap.users.manage'],
              userMessage: `${method} against the Okta API needs sdap.users.manage; this token is read-only.`,
            }),
          },
        ],
        isError: true,
      }
    }
    const data = await callInternal(`/api/okta${args.path}`, {
      method,
      body: args.body ? JSON.stringify(args.body) : undefined,
    })
    return { content: [{ type: 'text', text: JSON.stringify(data, null, 2).slice(0, 8000) }] }
  })

  return server
}

export function mountMcpRoutes(app) {
  const prm = prmBody()
  const metadataPaths = [
    '/.well-known/oauth-protected-resource',
    '/.well-known/oauth-protected-resource/mcp',
    '/mcp/.well-known/oauth-protected-resource',
  ]
  for (const p of metadataPaths) {
    app.get(p, (_req, res) => {
      res.setHeader('Cache-Control', 'public, max-age=300')
      res.setHeader('Access-Control-Allow-Origin', '*')
      res.json(prm)
    })
  }

  app.get('/.well-known/oauth-authorization-server', async (_req, res) => {
    try {
      const upstream = await fetch(`${ISSUER}/.well-known/oauth-authorization-server`)
      const body = await upstream.json()
      res.json({ ...body, resource: RESOURCE_URL })
    } catch (err) {
      res.status(502).json({ error: 'Failed to load authorization server metadata' })
    }
  })

  const transports = {}

  const challenge = (res, description) => {
    res.setHeader(
      'WWW-Authenticate',
      `Bearer resource_metadata="${API_PUBLIC_URL}/.well-known/oauth-protected-resource", error="invalid_token", error_description="${description}"`
    )
    res.status(401).json({ jsonrpc: '2.0', error: { code: -32001, message: description }, id: null })
  }

  const handler = async (req, res) => {
    const auth = await verifyBearer(req)
    if (!auth.ok) return challenge(res, auth.reason)

    const sessionId = req.headers['mcp-session-id']
    try {
      if (sessionId && transports[sessionId]) {
        return await transports[sessionId].handleRequest(req, res, req.body)
      }
      if (!sessionId && isInitializeRequest(req.body)) {
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (id) => {
            transports[id] = transport
          },
        })
        transport.onclose = () => {
          if (transport.sessionId) delete transports[transport.sessionId]
        }
        await buildServer(auth).connect(transport)
        return await transport.handleRequest(req, res, req.body)
      }
      res.status(400).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Bad Request: no valid MCP session id' },
        id: null,
      })
    } catch (err) {
      console.error('[mcp] error:', err)
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal error' }, id: null })
      }
    }
  }

  app.post('/mcp', handler)
  app.get('/mcp', handler)
  app.delete('/mcp', handler)

  console.log(`[mcp] HTTP MCP endpoint ready at ${RESOURCE_URL} (issuer ${ISSUER || 'UNSET'})`)
}
