#!/usr/bin/env node
/**
 * Super Duper Admin Portal MCP Server
 *
 * Exposes tools so LLM agents (Claude, Cursor, etc.) can:
 * - Chat with the Okta admin assistant
 * - Trigger admin actions (with approval flows)
 * - Query Okta via the portal backend
 *
 * Run: node mcp-server/index.js   (or via Claude Desktop config)
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js'
import { readFileSync, existsSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const PROJECT_ROOT = join(__dirname, '..')

// Load env (simple)
function loadEnv() {
  const env = {}
  const candidates = [join(PROJECT_ROOT, '.env.local'), join(PROJECT_ROOT, '.env')]
  for (const p of candidates) {
    if (!existsSync(p)) continue
    for (const line of readFileSync(p, 'utf8').split('\n')) {
      const t = line.trim()
      if (!t || t.startsWith('#')) continue
      const i = t.indexOf('=')
      if (i === -1) continue
      env[t.slice(0, i).trim()] = t.slice(i + 1).trim()
    }
  }
  return env
}
const ENV = loadEnv()
const API_BASE = `http://localhost:${ENV.API_PORT || 3001}`

const server = new Server(
  {
    name: 'super-duper-admin-portal',
    version: '0.1.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
)

// Tool definitions
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'sdap_chat',
        description: 'Send a message to the Super Duper Admin Portal Okta assistant (sledai.oktapreview.com). Returns the assistant reply.',
        inputSchema: {
          type: 'object',
          properties: {
            message: { type: 'string', description: 'The question or command for the admin assistant' },
            model: { type: 'string', description: 'Optional model id (gpt-4o, claude-3-5-sonnet-20241022, grok-4.3)' },
          },
          required: ['message'],
        },
      },
      {
        name: 'sdap_trigger_action',
        description: 'Trigger a portal quick action (user suspension, MFA reset, etc). These go through approval workflows in production.',
        inputSchema: {
          type: 'object',
          properties: {
            action: {
              type: 'string',
              enum: ['list-users', 'failed-logins', 'suspend-user', 'reset-mfa'],
              description: 'The action to request',
            },
            targetUserId: { type: 'string', description: 'Okta user ID (when applicable)' },
            reason: { type: 'string' },
          },
          required: ['action'],
        },
      },
      {
        name: 'sdap_okta_request',
        description: 'Make an authenticated Okta Management API call via the portal backend (uses server-side SSWS token).',
        inputSchema: {
          type: 'object',
          properties: {
            path: { type: 'string', description: 'Path under /api/v1 e.g. /users?limit=20 or /logs?since=...' },
            method: { type: 'string', enum: ['GET', 'POST'], default: 'GET' },
            body: { type: 'object', description: 'JSON body for POST/PUT' },
          },
          required: ['path'],
        },
      },
    ],
  }
})

// Tool implementations
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params

  if (name === 'sdap_chat') {
    const { message, model } = args || {}
    const resp = await fetch(`${API_BASE}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messages: [{ role: 'user', content: message }],
        model: model || 'gpt-4o',
      }),
    })
    if (!resp.ok) {
      const t = await resp.text()
      return { content: [{ type: 'text', text: `Chat failed: ${t}` }] }
    }
    const data = await resp.json()
    return { content: [{ type: 'text', text: data.content }] }
  }

  if (name === 'sdap_trigger_action') {
    const { action, targetUserId, reason } = args || {}
    const resp = await fetch(`${API_BASE}/api/actions/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUserId, reason, requestedBy: 'mcp-agent' }),
    })
    const data = await resp.json().catch(() => ({}))
    return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] }
  }

  if (name === 'sdap_okta_request') {
    const { path, method = 'GET', body } = args || {}
    const resp = await fetch(`${API_BASE}/api/okta${path}`, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    })
    const text = await resp.text()
    let out
    try { out = JSON.parse(text) } catch { out = text }
    return { content: [{ type: 'text', text: JSON.stringify(out, null, 2).slice(0, 8000) }] }
  }

  throw new Error(`Unknown tool: ${name}`)
})

// Start stdio transport
const transport = new StdioServerTransport()
await server.connect(transport)

console.error('Super Duper Admin Portal MCP server ready (stdio)')
