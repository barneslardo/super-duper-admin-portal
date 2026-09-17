// scripts/chat-harness.mjs — offline end-to-end check of the admin chat agent WITHOUT an OIDC
// session: evaluates the real system prompt + tool definitions out of api-server.js, runs the same
// tool loop against the LLM gateway, and executes tenant_activity_report / fetch_okta_data for real
// (SSWS, read-only). Other tools are stubbed. Usage:
//   node scripts/chat-harness.mjs <model> "<question>" [hours]
import dotenv from 'dotenv'
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { fetchOktaLogs, buildActivityReport, compactEvent } from '../lib/agentActivity.js'
import { directoryRoster } from '../lib/directoryRoster.js'
const root = join(dirname(fileURLToPath(import.meta.url)), '..')
dotenv.config({ path: join(root, '.env.local'), quiet: true })
const [modelId = 'gemma4', question = "what's going on in the tenant today?"] = process.argv.slice(2)
const src = readFileSync(join(root, 'api-server.js'), 'utf8')
const slice = (a, b) => { const i = src.indexOf(a); const j = src.indexOf(b, i); if (i < 0 || j < 0) throw new Error(`anchor missing: ${a}`); return src.slice(i, j + b.length) }
const sessionUser = { name: 'Skylar Barnes', email: 'skylar.barnes@okta.com' }
const model = modelId
const systemPrompt = new Function('sessionUser', 'process', slice("const systemPrompt = [", "].join('\\n')") + '\nreturn systemPrompt')(sessionUser, process)
const toolSrc = slice('const OKTA_TOOL = {', "const ALL_TOOLS = [").replace(/const ALL_TOOLS = \[$/, '')
const tools = new Function('process', toolSrc + '\nreturn [ACTIVITY_TOOL, ROSTER_TOOL, OKTA_TOOL, ACCESS_REQUEST_TOOL, ACCESS_REQUEST_STATUS_TOOL, SECRET_TOOL]')(process)
const smallModel = /gemma/i.test(model)
const oktaBase = process.env.OKTA_ORG_URL.replace(/\/$/, ''), token = process.env.OKTA_API_TOKEN
async function runTool(name, input) {
  if (name === 'tenant_activity_report') {
    const h = Math.min(168, Math.max(0.25, Number(input.hours) || 24))
    const until = input.until ? new Date(input.until) : new Date(), since = input.since ? new Date(input.since) : new Date(until - h * 36e5)
    const detail = input.detail === 'brief' || input.detail === 'full' ? input.detail : (smallModel ? 'brief' : 'full')
    const { events, pages, truncated, coveredFrom, coveredTo } = await fetchOktaLogs({ oktaBase, token, since: since.toISOString(), until: until.toISOString() })
    return buildActivityReport(events, { since: since.toISOString(), until: until.toISOString(), detail, user: input.user || null, fetched: { pages, truncated, coveredFrom, coveredTo } })
  }
  if (name === 'directory_roster') return directoryRoster({ oktaBase, token }, input)
  if (name === 'fetch_okta_data') {
    const p = (input.path || '/').replace(/^\/api\/agent\/okta/, '')
    if (!/^\/(logs|users|authorizationServers)/.test(p)) return { error: 'harness: only read routes' }
    const r = await fetch(`${oktaBase}/api/v1${p}`, { headers: { Authorization: `SSWS ${token}`, Accept: 'application/json' } })
    let data; try { data = JSON.parse(await r.text()) } catch { data = null }
    if (/^\/logs/.test(p) && Array.isArray(data)) { const cap = smallModel ? 40 : 150; return { status: r.status, count: data.length, returned: Math.min(cap, data.length), truncated: data.length > cap, events: data.slice(0, cap).map(compactEvent) } }
    return { status: r.status, data }
  }
  return { error: `harness stub: ${name} not executed` }
}
const endpoint = `${process.env.LLM_BASE_URL.replace(/\/+$/, '')}/chat/completions`
let messages = [{ role: 'system', content: systemPrompt }, { role: 'user', content: question }]
const oaTools = tools.map(t => ({ type: 'function', function: { name: t.name, description: t.description, parameters: t.input_schema } }))
const t0 = Date.now(); let content = ''
for (let round = 0; round < 5; round++) {
  const resp = await fetch(endpoint, { method: 'POST', headers: { 'content-type': 'application/json', Authorization: `Bearer ${process.env.LLM_API_KEY}` }, body: JSON.stringify({ model, messages, tools: oaTools, max_tokens: 4096 }) })
  if (!resp.ok) { console.error('gateway error', resp.status, await resp.text()); process.exit(1) }
  const data = await resp.json(); const choice = data.choices?.[0]
  if (choice?.finish_reason !== 'tool_calls' || !choice?.message?.tool_calls?.length) { content = choice?.message?.content || '(empty)'; break }
  messages.push(choice.message)
  for (const tc of choice.message.tool_calls) {
    let input; try { input = JSON.parse(tc.function.arguments) } catch { input = {} }
    const result = await runTool(tc.function.name, input)
    const body = JSON.stringify(result)
    console.error(`[round ${round}] ${tc.function.name}(${tc.function.arguments}) -> ${body.length} bytes${result?.error ? ' ERROR ' + result.error : ''}`)
    messages.push({ role: 'tool', tool_call_id: tc.id, content: body })
  }
}
console.error(`model=${model} elapsed=${((Date.now() - t0) / 1000).toFixed(1)}s prompt=${systemPrompt.length} chars`)
console.log(content)
