// scripts/activity-report-check.mjs — offline check of lib/agentActivity.js against the live
// System Log (read-only, SSWS token from .env.local). Usage: node scripts/activity-report-check.mjs [hours] [brief|full] [user]
import dotenv from 'dotenv'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { fetchOktaLogs, buildActivityReport, compactEvent, classifyEvent } from '../lib/agentActivity.js'
const root = join(dirname(fileURLToPath(import.meta.url)), '..')
dotenv.config({ path: join(root, '.env.local'), quiet: true }); dotenv.config({ path: join(root, '.env'), quiet: true })
const hours = Number(process.argv[2] || 24), detail = process.argv[3] || 'full', user = process.argv[4] || null
const until = new Date().toISOString(), since = new Date(Date.now() - hours * 36e5).toISOString()
const t0 = Date.now()
const { events, pages, truncated, coveredFrom, coveredTo } = await fetchOktaLogs({ oktaBase: process.env.OKTA_ORG_URL, token: process.env.OKTA_API_TOKEN, since, until })
console.error(`fetched ${events.length} events in ${pages} page(s), truncated=${truncated}, covered ${coveredFrom}..${coveredTo}, ${Date.now() - t0} ms`)
const tiers = {}
for (const ev of events) { const c = classifyEvent(ev); const k = `${c.tier}${c.mode ? '/' + c.mode : ''}`; tiers[k] = (tiers[k] || 0) + 1 }
console.error('tiers:', JSON.stringify(tiers))
const report = buildActivityReport(events, { since, until, detail, user, fetched: { pages, truncated, coveredFrom, coveredTo } })
const json = JSON.stringify(report, null, 1)
console.error(`report bytes: ${json.length} (${detail})`)
console.error('compact sample:', JSON.stringify(compactEvent(events[events.length - 1])))
console.log(json)
