// File-backed access-request cache — survives PM2 / api-server restarts.

import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'fs'
import { join } from 'path'
import { isAccessRequestTerminal } from './oktaAccessRequests.js'
import { dataDir } from './dataDir.js'

const TERMINAL_TTL_MS = 30 * 24 * 60 * 60 * 1000 // drop terminal records after 30 days

function defaultPath() {
  return join(dataDir(), 'access-requests.json')
}

function parseUpdatedAt(record) {
  const t = Date.parse(record?.updatedAt || record?.completedAt || '')
  return Number.isFinite(t) ? t : 0
}

export class AccessRequestStore {
  constructor(filePath = defaultPath()) {
    this.filePath = filePath
    mkdirSync(dataDir(), { recursive: true })
    this.map = new Map()
    this.saveTimer = null
    this.dirty = false
    this.load()
  }

  load() {
    try {
      const raw = readFileSync(this.filePath, 'utf8')
      const obj = JSON.parse(raw)
      if (!obj || typeof obj !== 'object') return
      const now = Date.now()
      for (const [requestId, record] of Object.entries(obj)) {
        if (!record || typeof record !== 'object') continue
        if (isAccessRequestTerminal(record.status) && now - parseUpdatedAt(record) > TERMINAL_TTL_MS) {
          continue
        }
        this.map.set(requestId, record)
      }
      console.log(`[access-request store] loaded ${this.map.size} record(s) from ${this.filePath}`)
    } catch (e) {
      if (e?.code !== 'ENOENT') {
        console.warn('[access-request store] load failed:', e.message)
      }
    }
  }

  scheduleSave() {
    if (this.saveTimer) return
    this.saveTimer = setTimeout(() => {
      this.saveTimer = null
      this.save()
    }, 400)
  }

  save() {
    if (!this.dirty) return
    try {
      const obj = Object.fromEntries(this.map)
      const tmp = `${this.filePath}.${process.pid}.tmp`
      writeFileSync(tmp, JSON.stringify(obj, null, 2), 'utf8')
      renameSync(tmp, this.filePath)
      this.dirty = false
    } catch (e) {
      console.error('[access-request store] save failed:', e.message)
    }
  }

  flush() {
    if (this.saveTimer) {
      clearTimeout(this.saveTimer)
      this.saveTimer = null
    }
    this.save()
  }

  get(requestId) {
    return this.map.get(requestId)
  }

  set(requestId, record) {
    this.map.set(requestId, record)
    this.dirty = true
    this.scheduleSave()
    return this
  }

  /** Shallow-merge into an existing record (or create). */
  merge(requestId, partial) {
    const next = {
      ...(this.map.get(requestId) || {}),
      ...partial,
      updatedAt: partial.updatedAt || new Date().toISOString(),
    }
    this.set(requestId, next)
    return next
  }

  size() {
    return this.map.size
  }
}
