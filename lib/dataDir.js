import { mkdirSync } from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const projectRoot = join(__dirname, '..')

/** Writable runtime data directory (access-request cache, sessions). */
export function dataDir() {
  const dir = process.env.SDAP_DATA_DIR || join(projectRoot, '.data')
  mkdirSync(dir, { recursive: true })
  return dir
}
