#!/usr/bin/env node
import { spawn } from 'child_process'
import dotenv from 'dotenv'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

dotenv.config({ path: join(__dirname, '.env.local') })
dotenv.config({ path: join(__dirname, '.env') })

const WEB_PORT = process.env.PORT || 3200
const API_PORT = process.env.API_PORT || 3201

console.log('🚀 Starting Super Duper Admin Portal...')
console.log(`   Web:  http://0.0.0.0:${WEB_PORT}`)
console.log(`   API:  http://0.0.0.0:${API_PORT}`)
console.log('   (Ports chosen as free on this crowded machine — override via .env if needed)')
console.log('')

// Start API server
const apiServer = spawn('node', ['api-server.js'], {
  stdio: 'inherit',
  env: { ...process.env, PORT: API_PORT, API_PORT }
})

// Start web server (after slight delay so API is ready)
setTimeout(() => {
  const webServer = spawn('node', ['web-server.js'], {
    stdio: 'inherit',
    env: { ...process.env, PORT: WEB_PORT }
  })

  webServer.on('error', (err) => {
    console.error('Web server error:', err)
  })

  process.on('SIGTERM', () => {
    console.log('\nShutting down servers...')
    webServer.kill()
    apiServer.kill()
    process.exit(0)
  })

  process.on('SIGINT', () => {
    console.log('\nShutting down servers...')
    webServer.kill()
    apiServer.kill()
    process.exit(0)
  })
}, 400)

apiServer.on('error', (err) => {
  console.error('API server error:', err)
})

apiServer.on('exit', (code) => {
  if (code !== 0) {
    console.error(`API server exited with code ${code}`)
    process.exit(code)
  }
})
