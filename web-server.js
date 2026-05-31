import express from 'express'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import morgan from 'morgan'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const app = express()
const PORT = process.env.PORT || 3200

// Logging
app.use(morgan('combined'))

// Security headers (good baseline for internal admin tool)
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-XSS-Protection', '1; mode=block')
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
  // When you add SAML + real auth you may want CSP and HSTS
  next()
})

// Serve built static files
app.use(express.static(join(__dirname, 'dist')))

// SPA fallback for client-side routing (Express 5 compatible)
app.use((req, res) => {
  // Don't rewrite API or asset paths that somehow reach here
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' })
  }
  res.sendFile(join(__dirname, 'dist', 'index.html'))
})

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✓ SDAP Web server running on http://0.0.0.0:${PORT}`)
  console.log(`  Serving dist/ (build the app first with "npm run build")`)
})
