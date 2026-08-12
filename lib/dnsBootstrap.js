// Preload via NODE_OPTIONS=--import=./lib/dnsBootstrap.js (see ecosystem.config.cjs).
// Some host resolvers (e.g. VPN/overlay-network DNS) SERVFAIL for certain public
// domains; Node fetch uses getaddrinfo via dns.lookup. Route lookups through
// dns.resolve4 on explicit resolvers instead.

import dns from 'node:dns'

const servers = (process.env.DNS_SERVERS || '1.1.1.1,8.8.8.8')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)
dns.setServers(servers)

const origLookup = dns.lookup.bind(dns)

function lookupViaResolver(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options
    options = {}
  } else if (typeof options === 'number') {
    options = { family: options }
  } else if (!options) {
    options = {}
  }

  dns.resolve4(hostname, (err, addresses) => {
    if (err) return origLookup(hostname, options, callback)
    if (options.all) {
      callback(null, addresses.map((address) => ({ address, family: 4 })))
    } else {
      callback(null, addresses[0], 4)
    }
  })
}

dns.lookup = lookupViaResolver

if (dns.promises?.lookup) {
  dns.promises.lookup = (hostname, options) =>
    new Promise((resolve, reject) => {
      lookupViaResolver(hostname, options, (err, address, family) => {
        if (err) return reject(err)
        if (options?.all) resolve(address)
        else resolve({ address, family })
      })
    })
}
