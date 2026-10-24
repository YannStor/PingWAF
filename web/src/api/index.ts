/**
 * Barrel for the REST layer.
 *
 * Every endpoint group lives in its own module next to this file; pages should
 * import from here (`import { sitesApi, useSites } from '@/api'`) so the wire
 * types and the query hooks stay discoverable in one place.
 */
export * from './client'
export * from './types'
export * from './errors'

export * from './auth'
export * from './passkeys'
export * from './sites'
export * from './rules'
export * from './rateLimiting'
export * from './analytics'
export * from './logs'
export * from './agents'
export * from './settings'
export * from './apiProtection'
export * from './keys'
export * from './system'
export * from './tls'
export * from './ssl'
export * from './caching'
export * from './challenge'
export * from './ipRules'
export * from './rewrite'
export * from './errorPages'
export * from './traffic'
export * from './bot'
export * from './geo'
export * from './siteBasicAuth'
export * from './siteOidc'
export * from './ai'
export * from './notifications'
export * from './configVersions'
export * from './failover'
