import { describe, expect, it, vi } from 'vitest'

// aiCrawl imports `client` (for apiClient) which pulls in authStore/localStorage;
// only the pure helpers are under test here.
vi.mock('./client', () => ({ apiClient: {} }))

import { aiCrawlBodyTooLong, aiCrawlRangeFor } from './aiCrawl'
import { AI_CRAWL_ACTIONS, AI_CRAWL_POLICY_ACTIONS } from './types'

describe('aiCrawlRangeFor', () => {
  it('widens narrow presets to the smallest supported window', () => {
    expect(aiCrawlRangeFor('1h')).toBe('24h')
    expect(aiCrawlRangeFor('6h')).toBe('24h')
    expect(aiCrawlRangeFor('24h')).toBe('24h')
    expect(aiCrawlRangeFor('7d')).toBe('7d')
    expect(aiCrawlRangeFor('30d')).toBe('30d')
  })
})

describe('aiCrawlBodyTooLong', () => {
  it('accepts bodies at or below 64 KiB and rejects larger ones', () => {
    expect(aiCrawlBodyTooLong('')).toBe(false)
    expect(aiCrawlBodyTooLong('x'.repeat(64 * 1024))).toBe(false)
    expect(aiCrawlBodyTooLong('x'.repeat(64 * 1024 + 1))).toBe(true)
    // Multi-byte characters count by UTF-8 bytes, not JS chars.
    expect(aiCrawlBodyTooLong('é'.repeat(64 * 1024))).toBe(true)
  })
})

describe('action catalogs', () => {
  it('mirror the wire contract', () => {
    expect(AI_CRAWL_ACTIONS).toEqual(['allow', 'monitor', 'block'])
    expect(AI_CRAWL_POLICY_ACTIONS).toEqual(['inherit', 'allow', 'monitor', 'block'])
  })
})
