import { describe, expect, it } from 'vitest'
import { MAX_REWRITE_PATH_BYTES, isValidRewritePath, isValidUpstreamHost } from '@/lib/routeRewrite'

/** rewrite_path 校验：与后端 sites.rs `validate_route` 对齐。 */
describe('isValidRewritePath', () => {
  it('accepts /-rooted paths within 2048 bytes', () => {
    expect(isValidRewritePath('/api/users')).toBe(true)
    expect(isValidRewritePath('  /padded  ')).toBe(true)
    expect(isValidRewritePath('/' + 'a'.repeat(2047))).toBe(true)
  })

  it('rejects over-long paths by UTF-8 bytes, not code units', () => {
    expect(isValidRewritePath('/' + 'a'.repeat(2048))).toBe(false)
    // 2048 bytes total: 'é' is 2 bytes, so 2047 chars of 'é' + '/' = 4095… too long.
    expect(isValidRewritePath('/' + 'é'.repeat(1023))).toBe(true) // 1 + 2046 = 2047 bytes
    expect(isValidRewritePath('/' + 'é'.repeat(1024))).toBe(false) // 2049 bytes
    expect(MAX_REWRITE_PATH_BYTES).toBe(2048)
  })

  it('rejects query, fragment and whitespace like the server', () => {
    expect(isValidRewritePath('/a?b')).toBe(false)
    expect(isValidRewritePath('/a#b')).toBe(false)
    expect(isValidRewritePath('/a b')).toBe(false)
    expect(isValidRewritePath('/a\tb')).toBe(false)
    expect(isValidRewritePath('/a\nb')).toBe(false)
  })

  it('rejects control characters (C0, DEL, C1) like char::is_control', () => {
    expect(isValidRewritePath('/a\u0000b')).toBe(false)
    expect(isValidRewritePath('/a\u001fb')).toBe(false)
    expect(isValidRewritePath('/a\u007fb')).toBe(false)
    expect(isValidRewritePath('/a\u0080b')).toBe(false)
    expect(isValidRewritePath('/a\u009fb')).toBe(false)
  })

  it('rejects paths without a leading slash or empty', () => {
    expect(isValidRewritePath('api/users')).toBe(false)
    expect(isValidRewritePath('')).toBe(false)
    expect(isValidRewritePath('   ')).toBe(false)
  })
})

/** upstream_host 校验：与后端 `validate_upstream_host` 对齐。 */
describe('isValidUpstreamHost', () => {
  it('accepts bare hosts and host:port', () => {
    expect(isValidUpstreamHost('www.example.com')).toBe(true)
    expect(isValidUpstreamHost('example.com:8443')).toBe(true)
    expect(isValidUpstreamHost('  spaced.example.com  ')).toBe(true)
  })

  it('rejects scheme, path, whitespace and over-long values', () => {
    expect(isValidUpstreamHost('http://x.com')).toBe(false)
    expect(isValidUpstreamHost('a/b')).toBe(false)
    expect(isValidUpstreamHost('a b')).toBe(false)
    expect(isValidUpstreamHost('x'.repeat(254))).toBe(false)
    expect(isValidUpstreamHost('x'.repeat(253))).toBe(true)
    expect(isValidUpstreamHost('é'.repeat(126))).toBe(true) // 252 bytes
    expect(isValidUpstreamHost('é'.repeat(127))).toBe(false) // 254 bytes
  })

  it('rejects C0/C1 control chars and JS line separators', () => {
    expect(isValidUpstreamHost('a\u0000b')).toBe(false)
    expect(isValidUpstreamHost('a\u001fb')).toBe(false)
    expect(isValidUpstreamHost('a\u007fb')).toBe(false)
    expect(isValidUpstreamHost('a\u0080b')).toBe(false)
    expect(isValidUpstreamHost('a\u009fb')).toBe(false)
    expect(isValidUpstreamHost('a\u2028b')).toBe(false)
    expect(isValidUpstreamHost('a\u2029b')).toBe(false)
    expect(isValidUpstreamHost('')).toBe(false)
  })
})
