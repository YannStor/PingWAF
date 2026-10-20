/**
 * Shared rewrite / upstream-host validators — the single front-end copy of
 * the server's rules (`pingwaf-server` route payload validation).
 *
 * RouteDialog and the contract tests import from here;
 * `pages/sites/basic/types.ts` re-exports the same names for compatibility.
 */

/** The server counts UTF-8 bytes, not UTF-16 code units. */
export const MAX_REWRITE_PATH_BYTES = 2048

/**
 * Mirrors the server's `rewrite_path` validation (`/`-rooted, ≤2048 bytes,
 * no `?`/`#`/whitespace/control characters). Returns true when the raw input
 * can be submitted.
 */
export function isValidRewritePath(raw: string): boolean {
  const path = raw.trim()
  // eslint-disable-next-line no-control-regex -- mirrors the server's control-char rejection
  if (!path.startsWith('/') || /[\s\u0000-\u001f\u007f-\u009f?#]/.test(path)) return false
  return new TextEncoder().encode(path).length <= MAX_REWRITE_PATH_BYTES
}

/**
 * Mirrors the server's `upstream_host` validation: a bare host name — no
 * scheme, path, whitespace or control characters, at most 253 bytes.
 *
 * 控制字符范围与服务端 `char::is_control` 对齐：拒绝 C0（\u0000-\u001f）、
 * DEL+C1（\u007f-\u009f）以及 JS 行分隔符 \u2028/\u2029。
 */
export function isValidUpstreamHost(raw: string): boolean {
  const host = raw.trim()
  if (!host || host.length > 253) return false
  if (new TextEncoder().encode(host).byteLength > 253) return false
  if (host.includes('/') || host.includes('://')) return false
  // eslint-disable-next-line no-control-regex -- mirrors the server's control-char rejection
  if (/[\s\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(host)) return false
  return true
}
