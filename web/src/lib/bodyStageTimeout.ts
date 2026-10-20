/**
 * Body-stage inspection budget bounds — must match the server contract.
 * Shared between ProtectionPage and its tests (kept dependency-free so the
 * pure normalisation logic can be unit-tested in a node environment).
 */
export const BODY_STAGE_TIMEOUT_MIN = 1
export const BODY_STAGE_TIMEOUT_MAX = 30
export const BODY_STAGE_TIMEOUT_DEFAULT = 30

export function clampBodyStageTimeout(value: number): number {
  return Math.min(
    Math.max(Math.round(value), BODY_STAGE_TIMEOUT_MIN),
    BODY_STAGE_TIMEOUT_MAX,
  )
}

/**
 * Normalise a raw input string against the currently committed value.
 * Returns `null` when the draft must NOT be committed (empty string or
 * non-numeric input) — the caller should revert the field to `committed`
 * instead of silently sending a mutation. Valid numbers (including
 * out-of-range ones, e.g. 99 or -5) are clamped to [MIN, MAX]; clamping
 * was chosen over reverting so accidental 0/negative entries still yield
 * a sane, contract-compliant value.
 */
export function normaliseBodyStageTimeout(
  raw: string,
  _committed: number, // reserved: caller reverts to this when the result is null
): number | null {
  const trimmed = raw.trim()
  if (trimmed === '') return null
  const parsed = Number(trimmed)
  if (!Number.isFinite(parsed)) return null
  return clampBodyStageTimeout(parsed)
}
