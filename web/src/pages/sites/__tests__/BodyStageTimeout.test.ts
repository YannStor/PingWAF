import { describe, expect, it } from 'vitest'
import { normaliseBodyStageTimeout } from '@/lib/bodyStageTimeout'

describe('normaliseBodyStageTimeout', () => {
  it('returns null for empty/whitespace input (revert, no mutation)', () => {
    expect(normaliseBodyStageTimeout('', 30)).toBeNull()
    expect(normaliseBodyStageTimeout('   ', 30)).toBeNull()
  })

  it('returns null for non-numeric input (revert, no mutation)', () => {
    expect(normaliseBodyStageTimeout('abc', 30)).toBeNull()
  })

  it('clamps out-of-range numbers to [1, 30]', () => {
    expect(normaliseBodyStageTimeout('99', 30)).toBe(30)
    expect(normaliseBodyStageTimeout('-5', 30)).toBe(1)
    expect(normaliseBodyStageTimeout('0', 30)).toBe(1)
  })

  it('passes through in-range values', () => {
    expect(normaliseBodyStageTimeout('15', 30)).toBe(15)
    expect(normaliseBodyStageTimeout('15.7', 15)).toBe(16)
  })
})
