import { describe, expect, it } from 'vitest'
import { accountSections } from './accountNav'

describe('account page sections', () => {
  it('keeps API keys last and preserves the administration order', () => {
    expect(accountSections(true).map((section) => section.id)).toEqual([
      'oidc-providers',
      'visitors',
      'users',
      'api-keys',
    ])
  })

  it('only exposes the sections a non-admin can actually use', () => {
    expect(accountSections(false).map((section) => section.id)).toEqual([
      'api-keys',
    ])
  })
})
