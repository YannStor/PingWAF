import { describe, expect, it } from 'vitest'
import type { Visitor } from '@/api/types'
import {
  createVisitorPayload,
  updateVisitorPayload,
  visitorFormFrom,
} from './visitorForm'

const visitor: Visitor = {
  id: 'visitor-1',
  email: 'ann@example.test',
  name: 'Ann',
  remark: 'Night-shift reviewer',
  disabled: false,
  site_ids: ['site-1'],
  created_at: '2026-10-25T00:00:00Z',
  updated_at: '2026-10-25T00:00:00Z',
}

describe('visitor form payloads', () => {
  it('round-trips the remark into the edit form', () => {
    expect(visitorFormFrom(visitor).remark).toBe('Night-shift reviewer')
  })

  it('trims display fields when creating a visitor', () => {
    expect(
      createVisitorPayload({
        email: ' ann@example.test ',
        password: 'password-123',
        name: ' Ann ',
        remark: '  collaborator  ',
        disabled: false,
        siteIds: ['site-1'],
      }),
    ).toMatchObject({
      email: 'ann@example.test',
      name: 'Ann',
      remark: 'collaborator',
    })
  })

  it('sends an empty remark to clear it and preserves an untouched password', () => {
    const payload = updateVisitorPayload({
      email: visitor.email,
      password: '',
      name: visitor.name,
      remark: '   ',
      disabled: false,
      siteIds: visitor.site_ids,
    })
    expect(payload.remark).toBe('')
    expect(payload).not.toHaveProperty('password')
  })
})
