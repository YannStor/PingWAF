import { describe, expect, it, vi } from 'vitest'

// ipRules imports `client` (for apiClient) which pulls in authStore/localStorage;
// only the validation helpers are under test here.
vi.mock('./client', () => ({ apiClient: {} }))

import { isValidIpv6, parseIpList, validateIpOrCidr } from './ipRules'

describe('isValidIpv6', () => {
  it.each([
    '::1',
    'fe80::1',
    '1:2:3:4:5:6:7:8',
    '::',
    '::ffff:192.168.1.1',
    '2001:db8:0:0:0:0:2:1',
    '2001:db8::2:1',
    '1:2:3:4:5:6:1.2.3.4', // 6 hex groups + IPv4 tail = 8 groups
    '::1.2.3.4',
  ])('accepts %s', (v) => {
    expect(isValidIpv6(v)).toBe(true)
  })

  it.each([
    '1::2::3', // more than one ::
    '12345::', // group too long
    '1:2:3:4:5:6:7:8:9', // 9 groups without ::
    '1:2:3:4:5:6:7', // 7 groups without ::
    '1:2:::3', // :::
    '1.2.3.4', // not IPv6
    '1::2:3::4', // double compression
    'gggg::1', // non-hex
    '1:2:3:4:5:6:7:1.2.3.4', // IPv4 tail without ::
    '1.2.3.4::', // `::` must compress at least one group
    '1:2:3:4:5:6:7:8::', // 8 groups + `::` compresses nothing
    '1:2::3.4.5', // malformed IPv4 tail
  ])('rejects %s', (v) => {
    expect(isValidIpv6(v)).toBe(false)
  })
})

describe('parseIpList', () => {
  it('splits, dedupes and classifies entries', () => {
    const r = parseIpList('1.2.3.4\n1.2.3.4\n10.0.0.0/8\nbad_ip\nbad_ip\n')
    expect(r.valid).toEqual(['1.2.3.4', '10.0.0.0/8'])
    expect(r.invalid).toEqual(['bad_ip'])
    expect(r.duplicateCount).toBe(2)
  })

  it('handles comma and semicolon separators and blanks', () => {
    const r = parseIpList('1.1.1.1, 2.2.2.2;;\n\n')
    expect(r.valid).toEqual(['1.1.1.1', '2.2.2.2'])
    expect(r.invalid).toEqual([])
    expect(r.duplicateCount).toBe(0)
  })
})

describe('validateIpOrCidr', () => {
  it('stays unrestricted without minPrefix (bulk import keeps wide CIDRs)', () => {
    expect(validateIpOrCidr('10.0.0.0/8')).toBeNull()
    expect(validateIpOrCidr('::/0')).toBeNull()
  })

  it('enforces the width floor with tooBroad when minPrefix is given', () => {
    const min = { v4: 16, v6: 32 }
    expect(validateIpOrCidr('10.0.0.0/8', min)).toBe('tooBroad')
    expect(validateIpOrCidr('10.0.0.0/16', min)).toBeNull()
    expect(validateIpOrCidr('2001:db8::/31', min)).toBe('tooBroad')
    expect(validateIpOrCidr('2001:db8::/32', min)).toBeNull()
    // Bare addresses are unaffected by the width floor.
    expect(validateIpOrCidr('10.0.0.1', min)).toBeNull()
  })

  it('rejects an empty prefix (`10.0.0.0/`)', () => {
    expect(validateIpOrCidr('10.0.0.0/')).toBe('malformed')
    expect(validateIpOrCidr('2001:db8::/')).toBe('malformed')
  })
})
