import { describe, expect, it } from 'vitest'
import { investigationReturn, withInvestigationReturn } from './investigationContext'

describe('investigation context', () => {
  it('preserves the exact local workspace state in a host drill-down', () => {
    const result = withInvestigationReturn('/hosts/host-1', {
      pathname: '/findings',
      search: '?category=ssh&severity=critical&page=2',
      hash: '',
    })
    expect(result).toBe('/hosts/host-1?return_to=%2Ffindings%3Fcategory%3Dssh%26severity%3Dcritical%26page%3D2')
  })

  it('accepts known console workspaces and rejects external or unknown return targets', () => {
    expect(investigationReturn('/applications?search=openssl')).toEqual({ to: '/applications?search=openssl', label: 'Applications' })
    expect(investigationReturn('https://attacker.example/findings')).toBeNull()
    expect(investigationReturn('//attacker.example/findings')).toBeNull()
    expect(investigationReturn('/settings/users')).toBeNull()
  })
})
