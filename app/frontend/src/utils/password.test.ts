import { describe, expect, it } from 'vitest'

import { validatePasswordChange } from '@/utils/password'

function validate(newPassword: string) {
  return validatePasswordChange({ currentPassword: 'Original_2026!', newPassword, confirmation: newPassword })
}

describe('password change validation', () => {
  it('requires the current password, new password and confirmation', () => {
    expect(validatePasswordChange({ currentPassword: '', newPassword: '', confirmation: '' }))
      .toEqual(expect.objectContaining({
        currentPassword: expect.any(String), newPassword: expect.any(String), confirmation: expect.any(String),
      }))
  })

  it.each([8, 72])('accepts the %i-byte boundary', (length) => {
    expect(validate('a'.repeat(length))).toEqual({})
  })

  it.each([7, 73])('rejects a %i-byte password', (length) => {
    expect(validate('a'.repeat(length)).newPassword).toBeTruthy()
  })

  it('uses UTF-8 byte length for Chinese passwords', () => {
    expect(validate('密'.repeat(24))).toEqual({})
    expect(validate('密'.repeat(25)).newPassword).toBeTruthy()
  })

  it('rejects reuse of the current password', () => {
    expect(validate('Original_2026!').newPassword).toBeTruthy()
  })

  it('rejects a confirmation that differs from the new password', () => {
    expect(validatePasswordChange({
      currentPassword: 'Original_2026!', newPassword: 'Updated_2026!', confirmation: 'Different_2026!',
    }).confirmation).toBeTruthy()
  })
})
