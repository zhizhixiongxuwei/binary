import { createPinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type { CurrentUser } from '@/api/types'
import { useSessionStore } from '@/stores/session'

const input = { current_password: 'current-test-value', new_password: 'new-test-value' }
const user: CurrentUser = {
  id: 'test-user', username: 'test-user', display_name: 'Test user',
  role: 'operator', must_change_password: false,
}

beforeEach(() => setActivePinia(createPinia()))
afterEach(() => vi.restoreAllMocks())

describe('session password change', () => {
  it('clears the session only after the password change succeeds and avoids restoring the revoked session', async () => {
    let complete: (() => void) | undefined
    const change = vi.spyOn(api, 'changePassword').mockImplementation(
      () => new Promise<void>((resolve) => { complete = resolve }),
    )
    const getMe = vi.spyOn(api, 'getMe')
    const session = useSessionStore()
    session.user = user

    const pending = session.changePassword(input)
    expect(session.user).toBe(user)
    expect(session.isAuthenticated).toBe(true)
    complete!()
    await pending

    expect(change).toHaveBeenCalledWith(input)
    expect(session.user).toBeNull()
    expect(session.isAuthenticated).toBe(false)
    expect(session.restored).toBe(true)
    await session.restore()
    expect(getMe).not.toHaveBeenCalled()
  })

  it.each([401, 500])('preserves the authenticated user when password change fails with %s', async (status) => {
    const error = new ApiError('Test failure', status, { code: 'invalid_credentials' })
    vi.spyOn(api, 'changePassword').mockRejectedValue(error)
    const session = useSessionStore()
    session.user = user
    session.restored = true

    await expect(session.changePassword(input)).rejects.toBe(error)
    expect(session.user).toBe(user)
    expect(session.isAuthenticated).toBe(true)
    expect(session.restored).toBe(true)
  })
})
