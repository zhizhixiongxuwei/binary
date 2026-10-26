import { describe, expect, it } from 'vitest'

import type { CurrentUser, UserRole } from '@/api/types'
import { passwordRouteRedirect } from '@/router/guards'

function user(role: UserRole, mustChange = false): CurrentUser {
  return { id: 'password-test-user', username: 'tester', display_name: 'Tester', role, must_change_password: mustChange }
}

describe('password page access', () => {
  it.each<UserRole>(['administrator', 'operator', 'reader'])(
    'lets an authenticated %s change their own password voluntarily',
    (role) => expect(passwordRouteRedirect(user(role), 'change-password')).toBeNull(),
  )

  it.each(['overview', 'tasks', 'system', 'login'])(
    'keeps users with an initial password out of %s',
    (route) => expect(passwordRouteRedirect(user('reader', true), route)).toBe('change-password'),
  )

  it('allows the mandatory password page without a redirect loop', () => {
    expect(passwordRouteRedirect(user('operator', true), 'change-password')).toBeNull()
  })

  it('leaves anonymous users to the authentication guard', () => {
    expect(passwordRouteRedirect(null, 'change-password')).toBeNull()
  })
})
