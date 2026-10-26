import { afterEach, describe, expect, it, vi } from 'vitest'

import { httpApi } from '@/api/client'
import { createDemoApiClient } from '@/api/demo/client'
import { createLiveApiClient } from '@/api/live/client'

const input = { current_password: 'current-test-value', new_password: 'new-test-value' }
const liveUser = {
  id: 'test-user', username: 'test-user', role: 'operator',
  mustChangePassword: false, csrfToken: 'csrf-test-token',
}
const task = {
  id: 'test-task', displayName: 'fixture', status: 'ready',
  createdAt: '2026-10-26T01:00:00Z', updatedAt: '2026-10-26T01:00:00Z',
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status, headers: { 'Content-Type': 'application/json' },
  })
}

afterEach(() => vi.unstubAllGlobals())

describe('password change transport', () => {
  it.each([true, false])('preserves mustChangePassword=%s through login and session restore', async (mustChangePassword) => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(json({ user: { ...liveUser, mustChangePassword } }))
      .mockResolvedValueOnce(json({ user: { ...liveUser, mustChangePassword } }))
    vi.stubGlobal('fetch', fetchMock)
    const client = createLiveApiClient()

    await expect(client.login({ username: liveUser.username, password: 'test-value' }))
      .resolves.toMatchObject({ must_change_password: mustChangePassword })
    await expect(client.getMe()).resolves.toMatchObject({ must_change_password: mustChangePassword })
  })

  it('accepts 204 without a user body or a follow-up me request, then clears auth state', async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(json({ user: liveUser }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(json({ tasks: [task] }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)
    const client = createLiveApiClient()
    await client.getMe()

    await expect(client.changePassword(input)).resolves.toBeUndefined()

    expect(fetchMock).toHaveBeenCalledTimes(2)
    const [url, init] = fetchMock.mock.calls[1]!
    expect(url).toBe('/api/v1/auth/password')
    expect(init).toMatchObject({ method: 'POST', credentials: 'include' })
    expect(JSON.parse(String(init?.body))).toEqual({
      currentPassword: input.current_password, newPassword: input.new_password,
    })
    expect(new Headers(init?.headers).get('X-CSRF-Token')).toBe(liveUser.csrfToken)
    expect(new Headers(init?.headers).get('Content-Type')).toBe('application/json')

    const page = await client.listTasks({ page_size: 10 })
    expect(page.items[0]?.creator_id).toBe('')
    await client.deleteUpload('test-upload')
    expect(new Headers(fetchMock.mock.calls[3]?.[1]?.headers).has('X-CSRF-Token')).toBe(false)
  })

  it('keeps the user and CSRF token when the current password is rejected with 401', async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(json({ user: liveUser }))
      .mockResolvedValueOnce(json({ error: 'invalid_current_password' }, 401))
      .mockResolvedValueOnce(json({ tasks: [task] }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)
    const client = createLiveApiClient()
    await client.getMe()

    await expect(client.changePassword(input)).rejects.toMatchObject({
      status: 401, code: 'invalid_current_password',
    })
    const page = await client.listTasks({ page_size: 10 })
    expect(page.items[0]?.creator_id).toBe(liveUser.id)
    await client.deleteUpload('test-upload')
    expect(new Headers(fetchMock.mock.calls[3]?.[1]?.headers).get('X-CSRF-Token')).toBe(liveUser.csrfToken)
  })

  it.each([true, false])('invalidates report retry snapshots only after success (%s)', async (succeeds) => {
    let taskReads = 0
    const reportBodies: unknown[] = []
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (url, init) => {
      if (String(url).endsWith('/auth/me')) return json({ user: liveUser })
      if (String(url).endsWith('/auth/password')) {
        return succeeds
          ? new Response(null, { status: 204 })
          : json({ error: { code: 'invalid_credentials' } }, 401)
      }
      if (String(url).endsWith('/tasks/test-task')) {
        taskReads += 1
        return json({ runs: [{ id: `run-${taskReads}`, status: 'ready' }] })
      }
      reportBodies.push(JSON.parse(String(init?.body)))
      return json({ error: { code: 'temporary_failure' } }, 503)
    })
    vi.stubGlobal('fetch', fetchMock)
    const client = createLiveApiClient()
    await client.getMe()
    await expect(client.createTaskReport(task.id, { format: 'html' }, 'intent')).rejects.toMatchObject({ status: 503 })

    const changed = client.changePassword(input)
    if (succeeds) await expect(changed).resolves.toBeUndefined()
    else await expect(changed).rejects.toMatchObject({ status: 401 })

    await expect(client.createTaskReport(task.id, { format: 'html' }, 'intent')).rejects.toMatchObject({ status: 503 })
    expect(taskReads).toBe(succeeds ? 2 : 1)
    expect(reportBodies).toEqual([
      { format: 'html', runIds: ['run-1'] },
      { format: 'html', runIds: [succeeds ? 'run-2' : 'run-1'] },
    ])
  })

  it('does not fetch me after a successful legacy password change', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)
    await expect(httpApi.changePassword(input)).resolves.toBeUndefined()
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/me/password')
    expect(fetchMock.mock.calls[0]?.[1]?.method).toBe('PUT')
  })

  it('requires a new login after changing the demo password', async () => {
    const client = createDemoApiClient({ delayMs: 0 })
    await client.login({ username: 'demo-operator', password: 'test-value' })
    await expect(client.changePassword(input)).resolves.toBeUndefined()
    await expect(client.getMe()).rejects.toMatchObject({ status: 401 })
    await expect(client.login({ username: 'demo-operator', password: input.new_password })).resolves.toMatchObject({ role: 'operator' })
  })
})
