import { effectScope } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { AuditLog, AuditLogPage, ReportDownload } from '@/api/types'

const requests = vi.hoisted(() => ({ list: vi.fn(), export: vi.fn() }))
vi.mock('@/api/client', () => ({
  api: { listAuditLogs: requests.list, exportAuditLogs: requests.export },
  ApiError: class ApiError extends Error {},
}))

import { useAuditLogs } from './useAuditLogs'

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: Error) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

const scopes: ReturnType<typeof effectScope>[] = []
const first = { id: '1', action: 'task.create' } as AuditLog
const second = { id: '2', action: 'task.delete' } as AuditLog
const click = vi.fn()

function model() {
  const scope = effectScope()
  scopes.push(scope)
  return { scope, audit: scope.run(useAuditLogs)! }
}

beforeEach(() => {
  vi.stubGlobal('window', { location: { origin: 'https://binary.test' } })
  vi.stubGlobal('document', {
    createElement: () => ({ href: '', download: '', rel: '', click, remove: vi.fn() }),
    body: { append: vi.fn() },
  })
  vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:audit-download')
  vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
})

afterEach(() => {
  scopes.splice(0).forEach((scope) => scope.stop())
  vi.useRealTimers()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  vi.clearAllMocks()
})

describe('audit query and download lifecycle', () => {
  it('preserves a failed page cursor and loaded rows so the same page can be retried', async () => {
    const { audit } = model()
    requests.list.mockResolvedValueOnce({ items: [first], next_cursor: 'older' })
    await audit.load({ action: 'task.create', cursor: 'unrelated', page_size: 1 })
    expect(requests.list).toHaveBeenLastCalledWith({ action: 'task.create', page_size: 50 })
    requests.list.mockRejectedValueOnce(new Error('connection lost'))
    await audit.load(audit.query.value, { append: true })
    expect(audit.logs.value).toEqual([first])
    expect(audit.nextCursor.value).toBe('older')
    expect(audit.loadMoreError.value).toBeTruthy()
    expect(audit.errorMessage.value).toBe('')

    requests.list.mockResolvedValueOnce({ items: [second] })
    await audit.load(audit.query.value, { append: true })
    expect(requests.list).toHaveBeenLastCalledWith({ action: 'task.create', cursor: 'older', page_size: 50 })
    expect(audit.logs.value).toEqual([first, second])
    expect(audit.loadMoreError.value).toBe('')
    expect(audit.nextCursor.value).toBeUndefined()
  })

  it('ignores late query responses and never uses the previous query cursor during a new search', async () => {
    const { audit } = model()
    requests.list.mockResolvedValueOnce({ items: [first], next_cursor: 'old-cursor' })
    await audit.load({ actor: 'old' })
    const oldResponse = deferred<AuditLogPage>()
    requests.list.mockReturnValueOnce(oldResponse.promise)
    const oldRequest = audit.load({ actor: 'old' })
    const newResponse = deferred<AuditLogPage>()
    requests.list.mockReturnValueOnce(newResponse.promise)
    const newRequest = audit.load({ actor: 'new' })
    await audit.load(audit.query.value, { append: true })
    expect(requests.list).toHaveBeenCalledTimes(3)
    expect(audit.nextCursor.value).toBeUndefined()

    newResponse.resolve({ items: [second], next_cursor: 'new-cursor' })
    await newRequest
    oldResponse.resolve({ items: [first], next_cursor: 'stale-cursor' })
    await oldRequest
    expect(audit.logs.value).toEqual([second])
    expect(audit.nextCursor.value).toBe('new-cursor')
    expect(audit.query.value).toEqual({ actor: 'new' })
    expect(audit.loading.value).toBe(false)
  })

  it('does not publish list responses or send another request after disposal', async () => {
    const { audit, scope } = model()
    const response = deferred<AuditLogPage>()
    requests.list.mockReturnValueOnce(response.promise)
    const request = audit.load()
    scope.stop()
    response.resolve({ items: [first], next_cursor: 'older' })
    await request
    expect(audit.logs.value).toEqual([])
    expect(audit.nextCursor.value).toBeUndefined()
    await audit.load()
    expect(requests.list).toHaveBeenCalledTimes(1)
  })

  it('exports all filled filters without page size or cursor and prevents duplicate downloads while pending', async () => {
    vi.useFakeTimers()
    const { audit } = model()
    const response = deferred<ReportDownload>()
    requests.export.mockReturnValueOnce(response.promise)
    const filters = { action: 'task.create', outcome: 'failure', actor: 'operator',
      created_from: '2026-11-01T00:00:00Z', created_to: '2026-11-02T23:59:59Z' }
    const request = audit.exportLogs({ ...filters, page_size: 1, cursor: 'current-page' })
    expect(audit.exporting.value).toBe(true)
    await audit.exportLogs(filters)
    expect(requests.export).toHaveBeenCalledOnce()
    expect(requests.export).toHaveBeenCalledWith(filters)
    response.resolve({ kind: 'blob', blob: new Blob(['csv']), filename: 'matching-audit.csv' })
    await request
    expect(click).toHaveBeenCalledOnce()
    expect(audit.exporting.value).toBe(false)
    expect(audit.exportFeedback.value).toContain('全部匹配记录')
    expect(audit.exportError.value).toBe('')
  })

  it('clears earlier success feedback when an export fails and rejects external download targets', async () => {
    const { audit } = model()
    requests.export.mockResolvedValueOnce({ kind: 'url', url: '/api/v1/admin/audit/export' })
    await audit.exportLogs()
    expect(audit.exportFeedback.value).toBeTruthy()
    requests.export.mockResolvedValueOnce({ kind: 'url', url: 'https://external.test/audit.csv' })
    await audit.exportLogs()
    expect(audit.exportFeedback.value).toBe('')
    expect(audit.exportError.value).toBeTruthy()
    expect(click).toHaveBeenCalledOnce()
    requests.export.mockRejectedValueOnce(new Error('export unavailable'))
    await audit.exportLogs()
    expect(audit.exportFeedback.value).toBe('')
    expect(audit.exportError.value).toContain('export unavailable')
    expect(audit.exporting.value).toBe(false)
  })

  it('does not start a download when its export response arrives after disposal', async () => {
    const { audit, scope } = model()
    const response = deferred<ReportDownload>()
    requests.export.mockReturnValueOnce(response.promise)
    const request = audit.exportLogs()
    scope.stop()
    response.resolve({ kind: 'blob', blob: new Blob(['csv']), filename: 'audit.csv' })
    await request
    expect(URL.createObjectURL).not.toHaveBeenCalled()
    expect(click).not.toHaveBeenCalled()
    expect(audit.exportFeedback.value).toBe('')
  })
})
