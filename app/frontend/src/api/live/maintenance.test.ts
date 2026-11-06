import { afterEach, describe, expect, it, vi } from 'vitest'
import { createLiveApiClient } from '@/api/live/client'
import { createDemoApiClient } from '@/api/demo/client'

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
const entry = {
  id: 7, actorId: 'operator-id', actorUsername: 'operator', action: 'task.create',
  objectType: 'task', objectId: 'task-id', requestId: 'request-id', clientIp: '127.0.0.1',
  outcome: 'failed', details: null, createdAt: '2026-11-03T01:00:00Z',
}

afterEach(() => vi.unstubAllGlobals())

describe('real system maintenance transport', () => {
  it('reads the real probe endpoint and preserves missing or stale reports', async () => {
    const result = {
      version: 'app-version', service_status: 'degraded', active_tasks: 3, queued_tasks: 2,
      repository_used_bytes: null, repository_total_bytes: null,
      analyzers: [{ name: 'scanner', status: 'unknown', freshness: 'stale', version: '0.74.0', ready_workers: 0 }],
      trivy_database_bundle: null,
    }
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(json(result))
    vi.stubGlobal('fetch', fetchMock)
    expect(await createLiveApiClient().getSystemStatus()).toEqual(result)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/admin/system', expect.objectContaining({ credentials: 'include' }))
  })

  it('passes every audit filter to the backend before pagination and preserves failure', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(json({ entries: [entry], nextBeforeId: '6' }))
    vi.stubGlobal('fetch', fetchMock)
    const query = { action: 'task.create', outcome: 'failure', actor: 'operator', created_from: '2026-11-01T00:00:00Z', created_to: '2026-11-03T23:59:59Z', page_size: 1, cursor: '8' }
    const result = await createLiveApiClient().listAuditLogs(query)
    const url = new URL(String(fetchMock.mock.calls[0]?.[0]), 'http://localhost')
    expect(Object.fromEntries(url.searchParams)).toEqual({ action: query.action, outcome: query.outcome, actor: query.actor, created_from: query.created_from, created_to: query.created_to, limit: '1', beforeId: '8' })
    expect(result).toMatchObject({ items: [{ outcome: 'failure', client_ip: '127.0.0.1' }], next_cursor: '6' })
  })

  it('does not silently label an unrecognized audit result as success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ entries: [{ ...entry, outcome: 'invalid' }], nextBeforeId: null })))
    await expect(createLiveApiClient().listAuditLogs()).rejects.toThrow('未知的操作结果')
  })

  it('downloads all matching audit records independently of list pagination', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(new Response('\ufeff时间,结果\r\n2026-11-03,failure\r\n', {
      headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="audit-logs-20261103.csv"' },
    }))
    vi.stubGlobal('fetch', fetchMock)
    const result = await createLiveApiClient().exportAuditLogs({ actor: 'operator', cursor: '8', page_size: 1 })
    const url = new URL(String(fetchMock.mock.calls[0]?.[0]), 'http://localhost')
    expect(url.pathname).toBe('/api/v1/admin/audit/export')
    expect(Object.fromEntries(url.searchParams)).toEqual({ actor: 'operator' })
    expect(result).toMatchObject({ kind: 'blob', filename: 'audit-logs-20261103.csv' })
    if (result.kind === 'blob') expect(await result.blob.text()).toContain('failure')
  })

  it('reports an oversized export as an error instead of downloading a truncated result', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ error: 'audit_export_too_large' }, 413)))
    await expect(createLiveApiClient().exportAuditLogs()).rejects.toMatchObject({ status: 413, code: 'audit_export_too_large', message: expect.stringContaining('缩小时间范围') })
  })

  it('exports demo events without applying the current list cursor or page size', async () => {
    const client = createDemoApiClient({ delayMs: 0 })
    const page = await client.listAuditLogs({ page_size: 500 })
    const exported = await client.exportAuditLogs({ cursor: 'demo-offset-1', page_size: 1 })
    expect(exported.kind).toBe('blob')
    if (exported.kind === 'blob') {
      const csv = await exported.blob.text()
      for (const item of page.items) expect(csv).toContain(item.action)
    }
  })
})
