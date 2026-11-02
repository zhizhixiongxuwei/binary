import { describe, expect, it } from 'vitest'
import { summarizeOverview } from '@/api/overview'
import { DEMO_TASKS } from '@/api/demo/fixtures'
import type { ScanTask } from '@/api/types'

const now = new Date('2026-11-02T14:00:00Z')
function task(overrides: Partial<ScanTask> = {}): ScanTask {
  return { ...DEMO_TASKS[0]!, created_at: '2026-11-02T08:00:00Z', ...overrides }
}

describe('overview aggregation', () => {
  it('counts the full collection and separates current snapshots from the creation window', () => {
    const tasks = Array.from({ length: 125 }, (_, index) => task({ id: String(index), status: 'SUCCEEDED' }))
    tasks.push(task({ status: 'SCANNING', created_at: '2025-01-01T00:00:00Z' }))
    tasks.push(task({ status: 'QUEUED', created_at: '2025-01-01T00:00:00Z' }))
    const result = summarizeOverview(tasks, 7, now)
    expect(result.total).toBe(125)
    expect(result.active).toBe(1)
    expect(result.queued).toBe(1)
    expect(result.trend.reduce((sum, day) => sum + day.created, 0)).toBe(result.total)
    expect(result.statuses.reduce((sum, status) => sum + status.count, 0)).toBe(result.total)
    expect(result.formats.reduce((sum, format) => sum + format.count, 0)).toBe(result.total)
  })

  it('uses UTC calendar boundaries, zero-fills days, and excludes archive and deleted tasks', () => {
    const result = summarizeOverview([
      task({ created_at: '2026-10-26T23:59:59Z' }),
      task({ created_at: '2026-10-27T00:00:00Z' }),
      task({ created_at: '2026-11-03T00:00:00+08:00' }),
      task({ analysis_mode: 'archive' }), task({ status: 'DELETED' }),
    ], 7, now)
    expect(result.created_from).toBe('2026-10-27')
    expect(result.total).toBe(1)
    expect(result.trend).toHaveLength(7)
    expect(result.trend[0]?.created).toBe(1)
    expect(result.trend[1]?.created).toBe(0)
    expect(summarizeOverview([], 30, now).created_from).toBe('2026-10-04')
  })

  it('keeps unknown format and limits failure previews without truncating failure counts', () => {
    const result = summarizeOverview(Array.from({ length: 6 }, (_, index) => task({
      id: String(index), status: 'FAILED', input_type: '', created_at: `2026-11-02T0${index}:00:00Z`,
    })), 7, now)
    expect(result.failed).toBe(6)
    expect(result.failures.map((item) => item.id)).toEqual(['5', '4', '3'])
    expect(result.formats).toEqual([{ value: 'unknown', count: 6 }])
    expect(result.trend[result.trend.length - 1]?.failed).toBe(6)
    expect(summarizeOverview([], 7, now).statuses).toEqual([])
  })
})
