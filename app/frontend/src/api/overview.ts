import type { OverviewSummary, ScanTask, TaskStatus } from '@/api/types'

export const overviewStatuses: Record<string, { label: string; color: string; filter?: TaskStatus }> = {
  SUCCEEDED: { label: '已完成', color: 'var(--success)', filter: 'SUCCEEDED' },
  PARTIAL_SUCCEEDED: { label: '部分完成', color: 'var(--warning)', filter: 'PARTIAL_SUCCEEDED' },
  SCANNING: { label: '处理中', color: 'var(--primary)', filter: 'SCANNING' },
  QUEUED: { label: '排队中', color: '#8b5cf6', filter: 'QUEUED' },
  FAILED: { label: '失败', color: 'var(--danger)', filter: 'FAILED' },
  DELETING: { label: '正在删除', color: 'var(--ink-400)', filter: 'DELETING' },
  CANCELLED: { label: '已取消', color: 'var(--ink-500)', filter: 'CANCELLED' },
}

export function normalizeOverviewStatus(value: string): string {
  const status = value.toUpperCase()
  return ({ READY: 'SUCCEEDED', PARTIAL: 'PARTIAL_SUCCEEDED', RUNNING: 'SCANNING' } as Record<string, string>)[status] ?? status
}

/** Demo uses the entire fixture collection, never a paginated list. */
export function summarizeOverview(tasks: readonly ScanTask[], days: 7 | 30, now = new Date()): OverviewSummary {
  const today = now.toISOString().slice(0, 10)
  const start = new Date(`${today}T00:00:00Z`)
  start.setUTCDate(start.getUTCDate() - days + 1)
  const createdFrom = start.toISOString().slice(0, 10)
  const visible = tasks.filter((task) => task.analysis_mode !== 'archive' && !['DELETED'].includes(task.status.toUpperCase()))
  const period = visible.filter((task) => Date.parse(task.created_at) >= start.getTime() && Date.parse(task.created_at) <= now.getTime())
  const statuses = new Map<string, number>()
  const formats = new Map<string, number>()
  const trend = Array.from({ length: days }, (_, index) => {
    const date = new Date(start)
    date.setUTCDate(date.getUTCDate() + index)
    return { date: date.toISOString().slice(0, 10), created: 0, failed: 0 }
  })
  for (const task of period) {
    const status = normalizeOverviewStatus(task.status)
    const format = task.input_type?.toLowerCase() || 'unknown'
    statuses.set(status, (statuses.get(status) ?? 0) + 1)
    formats.set(format, (formats.get(format) ?? 0) + 1)
    const day = trend.find((item) => item.date === new Date(task.created_at).toISOString().slice(0, 10))!
    day.created++
    if (status === 'FAILED') day.failed++
  }
  return {
    created_from: createdFrom, created_to: today, collected_at: now.toISOString(),
    total: period.length,
    active: visible.filter((task) => ['SCANNING', 'RUNNING', 'VALIDATING', 'IDENTIFYING', 'EXTRACTING', 'INDEXING', 'REPORTING', 'CANCEL_REQUESTED'].includes(task.status.toUpperCase())).length,
    queued: visible.filter((task) => task.status.toUpperCase() === 'QUEUED').length,
    failed: period.filter((task) => task.status.toUpperCase() === 'FAILED').length,
    statuses: [...statuses].map(([value, count]) => ({ value, count })),
    formats: [...formats].map(([value, count]) => ({ value, count })), trend,
    failures: period.filter((task) => task.status.toUpperCase() === 'FAILED')
      .sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, 3)
      .map((task) => ({ id: task.id, name: task.name, created_at: task.created_at })),
  }
}
