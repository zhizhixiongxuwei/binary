import type { AuditLog, AuditLogListQuery, AuditLogPage, JsonValue } from '@/api/types'

export interface LiveAuditEntry {
  id: string | number
  actorId: string | null
  actorUsername: string | null
  action: string
  objectType: string | null
  objectId: string | null
  requestId: string | null
  clientIp?: string | null
  outcome: string
  details: JsonValue | null
  createdAt: string
}

export interface LiveAuditPage {
  entries: LiveAuditEntry[]
  nextBeforeId: string | number | null
}

export function buildAuditQuery(query: AuditLogListQuery = {}, paged = true): string {
  const params = new URLSearchParams()
  if (paged) {
    params.set('limit', String(query.page_size ?? 50))
    if (query.cursor) params.set('beforeId', query.cursor)
  }
  for (const key of ['action', 'outcome', 'actor', 'created_from', 'created_to'] as const) {
    if (query[key]) params.set(key, query[key]!)
  }
  return params.toString()
}

export function mapAuditPage(page: LiveAuditPage): AuditLogPage {
  return {
    items: page.entries.map((entry): AuditLog => {
      const outcome = entry.outcome === 'failed' ? 'failure' : entry.outcome
      if (!['success', 'failure', 'denied'].includes(outcome)) throw new Error('审计响应包含未知的操作结果')
      return {
        id: String(entry.id),
        actor: entry.actorId ? { id: entry.actorId, username: entry.actorUsername ?? '', display_name: entry.actorUsername ?? '' } : null,
        action: entry.action, outcome: outcome as AuditLog['outcome'],
        object_type: entry.objectType ?? '', object_id: entry.objectId,
        request_id: entry.requestId ?? '', client_ip: entry.clientIp ?? null,
        metadata: entry.details, created_at: entry.createdAt,
      }
    }),
    ...(page.nextBeforeId == null ? {} : { next_cursor: String(page.nextBeforeId) }),
  }
}

export function auditCsv(logs: readonly AuditLog[]): string {
  const cell = (value: unknown): string => {
    let result = String(value ?? '')
    if (/^[\s\u0000-\u001f]*[=+@-]/.test(result)) result = `'${result}`
    return `"${result.replace(/"/g, '""')}"`
  }
  const rows = [['时间 (UTC)', '事件ID', '操作者', '操作', '结果', '对象类型', '对象ID', '请求ID', '客户端IP'],
    ...logs.map((log) => [new Date(log.created_at).toISOString(), log.id, log.actor?.username ?? '系统', log.action, log.outcome,
      log.object_type, log.object_id, log.request_id, log.client_ip])]
  return '\ufeff' + rows.map((row) => row.map(cell).join(',')).join('\r\n') + '\r\n'
}
