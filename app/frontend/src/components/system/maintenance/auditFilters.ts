import type { AuditLogListQuery } from '@/api/types'

export interface AuditFilterValues {
  action: string
  outcome: string
  actor: string
  createdFrom: string
  createdTo: string
}

function localMinute(value: string, endOfMinute = false): string | undefined {
  if (!value) return undefined
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) return undefined
  const parts = value.split(/[-T:]/).map(Number)
  const date = new Date(`${value}:00.000`)
  // Date normalizes impossible calendar dates; reject those instead of silently
  // changing the operator's requested range.
  if (Number.isNaN(date.getTime()) || date.getFullYear() !== parts[0]
    || date.getMonth() + 1 !== parts[1] || date.getDate() !== parts[2]
    || date.getHours() !== parts[3] || date.getMinutes() !== parts[4]) return undefined
  if (endOfMinute) date.setSeconds(59, 999)
  return date.toISOString()
}

export function auditFilterQuery(filters: AuditFilterValues): AuditLogListQuery {
  const createdFrom = localMinute(filters.createdFrom)
  const createdTo = localMinute(filters.createdTo, true)
  if ((filters.createdFrom && !createdFrom) || (filters.createdTo && !createdTo)) {
    throw new Error('请输入有效的起始和结束时间')
  }
  if (createdFrom && createdTo && createdFrom > createdTo) throw new Error('起始时间不能晚于结束时间')
  if (!['', 'success', 'failure', 'denied'].includes(filters.outcome)) throw new Error('请选择有效的操作结果')
  const action = filters.action.trim()
  const actor = filters.actor.trim()
  return {
    ...(action ? { action } : {}),
    ...(filters.outcome ? { outcome: filters.outcome } : {}),
    ...(actor ? { actor } : {}),
    ...(createdFrom ? { created_from: createdFrom } : {}),
    ...(createdTo ? { created_to: createdTo } : {}),
  }
}
