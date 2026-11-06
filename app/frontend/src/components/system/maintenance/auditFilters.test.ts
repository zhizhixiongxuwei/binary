import { describe, expect, it } from 'vitest'

import { auditFilterQuery } from './auditFilters'

const empty = { action: '', actor: '', outcome: '', createdFrom: '', createdTo: '' }

describe('audit filter date boundaries', () => {
  it('includes every instant of the entered final minute for both query and export', () => {
    const query = auditFilterQuery({ ...empty, action: ' task.delete ', actor: ' admin ', outcome: 'failure',
      createdFrom: '2026-11-03T08:00', createdTo: '2026-11-03T08:00' })
    expect(query.action).toBe('task.delete')
    expect(query.actor).toBe('admin')
    expect(query.outcome).toBe('failure')
    expect(Date.parse(query.created_to!) - Date.parse(query.created_from!)).toBe(59999)
  })

  it('rejects reversed ranges instead of silently changing the selected dates', () => {
    expect(() => auditFilterQuery({ ...empty,
      createdFrom: '2026-11-04T00:00', createdTo: '2026-11-03T23:59' })).toThrow('起始时间不能晚于结束时间')
  })

  it('rejects invalid calendar dates instead of Date normalizing them into another month', () => {
    expect(() => auditFilterQuery({ ...empty, createdFrom: '2026-02-30T09:00' })).toThrow('请输入有效')
    expect(() => auditFilterQuery({ ...empty, createdTo: 'not-a-date' })).toThrow('请输入有效')
    expect(auditFilterQuery({ ...empty, createdFrom: '2028-02-29T09:00' }).created_from).toBeTruthy()
  })
})
