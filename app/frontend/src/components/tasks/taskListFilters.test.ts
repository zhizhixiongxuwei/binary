import { describe, expect, it } from 'vitest'

import { parseTaskListRouteQuery, serializeTaskListRouteQuery } from './taskListFilters'

describe('task list archive navigation state', () => {
  it('preserves real execution milestone filters instead of conflating them with file readiness', () => {
    for (const status of ['UPLOADED', 'DECOMPILED', 'SCAN_COMPLETED', 'SCAN_PARTIAL', 'DECOMPILE_FAILED']) {
      const state = parseTaskListRouteQuery({ status })
      expect(state.status).toBe(status)
      expect(serializeTaskListRouteQuery(state).status).toBe(status)
    }
  })
  it('preserves the analysis mode and expanded batch when restoring a task list URL', () => {
    const state = parseTaskListRouteQuery({
      keyword: 'archive-parent', analysis_mode: 'archive', expanded: 'archive-parent',
      page_size: '10', cursor: 'next_cursor',
    })
    expect(state.analysis_mode).toBe('archive')
    expect(state.expanded).toBe('archive-parent')
    expect(serializeTaskListRouteQuery(state)).toEqual({
      keyword: 'archive-parent', analysis_mode: 'archive', expanded: 'archive-parent',
      page_size: '10', cursor: 'next_cursor',
    })
  })

  it('rejects unknown modes, malformed IDs and ambiguous query arrays', () => {
    expect(parseTaskListRouteQuery({ analysis_mode: 'unsupported', expanded: '../task' })).toMatchObject({ analysis_mode: '', expanded: '' })
    expect(parseTaskListRouteQuery({ analysis_mode: ['archive', 'binary'], expanded: ['one', 'two'] })).toMatchObject({ analysis_mode: '', expanded: '' })
  })
})
