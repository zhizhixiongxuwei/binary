import { describe, expect, it } from 'vitest'

import { parseArchiveTaskGroup, parseTaskDetail, parseTaskPage } from '@/api/taskContract'

const archive = {
  import_id: 'import-1', upload_id: 'upload-1', status: 'ready', source_retained: false,
  child_count: 2, completed_count: 1, active_count: 1, failed_count: 0,
}
const task = {
  id: '11111111-1111-4111-8111-111111111111', name: 'bundle.zip', input_type: 'zip',
  status: 'SUCCEEDED', risk_level: 'UNKNOWN', progress: 100, progress_indeterminate: false,
  creator_id: '22222222-2222-4222-8222-222222222222', creator_name: 'operator', tags: [],
  created_at: '2026-08-27T01:00:00Z', updated_at: '2026-08-27T01:01:00Z',
  original_filename: 'bundle.zip', size_bytes: 1024, sha256: 'a'.repeat(64),
  sample_expires_at: '2026-09-27T01:00:00Z', sample_deleted_at: null,
}

describe('task grouping contract', () => {
  it('accepts optional parent summaries and child paths without requiring them on historical tasks', () => {
    expect(parseTaskDetail(task).archive).toBeUndefined()
    expect(parseTaskPage({ items: [{ ...task, analysis_mode: 'archive', archive }] }).items[0]?.archive).toEqual(archive)
    expect(parseTaskDetail({ ...task, analysis_mode: 'binary', archive_path: 'bin/tool' }).archive_path).toBe('bin/tool')
    expect(parseTaskDetail({ ...task, analysis_mode: 'archive' }).archive).toBeUndefined()
    expect(parseTaskDetail({ ...task, execution_status: 'UPLOADED' }).execution_status).toBe('UPLOADED')
    expect(parseTaskDetail({ ...task, execution_status: 'DECOMPILED' }).execution_status).toBe('DECOMPILED')
    expect(parseTaskDetail({ ...task, execution_status: 'SCAN_COMPLETED' }).execution_status).toBe('SCAN_COMPLETED')
  })

  it('rejects malformed group counts, unknown states and extra fields', () => {
    expect(() => parseArchiveTaskGroup({ ...archive, child_count: -1 })).toThrow('archive.child_count')
    expect(() => parseArchiveTaskGroup({ ...archive, active_count: 0.5 })).toThrow('archive.active_count')
    expect(() => parseArchiveTaskGroup({ ...archive, status: 'complete' })).toThrow('archive.status')
    expect(() => parseArchiveTaskGroup({ ...archive, parent_id: 'unexpected' })).toThrow('archive')
    expect(() => parseTaskDetail({ ...task, analysis_mode: 'other' })).toThrow('analysis_mode')
    expect(() => parseTaskDetail({ ...task, execution_status: 'complete' })).toThrow('execution_status')
  })
})
