import { effectScope } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type { ArchiveImport } from '@/api/types'
import { useArchiveImport } from './useArchiveImport'

vi.mock('@/api/client', async (importOriginal) => {
  const original = await importOriginal<typeof import('@/api/client')>()
  return {
    ...original,
    api: {
      getArchiveImport: vi.fn(),
      listArchiveImportEntries: vi.fn(),
      cleanupArchiveSource: vi.fn(),
      deleteUpload: vi.fn(),
      createArchiveTaskBatch: vi.fn(),
    },
  }
})

const retained: ArchiveImport = {
  id: 'import-1', upload_id: 'upload-1', filename: 'release.zip', status: 'ready',
  source_retained: true, scanned_entries: 2, total_entries: 2, eligible_entries: 2,
  skipped_entries: 0, created_tasks: 1, report_ready_tasks: 1, ready_reports: 1,
  created_at: '2026-11-03T00:00:00Z', updated_at: '2026-11-03T00:00:00Z',
}
const scopes: ReturnType<typeof effectScope>[] = []

async function workspace(value: ArchiveImport) {
  vi.mocked(api.getArchiveImport).mockResolvedValue(value)
  vi.mocked(api.listArchiveImportEntries).mockResolvedValue({ items: [] })
  const scope = effectScope()
  scopes.push(scope)
  const model = scope.run(() => useArchiveImport({
    importId: retained.id, uploadId: retained.upload_id, taskId: 'parent-task',
    applyInitialSelection: false,
  }))!
  await model.refreshImport()
  return model
}

afterEach(() => {
  scopes.splice(0).forEach((scope) => scope.stop())
  vi.resetAllMocks()
})

describe('archive source cleanup in the unified task list', () => {
  it('refreshes a retained group after cleanup without treating its children as deleted', async () => {
    const model = await workspace(retained)
    vi.mocked(api.cleanupArchiveSource).mockResolvedValue(undefined)
    vi.mocked(api.getArchiveImport).mockResolvedValue({ ...retained, source_retained: false })

    await model.deleteUpload()

    expect(api.cleanupArchiveSource).toHaveBeenCalledWith('parent-task')
    expect(api.deleteUpload).not.toHaveBeenCalled()
    expect(model.deleted.value).toBe(false)
    expect(model.archiveImport.value?.created_tasks).toBe(1)
    expect(model.archiveImport.value?.source_retained).toBe(false)
    expect(model.canDelete.value).toBe(false)
    expect(model.isReady.value).toBe(false)
  })

  it('removes an empty group when cleanup leaves no retained import', async () => {
    const model = await workspace({ ...retained, created_tasks: 0, report_ready_tasks: 0, ready_reports: 0 })
    vi.mocked(api.cleanupArchiveSource).mockResolvedValue(undefined)
    vi.mocked(api.getArchiveImport).mockRejectedValue(new ApiError('归档导入不存在', 404))

    await model.deleteUpload()

    expect(model.deleted.value).toBe(true)
    expect(model.entries.value).toEqual([])
  })

  it('prevents creating more tasks once the source has been cleaned', async () => {
    const model = await workspace({ ...retained, source_retained: false })

    await model.createTasks()
    await model.deleteUpload()

    expect(model.isReady.value).toBe(false)
    expect(api.createArchiveTaskBatch).not.toHaveBeenCalled()
    expect(api.cleanupArchiveSource).not.toHaveBeenCalled()
  })
})
