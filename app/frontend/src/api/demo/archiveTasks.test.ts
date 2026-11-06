import { describe, expect, it } from 'vitest'

import { createDemoApiClient } from '@/api/demo/client'
import { DEMO_TASK_IDS } from '@/api/demo/fixtures'

describe('demo archive task groups', () => {
  it('pages root rows without duplicating children and resolves child searches to their parent', async () => {
    const client = createDemoApiClient({ delayMs: 0 })
    const roots = await client.listTasks({ page_size: 20 })
    const parent = roots.items.find((task) => task.archive)
    expect(parent?.archive).toMatchObject({ child_count: 2, completed_count: 0, active_count: 0, source_retained: false })
    expect(roots.items.some((task) => task.id === DEMO_TASK_IDS.firmware || task.id === DEMO_TASK_IDS.apk)).toBe(false)
    const children = await client.listTaskChildren(parent!.id, { page_size: 1 })
    expect(children.items).toHaveLength(1)
    expect(children.items[0]?.archive_path).toBeTruthy()
    expect(children.next_cursor).toBeTruthy()
    const nextChildren = await client.listTaskChildren(parent!.id, { page_size: 1, cursor: children.next_cursor! })
    expect(nextChildren.items[0]?.id).not.toBe(children.items[0]?.id)
    const search = await client.listTasks({ page_size: 20, keyword: 'bin/vulnerable-elf', input_type: 'elf64' })
    expect(search.items.map((task) => task.id)).toEqual([parent!.id])
    expect((await client.listTasks({
      page_size: 20, keyword: 'bin/vulnerable-elf', created_from: '2026-07-30', created_to: '2026-07-30',
    })).items.map((task) => task.id)).toEqual([parent!.id])
    expect((await client.listTasks({ page_size: 20, analysis_mode: 'archive' })).items.map((task) => task.id)).toContain(parent!.id)
  })

  it('filters actual execution milestones independently of historical input-ready status', async () => {
    const client = createDemoApiClient({ delayMs: 0 })
    const parent = (await client.listTasks({ page_size: 20 })).items.find((task) => task.archive)!
    const decompiled = await client.listTaskChildren(parent.id, { page_size: 20, execution_status: 'DECOMPILED' })
    expect(decompiled.items.map((task) => task.id)).toEqual([DEMO_TASK_IDS.apk])
    expect(decompiled.items[0]?.status).toBe('SUCCEEDED')
    expect((await client.listTasks({ page_size: 20, execution_status: 'DECOMPILED' })).items.map((task) => task.id)).toEqual([parent.id])
    expect((await client.listTaskChildren(parent.id, { page_size: 20, execution_status: 'SCAN_COMPLETED' })).items).toEqual([])
    expect((await client.listTasks({ page_size: 20, execution_status: 'SCAN_COMPLETED' })).items).toEqual([])
  })

  it('keeps child tasks and report history accessible after cleaning the outer source', async () => {
    const client = createDemoApiClient({ delayMs: 0 })
    const parent = (await client.listTasks({ page_size: 20 })).items.find((task) => task.archive)!
    await client.cleanupArchiveSource(parent.id)
    expect((await client.getTask(parent.id)).archive?.child_count).toBe(2)
    expect((await client.listTaskChildren(parent.id, { page_size: 20 })).items).toHaveLength(2)
    const imports = await client.listArchiveImports({ task_id: parent.id })
    expect(imports.items).toHaveLength(1)
    expect(imports.items[0]?.source_retained).toBe(false)
    expect((await client.listArchiveReportBundles(imports.items[0]!.id)).items).toHaveLength(1)
    expect((await client.listArchiveImports({ task_id: 'unrelated-task' })).items).toEqual([])
  })

  it('keeps newly created and unsupported archives visible before any child exists', async () => {
    const client = createDemoApiClient({ delayMs: 0 })
    const upload = await client.createUpload({ filename: 'new.zip', size: 0, content_type: 'application/zip' }, 'new-archive')
    await client.completeUpload(upload.id)
    const created = await client.createUploadAnalysisTask(upload.id, { analysis_mode: 'archive' }, 'new-mode')
    const parent = (await client.listTasks({ page_size: 20 })).items.find((task) => task.id === created.task_id)!
    expect(parent.archive?.child_count).toBe(0)
    expect((await client.listTaskChildren(parent.id, { page_size: 20 })).items).toEqual([])
    await client.createArchiveTaskBatch(parent.archive!.import_id, { entry_ids: ['1'] }, 'new-child')
    expect((await client.getTask(parent.id)).archive?.child_count).toBe(1)
    expect((await client.getTask(parent.id)).archive).toMatchObject({ completed_count: 0, active_count: 0 })
    expect((await client.listTaskChildren(parent.id, { page_size: 20 })).items[0]?.execution_status).toBe('UPLOADED')
    await client.cleanupArchiveSource(parent.id)
    expect((await client.getTask(parent.id)).archive?.source_retained).toBe(false)
    expect((await client.listTaskChildren(parent.id, { page_size: 20 })).items).toHaveLength(1)

    const unsupported = await client.createUpload({ filename: 'unknown.data', size: 0, content_type: 'application/octet-stream' }, 'unsupported')
    await client.completeUpload(unsupported.id)
    const mode = await client.createUploadAnalysisTask(unsupported.id, { analysis_mode: 'archive' }, 'unsupported-mode')
    expect(mode.archive_import_id).toBeUndefined()
    const unsupportedTask = await client.getTask(mode.task_id)
    expect(unsupportedTask.analysis_mode).toBe('archive')
    expect(unsupportedTask.archive).toBeUndefined()
    expect(unsupportedTask.error_code).toBe('analysis_mode_not_applicable')
    expect(unsupportedTask.execution_status).toBe('UNSUPPORTED')
    expect((await client.listTasks({ page_size: 20 })).items.some((task) => task.id === mode.task_id)).toBe(true)
  })

  it('hides an empty cleaned archive while preserving groups retained by children or report bundles', async () => {
    const client = createDemoApiClient({ delayMs: 0 })
    const upload = await client.createUpload({ filename: 'empty.zip', size: 0, content_type: 'application/zip' }, 'empty-archive')
    await client.completeUpload(upload.id)
    const created = await client.createUploadAnalysisTask(upload.id, { analysis_mode: 'archive' }, 'empty-mode')
    const importId = created.archive_import_id!
    expect((await client.listTasks({ page_size: 20 })).items.some((task) => task.id === created.task_id)).toBe(true)
    await client.cleanupArchiveSource(created.task_id)
    expect((await client.listTasks({ page_size: 20 })).items.some((task) => task.id === created.task_id)).toBe(false)
    expect((await client.listArchiveImports({ task_id: created.task_id })).items).toEqual([])
    await expect(client.getArchiveImport(importId)).rejects.toMatchObject({ status: 404 })
    await expect(client.listArchiveImportEntries(importId)).rejects.toMatchObject({ status: 404 })
    await expect(client.listTaskChildren(created.task_id, { page_size: 20 })).rejects.toMatchObject({ status: 404 })

    const parent = (await client.listTasks({ page_size: 20 })).items.find((task) => task.archive)!
    await client.cleanupArchiveSource(parent.id)
    expect((await client.listTasks({ page_size: 20 })).items.find((task) => task.id === parent.id)?.archive?.child_count).toBe(2)
    for (const child of (await client.listTaskChildren(parent.id, { page_size: 20 })).items) {
      await client.deleteTask(child.id)
    }
    const retained = (await client.listTasks({ page_size: 20 })).items.find((task) => task.id === parent.id)
    expect(retained?.archive?.child_count).toBe(0)
    expect((await client.listTaskChildren(parent.id, { page_size: 20 })).items).toEqual([])
    expect((await client.listArchiveImports({ task_id: parent.id })).items).toHaveLength(1)
    expect((await client.listArchiveReportBundles(retained!.archive!.import_id)).items).toHaveLength(1)
  })
})
