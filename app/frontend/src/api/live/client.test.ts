import { afterEach, describe, expect, it, vi } from 'vitest'

import { buildLiveTaskListQuery, createLiveApiClient } from '@/api/live/client'

const taskId = '11111111-1111-4111-8111-111111111111'
const creatorId = '22222222-2222-4222-8222-222222222222'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('live task pagination adapter', () => {
  it('serializes the cursor and every server-side task filter', () => {
    const query = new URLSearchParams(
      buildLiveTaskListQuery({
        page_size: 20,
        cursor: taskId,
        keyword: 'vulnerable',
        status: 'SUCCEEDED',
        execution_status: 'DECOMPILED',
        input_type: 'elf64',
        analysis_mode: 'archive',
        creator: 'admin',
        tag: 'ELF64',
        created_from: '2026-08-01',
        created_to: '2026-08-27',
      }),
    )

    expect(Object.fromEntries(query)).toEqual({
      page_size: '20',
      cursor: taskId,
      keyword: 'vulnerable',
      status: 'SUCCEEDED',
      execution_status: 'DECOMPILED',
      input_type: 'elf64',
      analysis_mode: 'archive',
      creator: 'admin',
      tag: 'ELF64',
      created_from: '2026-08-01',
      created_to: '2026-08-27',
    })
  })

  it('preserves next_cursor and maps the real task creator', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          tasks: [
            {
              id: taskId,
              displayName: 'vulnerable-elf',
              status: 'ready',
              creatorId,
              creatorName: 'operator',
              inputSha256: 'a'.repeat(64),
              detectedFormat: 'elf64',
              analysisMode: 'binary',
              createdAt: '2026-08-27T01:00:00Z',
              updatedAt: '2026-08-27T01:01:00Z',
            },
          ],
          next_cursor: taskId,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    vi.stubGlobal('fetch', fetchMock)

    const page = await createLiveApiClient().listTasks({ page_size: 20 })

    expect(page.next_cursor).toBe(taskId)
    expect(page.items).toHaveLength(1)
    expect(page.items[0]?.creator_id).toBe(creatorId)
    expect(page.items[0]?.creator_name).toBe('operator')
    expect(page.items[0]).toMatchObject({ execution_status: 'UPLOADED', progress: 0, progress_indeterminate: false })
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/tasks?page_size=20',
      expect.objectContaining({ method: 'GET', credentials: 'include' }),
    )
  })

  it('keeps input readiness separate from actual analyzer milestones in lists and details', async () => {
    const rawTask = {
      id: taskId, displayName: 'member.elf', status: 'ready', analysisMode: 'binary',
      createdAt: '2026-08-27T01:00:00Z', updatedAt: '2026-08-27T01:01:00Z',
    }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ tasks: [
        { ...rawTask, execution_status: 'UPLOADED' },
        { ...rawTask, id: 'decompiled', execution_status: 'DECOMPILED' },
        { ...rawTask, id: 'checked', execution_status: 'SCAN_COMPLETED' },
        { ...rawTask, id: 'checking', execution_status: 'SCANNING' },
        { ...rawTask, id: 'failed', execution_status: 'SCAN_FAILED' },
      ] })))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        task: { ...rawTask, execution_status: 'DECOMPILED' }, files: [], runs: [], projects: [],
      })))
    vi.stubGlobal('fetch', fetchMock)
    const client = createLiveApiClient()
    const page = await client.listTasks({ page_size: 20 })
    expect(page.items.map((task) => task.execution_status)).toEqual([
      'UPLOADED', 'DECOMPILED', 'SCAN_COMPLETED', 'SCANNING', 'SCAN_FAILED',
    ])
    expect(page.items.every((task) => task.status === 'SUCCEEDED')).toBe(true)
    expect(page.items[0]).toMatchObject({ progress: 0, progress_indeterminate: false })
    expect(page.items[3]).toMatchObject({ progress: 0, progress_indeterminate: true })
    expect(page.items[4]).toMatchObject({ progress: 0, progress_indeterminate: false })
    expect(await client.getTask(taskId)).toMatchObject({ execution_status: 'DECOMPILED', current_stage: 'DECOMPILED' })
  })

  it('maps archive parents and loads children without losing their source paths', async () => {
    const archive = {
      import_id: 'import-1', upload_id: 'upload-1', status: 'ready', source_retained: false,
      child_count: 2, completed_count: 1, active_count: 1, failed_count: 0,
    }
    const rawTask = {
      id: taskId, displayName: 'bundle.zip', status: 'ready', analysisMode: 'archive',
      createdAt: '2026-08-27T01:00:00Z', updatedAt: '2026-08-27T01:01:00Z', archive,
    }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ tasks: [rawTask] })))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        tasks: [{ ...rawTask, archive: undefined, analysisMode: 'binary', archive_path: 'bin/tool', execution_status: 'DECOMPILED' }],
        next_cursor: taskId,
      })))
    vi.stubGlobal('fetch', fetchMock)
    const client = createLiveApiClient()
    expect((await client.listTasks({ page_size: 20 })).items[0]?.archive).toEqual(archive)
    const children = await client.listTaskChildren(taskId, { page_size: 10, execution_status: 'DECOMPILED' })
    expect(children.items[0]?.archive_path).toBe('bin/tool')
    expect(children.items[0]?.archive).toBeUndefined()
    expect(children.items[0]?.execution_status).toBe('DECOMPILED')
    expect(children.next_cursor).toBe(taskId)
    expect(fetchMock).toHaveBeenLastCalledWith(
      `/api/v1/tasks/${taskId}/children?page_size=10&execution_status=DECOMPILED`,
      expect.objectContaining({ method: 'GET' }),
    )
  })

  it('queries import history for one parent and cleans only its outer archive', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ items: [] })))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)
    const client = createLiveApiClient()
    await client.listArchiveImports({ task_id: taskId, page_size: 10 })
    await client.cleanupArchiveSource(taskId)
    expect(fetchMock).toHaveBeenNthCalledWith(1,
      `/api/v1/archive-imports?task_id=${taskId}&page_size=10`, expect.anything(),
    )
    expect(fetchMock).toHaveBeenLastCalledWith(`/api/v1/tasks/${taskId}/archive-source`,
      expect.objectContaining({ method: 'DELETE' }),
    )
  })
})
