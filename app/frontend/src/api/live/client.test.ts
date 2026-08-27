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
        input_type: 'elf64',
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
      input_type: 'elf64',
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
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/tasks?page_size=20',
      expect.objectContaining({ method: 'GET', credentials: 'include' }),
    )
  })
})
