import { effectScope, shallowRef } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { ScanTask } from '@/api/types'

const listChildren = vi.hoisted(() => vi.fn())
vi.mock('@/api/client', () => ({
  api: { listTaskChildren: listChildren },
  ApiError: class ApiError extends Error {},
}))

import { useArchiveTaskChildren } from './useArchiveTaskChildren'

const parent = { id: 'parent', name: 'release.zip', input_type: 'zip' } as ScanTask
const child = { id: 'child', status: 'SUCCEEDED' } as ScanTask
const scopes: ReturnType<typeof effectScope>[] = []

afterEach(() => {
  scopes.splice(0).forEach((scope) => scope.stop())
  vi.useRealTimers()
  vi.clearAllMocks()
})

describe('archive child pagination', () => {
  it('keeps the displayed page and cursor when the next request fails', async () => {
    listChildren.mockResolvedValueOnce({ items: [child], next_cursor: 'next' })
    const scope = effectScope()
    scopes.push(scope)
    const model = scope.run(() => useArchiveTaskChildren(() => parent, () => ({ page_size: 20 })))!
    await vi.waitFor(() => expect(model.loading.value).toBe(false))
    listChildren.mockRejectedValueOnce(new Error('connection lost'))
    await model.nextPage()
    expect(model.pageIndex.value).toBe(0)
    expect(model.items.value).toEqual([child])
    expect(model.nextCursor.value).toBe('next')
    expect(model.error.value).toBeTruthy()
    listChildren.mockResolvedValueOnce({ items: [], next_cursor: '' })
    await model.nextPage()
    expect(listChildren).toHaveBeenLastCalledWith('parent', { page_size: 10, cursor: 'next' })
    expect(model.pageIndex.value).toBe(1)
  })

  it('automatically updates running children and stops polling when they finish', async () => {
    vi.useFakeTimers()
    listChildren.mockResolvedValueOnce({ items: [{ ...child, status: 'SCANNING' }] })
    const scope = effectScope()
    scopes.push(scope)
    const model = scope.run(() => useArchiveTaskChildren(() => parent, () => ({ page_size: 20 })))!
    await vi.advanceTimersByTimeAsync(0)
    listChildren.mockResolvedValueOnce({ items: [child] })

    await vi.advanceTimersByTimeAsync(5000)
    expect(model.items.value).toEqual([child])
    expect(listChildren).toHaveBeenCalledTimes(2)
    await vi.advanceTimersByTimeAsync(10000)
    expect(listChildren).toHaveBeenCalledTimes(2)
  })

  it('refreshes the current page when the parent summary changes', async () => {
    const current = shallowRef({ ...parent, archive: { child_count: 11, active_count: 0 } } as ScanTask)
    listChildren.mockResolvedValueOnce({ items: [child], next_cursor: 'next' })
    const scope = effectScope()
    scopes.push(scope)
    const model = scope.run(() => useArchiveTaskChildren(() => current.value, () => ({ page_size: 20 })))!
    await vi.waitFor(() => expect(model.loading.value).toBe(false))
    listChildren.mockResolvedValueOnce({ items: [child] })
    await model.nextPage()

    const updatedChild = { ...child, name: 'updated child' }
    listChildren.mockResolvedValueOnce({ items: [updatedChild] })
    current.value = { ...current.value, archive: { ...current.value.archive!, completed_count: 1 } }
    await vi.waitFor(() => expect(model.items.value).toEqual([updatedChild]))
    expect(model.pageIndex.value).toBe(1)
    expect(listChildren).toHaveBeenLastCalledWith('parent', { page_size: 10, cursor: 'next' })
  })

  it('allows retrying a failed load and cancels scheduled updates on disposal', async () => {
    vi.useFakeTimers()
    listChildren.mockRejectedValueOnce(new Error('connection lost'))
    const scope = effectScope()
    scopes.push(scope)
    const model = scope.run(() => useArchiveTaskChildren(() => parent, () => ({ page_size: 20 })))!
    await vi.advanceTimersByTimeAsync(0)
    expect(model.error.value).toBeTruthy()
    listChildren.mockResolvedValueOnce({ items: [{ ...child, status: 'SCANNING' }] })
    await model.refresh()
    expect(model.error.value).toBe('')
    expect(model.items.value[0]?.status).toBe('SCANNING')

    scope.stop()
    await vi.advanceTimersByTimeAsync(5000)
    expect(listChildren).toHaveBeenCalledTimes(2)
  })
})
