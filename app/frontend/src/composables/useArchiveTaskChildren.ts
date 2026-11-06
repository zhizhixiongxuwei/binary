import { computed, onScopeDispose, readonly, shallowRef, watch } from 'vue'

import { api, ApiError } from '@/api/client'
import type { ScanTask, TaskListQuery } from '@/api/types'
import { archiveChildFilters, taskIsActive } from '@/components/tasks/archiveTaskPresentation'

export function useArchiveTaskChildren(task: () => ScanTask, filters: () => TaskListQuery) {
  const items = shallowRef<ScanTask[]>([])
  const loading = shallowRef(false)
  const error = shallowRef('')
  const nextCursor = shallowRef('')
  const cursors = shallowRef<string[]>([''])
  const pageIndex = shallowRef(0)
  const matchingOnly = shallowRef(true)
  let generation = 0
  let disposed = false
  let pollTimer: ReturnType<typeof setTimeout> | undefined

  const matchingQuery = computed(() => archiveChildFilters(task(), filters()))
  const hasFilters = computed(() => Object.keys(matchingQuery.value).some((key) => key !== 'page_size'))

  function clearPoll(): void {
    if (pollTimer !== undefined) clearTimeout(pollTimer)
    pollTimer = undefined
  }

  async function load(quiet = false): Promise<boolean> {
    if (disposed) return false
    clearPoll()
    const request = ++generation
    if (!quiet) loading.value = true
    error.value = ''
    try {
      const query: TaskListQuery = matchingOnly.value ? { ...matchingQuery.value } : { page_size: 10 }
      const cursor = cursors.value[pageIndex.value]
      if (cursor) query.cursor = cursor
      const page = await api.listTaskChildren(task().id, query)
      if (disposed || generation !== request) return false
      items.value = page.items
      nextCursor.value = page.next_cursor ?? ''
      return true
    } catch (reason) {
      if (disposed || generation !== request) return false
      error.value = reason instanceof ApiError ? reason.message : '无法读取归档子任务'
      return false
    } finally {
      if (!disposed && generation === request) {
        loading.value = false
        if (task().archive?.active_count || items.value.some(taskIsActive)) {
          pollTimer = setTimeout(() => void load(true), 5000)
        }
      }
    }
  }

  async function refresh(): Promise<void> {
    const loaded = await load()
    if (loaded && !items.value.length && pageIndex.value > 0 && !error.value) {
      pageIndex.value = 0
      cursors.value = ['']
      await load()
    }
  }

  async function nextPage(): Promise<void> {
    if (!nextCursor.value || loading.value) return
    const previousIndex = pageIndex.value
    const previousCursors = cursors.value
    const previousNext = nextCursor.value
    cursors.value = [...cursors.value.slice(0, pageIndex.value + 1), nextCursor.value]
    pageIndex.value += 1
    const request = generation + 1
    if (!await load() && !disposed && request === generation) {
      pageIndex.value = previousIndex
      cursors.value = previousCursors
      nextCursor.value = previousNext
    }
  }

  async function previousPage(): Promise<void> {
    if (!pageIndex.value || loading.value) return
    const previousIndex = pageIndex.value
    const previousNext = nextCursor.value
    pageIndex.value -= 1
    const request = generation + 1
    if (!await load() && !disposed && request === generation) {
      pageIndex.value = previousIndex
      nextCursor.value = previousNext
    }
  }

  watch(() => JSON.stringify([task().id, matchingQuery.value, matchingOnly.value]), () => {
    cursors.value = ['']
    pageIndex.value = 0
    nextCursor.value = ''
    items.value = []
    void load()
  }, { immediate: true })

  // The current page can be idle while another page gains or finishes work.
  // Reconcile it when the parent summary changes without losing pagination.
  watch([() => task().id, () => JSON.stringify(task().archive)], ([id], [previousId]) => {
    if (id === previousId) void refresh()
  })

  onScopeDispose(() => {
    disposed = true
    generation += 1
    clearPoll()
  })

  return {
    items: readonly(items), loading: readonly(loading), error: readonly(error),
    nextCursor: readonly(nextCursor), pageIndex: readonly(pageIndex), hasFilters,
    matchingOnly, refresh, nextPage, previousPage,
  }
}
