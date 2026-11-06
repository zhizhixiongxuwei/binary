import { onScopeDispose, readonly, shallowRef } from 'vue'

import { api, ApiError } from '@/api/client'
import type { ScanTask, TaskListQuery } from '@/api/types'
import { taskIsActive } from '@/components/tasks/archiveTaskPresentation'

export function useTaskList() {
  const items = shallowRef<ScanTask[]>([])
  const nextCursor = shallowRef('')
  const loading = shallowRef(false)
  const errorMessage = shallowRef('')
  const lastQuery = shallowRef<TaskListQuery>({ page_size: 20 })
  let requestGeneration = 0
  let disposed = false
  let pollTimer: ReturnType<typeof setTimeout> | undefined

  async function load(query: TaskListQuery, quiet = false): Promise<void> {
    if (pollTimer !== undefined) clearTimeout(pollTimer)
    const generation = ++requestGeneration
    if (!quiet) loading.value = true
    errorMessage.value = ''
    if (!quiet) nextCursor.value = ''
    lastQuery.value = { ...query }
    try {
      const result = await api.listTasks(query)
      if (disposed || generation !== requestGeneration) return
      items.value = result.items
      nextCursor.value = result.next_cursor ?? ''
    } catch (error) {
      if (disposed || generation !== requestGeneration) return
      errorMessage.value =
        error instanceof ApiError ? error.message : '无法连接检测服务，请检查服务状态'
    } finally {
      if (!disposed && generation === requestGeneration) {
        loading.value = false
        if (items.value.some((item) => taskIsActive(item) || Boolean(item.archive?.active_count))) {
          pollTimer = setTimeout(() => void load(lastQuery.value, true), 5000)
        }
      }
    }
  }

  async function reload(): Promise<void> {
    await load(lastQuery.value)
  }

  onScopeDispose(() => {
    disposed = true
    requestGeneration += 1
    if (pollTimer !== undefined) clearTimeout(pollTimer)
  })

  return {
    items: readonly(items),
    nextCursor: readonly(nextCursor),
    loading: readonly(loading),
    errorMessage: readonly(errorMessage),
    load,
    reload,
  }
}
