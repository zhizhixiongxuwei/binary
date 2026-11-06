import { onScopeDispose, readonly, shallowRef } from 'vue'

import { api, ApiError } from '@/api/client'
import type { AuditLog, AuditLogListQuery } from '@/api/types'

const PAGE_SIZE = 50

export function useAuditLogs() {
  const logs = shallowRef<AuditLog[]>([])
  const query = shallowRef<AuditLogListQuery>({})
  const nextCursor = shallowRef<string | undefined>()
  const loading = shallowRef(false)
  const loadingMore = shallowRef(false)
  const errorMessage = shallowRef('')
  const loadMoreError = shallowRef('')
  const exporting = shallowRef(false)
  const exportError = shallowRef('')
  const exportFeedback = shallowRef('')
  let requestSequence = 0
  let disposed = false
  const downloadUrls = new Set<string>()

  async function load(
    nextQuery: AuditLogListQuery = query.value,
    options: { append?: boolean } = {},
  ): Promise<void> {
    if (disposed) return
    const append = options.append === true
    if (append && (!nextCursor.value || loading.value || loadingMore.value)) return
    const sequence = ++requestSequence
    if (append) loadingMore.value = true
    else {
      loading.value = true
      loadingMore.value = false
      nextCursor.value = undefined
    }
    errorMessage.value = ''
    loadMoreError.value = ''
    if (!append) {
      const { cursor: _cursor, page_size: _size, ...filters } = nextQuery
      query.value = filters
    }
    try {
      const cursor = append ? nextCursor.value : undefined
      const page = await api.listAuditLogs({
        ...query.value,
        ...(cursor ? { cursor } : {}),
        page_size: PAGE_SIZE,
      })
      if (disposed || sequence !== requestSequence) return
      logs.value = append ? [...logs.value, ...page.items] : page.items
      nextCursor.value = page.next_cursor
    } catch (error) {
      if (!disposed && sequence === requestSequence) {
        const message =
          error instanceof ApiError ? error.message : '审计日志读取失败'
        if (append) loadMoreError.value = message
        else errorMessage.value = message
      }
    } finally {
      if (sequence === requestSequence) {
        loading.value = false
        loadingMore.value = false
      }
    }
  }

  async function exportLogs(exportQuery: AuditLogListQuery = query.value): Promise<void> {
    if (disposed || exporting.value) return
    exporting.value = true
    exportError.value = ''
    exportFeedback.value = ''
    try {
      const { cursor: _cursor, page_size: _size, ...filters } = exportQuery
      const result = await api.exportAuditLogs(filters)
      if (disposed) return
      let url: string
      let filename = 'audit-logs.csv'
      if (result.kind === 'blob') {
        url = URL.createObjectURL(result.blob)
        filename = result.filename
        downloadUrls.add(url)
        setTimeout(() => { URL.revokeObjectURL(url); downloadUrls.delete(url) }, 30000)
      } else {
        const target = new URL(result.url, window.location.origin)
        if (target.origin !== window.location.origin) throw new Error('审计下载地址无效')
        url = target.href
      }
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = filename
      anchor.rel = 'noopener'
      document.body.append(anchor)
      anchor.click()
      anchor.remove()
      exportFeedback.value = '已开始下载CSV，包含筛选条件下的全部匹配记录。'
    } catch (error) {
      if (!disposed) exportError.value = error instanceof Error ? error.message : '审计日志导出失败'
    } finally {
      if (!disposed) exporting.value = false
    }
  }

  onScopeDispose(() => {
    disposed = true
    requestSequence += 1
    for (const url of downloadUrls) URL.revokeObjectURL(url)
    downloadUrls.clear()
  })

  return {
    logs: readonly(logs),
    query: readonly(query),
    nextCursor: readonly(nextCursor),
    loading: readonly(loading),
    loadingMore: readonly(loadingMore),
    errorMessage: readonly(errorMessage),
    loadMoreError: readonly(loadMoreError),
    exporting: readonly(exporting),
    exportError: readonly(exportError),
    exportFeedback: readonly(exportFeedback),
    exportLogs,
    load,
  }
}
