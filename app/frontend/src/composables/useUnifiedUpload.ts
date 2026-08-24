import { computed, shallowRef } from 'vue'

import { api, ApiError } from '@/api/client'
import type {
  AnalysisMode,
  UploadAnalysisOption,
  UploadAnalysisTask,
  UploadSession,
} from '@/api/types'
import { sha256Blob } from '@/utils/hash'
import { createIdempotencyKey } from '@/utils/idempotency'

const MAX_UPLOAD_SIZE = 2 * 1024 ** 3

export type UnifiedUploadStatus =
  | 'ready'
  | 'uploading'
  | 'awaiting_mode'
  | 'failed'

export interface UnifiedUploadItem {
  localId: string
  file: File | undefined
  filename: string
  size: number
  contentType: string
  status: UnifiedUploadStatus
  progress: number
  uploadedBytes: number
  uploadId: string | undefined
  detectedFormat: string | undefined
  detectedCategory: string | undefined
  sha256: string | undefined
  analysisOptions: UploadAnalysisOption[]
  tasks: UploadAnalysisTask[]
  creatingMode: AnalysisMode | undefined
  errorMessage: string
  canRetry: boolean
  removing: boolean
}

function replaceItem(
  items: UnifiedUploadItem[],
  localId: string,
  patch: Partial<UnifiedUploadItem>,
): UnifiedUploadItem[] {
  return items.map((item) =>
    item.localId === localId ? { ...item, ...patch } : item,
  )
}

function uploadedBytes(
  size: number,
  partSize: number,
  parts: readonly number[],
): number {
  return [...new Set(parts)].reduce((total, part) => {
    const start = (part - 1) * partSize
    return total + Math.max(0, Math.min(partSize, size - start))
  }, 0)
}

function recoveredItem(session: UploadSession): UnifiedUploadItem {
  const size = session.size_bytes ?? 0
  return {
    localId: `recovered:${session.id}`,
    file: undefined,
    filename: session.filename ?? session.id,
    size,
    contentType: session.content_type ?? 'application/octet-stream',
    status: session.status === 'completed' ? 'awaiting_mode' : 'failed',
    progress: session.status === 'completed' ? 100 : 0,
    uploadedBytes: session.status === 'completed' ? size : 0,
    uploadId: session.id,
    detectedFormat: session.detected_format,
    detectedCategory: session.detected_category,
    sha256: session.sha256,
    analysisOptions: session.analysis_options ?? [],
    tasks: session.tasks ?? [],
    creatingMode: undefined,
    errorMessage:
      session.status === 'completed' ? '' : '历史上传未完成，请重新选择文件',
    canRetry: false,
    removing: false,
  }
}

export function useUnifiedUpload() {
  const queue = shallowRef<UnifiedUploadItem[]>([])
  const activeId = shallowRef<string | null>(null)
  const recovering = shallowRef(false)
  const recoveryError = shallowRef('')

  const readyCount = computed(
    () =>
      queue.value.filter(
        (item) =>
          item.status === 'ready' ||
          (item.status === 'failed' && item.canRetry),
      ).length,
  )

  function patch(localId: string, value: Partial<UnifiedUploadItem>): void {
    queue.value = replaceItem(queue.value, localId, value)
  }

  function addFiles(files: readonly File[]): string[] {
    const rejected: string[] = []
    const additions: UnifiedUploadItem[] = []
    for (const file of files) {
      if (file.size <= 0) {
        rejected.push(`${file.name} 是空文件`)
        continue
      }
      if (file.size > MAX_UPLOAD_SIZE) {
        rejected.push(`${file.name} 超过 2 GiB`)
        continue
      }
      additions.push({
        localId: createIdempotencyKey(),
        file,
        filename: file.name,
        size: file.size,
        contentType: file.type || 'application/octet-stream',
        status: 'ready',
        progress: 0,
        uploadedBytes: 0,
        uploadId: undefined,
        detectedFormat: undefined,
        detectedCategory: undefined,
        sha256: undefined,
        analysisOptions: [],
        tasks: [],
        creatingMode: undefined,
        errorMessage: '',
        canRetry: true,
        removing: false,
      })
    }
    queue.value = [...queue.value, ...additions]
    return rejected
  }

  async function recover(): Promise<void> {
    recovering.value = true
    recoveryError.value = ''
    try {
      const page = await api.listUploads()
      const existing = new Set(queue.value.flatMap((item) => item.uploadId ?? []))
      const restored = page.items
        .filter(
          (session) =>
            session.status === 'completed' &&
            session.validation_status === 'valid' &&
            !existing.has(session.id),
        )
        .map(recoveredItem)
      queue.value = [...queue.value, ...restored]
    } catch (error) {
      recoveryError.value =
        error instanceof ApiError ? error.message : '待处理上传恢复失败'
    } finally {
      recovering.value = false
    }
  }

  async function uploadItem(localId: string): Promise<void> {
    const item = queue.value.find((candidate) => candidate.localId === localId)
    if (!item?.file || item.status === 'uploading' || activeId.value) return
    activeId.value = localId
    patch(localId, {
      status: 'uploading',
      errorMessage: '',
      canRetry: true,
    })
    try {
      let session = item.uploadId
        ? await api.getUpload(item.uploadId)
        : await api.createUpload(
            {
              filename: item.filename,
              size: item.size,
              content_type: item.contentType,
            },
            item.localId,
          )
      patch(localId, { uploadId: session.id })
      const completedParts = new Set(session.uploaded_parts)
      const totalParts = Math.ceil(item.size / session.part_size)
      for (let partNumber = 1; partNumber <= totalParts; partNumber += 1) {
        if (completedParts.has(partNumber)) continue
        const start = (partNumber - 1) * session.part_size
        const end = Math.min(start + session.part_size, item.size)
        const chunk = item.file.slice(start, end)
        await api.uploadPart(session.id, {
          part_number: partNumber,
          start,
          end: end - 1,
          total: item.size,
          sha256: await sha256Blob(chunk),
          chunk,
        })
        completedParts.add(partNumber)
        const done = uploadedBytes(
          item.size,
          session.part_size,
          [...completedParts],
        )
        patch(localId, {
          uploadedBytes: done,
          progress: Math.min(99, Math.round((done / item.size) * 100)),
        })
      }
      session = await api.completeUpload(session.id)
      patch(localId, {
        status: 'awaiting_mode',
        progress: 100,
        uploadedBytes: item.size,
        uploadId: session.id,
        detectedFormat: session.detected_format,
        detectedCategory: session.detected_category,
        sha256: session.sha256,
        analysisOptions: session.analysis_options ?? [],
        tasks: session.tasks ?? [],
        canRetry: false,
      })
    } catch (error) {
      const unsupported =
        error instanceof ApiError && error.code === 'unsupported_input_format'
      patch(localId, {
        status: 'failed',
        errorMessage: unsupported
          ? '服务端无法识别该文件为当前支持的格式'
          : error instanceof ApiError
            ? error.message
            : '上传中断，请重试',
        canRetry: !unsupported,
      })
    } finally {
      activeId.value = null
    }
  }

  async function startAll(): Promise<void> {
    for (const localId of queue.value
      .filter((item) => item.status === 'ready' || (item.status === 'failed' && item.canRetry))
      .map((item) => item.localId)) {
      await uploadItem(localId)
    }
  }

  async function selectMode(
    localId: string,
    mode: AnalysisMode,
  ): Promise<UploadAnalysisTask | null> {
    const item = queue.value.find((candidate) => candidate.localId === localId)
    if (!item?.uploadId || item.creatingMode) return null
    const existing = item.tasks.find((task) => task.analysis_mode === mode)
    if (existing) return existing
    patch(localId, { creatingMode: mode, errorMessage: '' })
    try {
      const task = await api.createUploadAnalysisTask(
        item.uploadId,
        { analysis_mode: mode },
        `analysis:${item.uploadId}:${mode}`,
      )
      patch(localId, { tasks: [...item.tasks, task], creatingMode: undefined })
      return task
    } catch (error) {
      patch(localId, {
        creatingMode: undefined,
        errorMessage:
          error instanceof ApiError ? error.message : '分析任务创建失败，请重试',
      })
      return null
    }
  }

  async function remove(localId: string): Promise<void> {
    const item = queue.value.find((candidate) => candidate.localId === localId)
    if (!item || item.status === 'uploading' || item.removing) return
    if (!item.uploadId || item.tasks.length > 0) {
      queue.value = queue.value.filter((candidate) => candidate.localId !== localId)
      return
    }
    patch(localId, { removing: true, errorMessage: '' })
    try {
      await api.deleteUpload(item.uploadId)
      queue.value = queue.value.filter((candidate) => candidate.localId !== localId)
    } catch (error) {
      patch(localId, {
        removing: false,
        errorMessage: error instanceof ApiError ? error.message : '删除上传失败',
      })
    }
  }

  return {
    queue,
    activeId,
    readyCount,
    recovering,
    recoveryError,
    addFiles,
    recover,
    uploadItem,
    startAll,
    selectMode,
    remove,
  }
}
