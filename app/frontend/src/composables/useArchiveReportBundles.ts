import {
  onScopeDispose,
  readonly,
  shallowRef,
  toValue,
  watch,
  type MaybeRefOrGetter,
} from 'vue'

import { api, ApiError } from '@/api/client'
import type {
  ArchiveReportBundle,
  CreateArchiveReportBundleInput,
  ReportDownload,
} from '@/api/types'
import { createIdempotencyKey } from '@/utils/idempotency'

interface UseArchiveReportBundlesOptions {
  importId: MaybeRefOrGetter<string>
}

const BLOB_URL_RELEASE_DELAY_MS = 30_000

function message(error: unknown, fallback: string): string {
  return error instanceof ApiError || error instanceof Error
    ? error.message
    : fallback
}

export function useArchiveReportBundles(
  options: UseArchiveReportBundlesOptions,
) {
  // 报告包是归档导入的聚合产物，不在浏览器拼装：前端只提交格式/源码选项、
  // 跟踪服务端产物，并负责把 URL 或 Blob 以安全方式交给浏览器下载。
  const bundles = shallowRef<readonly ArchiveReportBundle[]>([])
  const loading = shallowRef(false)
  const generating = shallowRef(false)
  const downloadingId = shallowRef('')
  const error = shallowRef('')
  const operationError = shallowRef('')
  const idempotencyKeys = new Map<string, string>()
  const releaseTimers = new Map<
    string,
    ReturnType<typeof globalThis.setTimeout>
  >()
  let generation = 0

  function inputSignature(input: CreateArchiveReportBundleInput): string {
    // 格式先排序，确保勾选顺序不同但语义相同的请求复用同一个幂等键。
    return `${[...input.formats].sort().join(',')}:${input.include_sources ? 'sources' : 'reports'}`
  }

  function clickDownload(url: string, filename?: string): void {
    if (typeof document === 'undefined') {
      throw new Error('当前浏览器不支持归档报告包下载')
    }
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename ?? ''
    anchor.rel = 'noopener'
    anchor.style.display = 'none'
    document.body.append(anchor)
    anchor.click()
    anchor.remove()
  }

  function scheduleRelease(objectUrl: string): void {
    // 点击下载后不能立即 revoke，部分浏览器会异步读取 Blob；延迟释放并在销毁时兜底。
    const timer = globalThis.setTimeout(() => {
      releaseTimers.delete(objectUrl)
      URL.revokeObjectURL(objectUrl)
    }, BLOB_URL_RELEASE_DELAY_MS)
    releaseTimers.set(objectUrl, timer)
  }

  async function load(): Promise<void> {
    const importId = toValue(options.importId)
    if (!importId) return
    // generation 同时标记 importId 作用域，避免快速切换归档时旧响应覆盖新列表。
    const current = ++generation
    loading.value = true
    error.value = ''
    try {
      const result = await api.listArchiveReportBundles(importId)
      if (current !== generation || importId !== toValue(options.importId)) return
      bundles.value = result.items
    } catch (caught) {
      if (current !== generation || importId !== toValue(options.importId)) return
      error.value = message(caught, '无法读取归档报告包')
      bundles.value = []
    } finally {
      if (current === generation) loading.value = false
    }
  }

  async function generate(
    input: CreateArchiveReportBundleInput,
  ): Promise<ArchiveReportBundle | null> {
    const importId = toValue(options.importId)
    if (!importId || generating.value || input.formats.length === 0) return null
    const current = generation
    const signature = inputSignature(input)
    const idempotencyKey =
      idempotencyKeys.get(signature) ?? createIdempotencyKey()
    idempotencyKeys.set(signature, idempotencyKey)
    generating.value = true
    operationError.value = ''
    try {
      const created = await api.createArchiveReportBundle(
        importId,
        {
          formats: [...input.formats].sort(),
          include_sources: input.include_sources,
        },
        idempotencyKey,
      )
      if (current !== generation || importId !== toValue(options.importId)) {
        return null
      }
      idempotencyKeys.delete(signature)
      bundles.value = [
        created,
        ...bundles.value.filter((bundle) => bundle.id !== created.id),
      ]
      return created
    } catch (caught) {
      if (current !== generation || importId !== toValue(options.importId)) {
        return null
      }
      if (
        caught instanceof ApiError &&
        caught.code === 'archive_report_bundle_idempotency_conflict'
      ) {
        idempotencyKeys.delete(signature)
      }
      operationError.value = message(caught, '归档报告包生成失败')
      return null
    } finally {
      if (current === generation) generating.value = false
    }
  }

  async function presentDownload(result: ReportDownload, bundleId: string): Promise<void> {
    if (result.kind === 'url') {
      if (typeof window === 'undefined') {
        throw new Error('当前浏览器不支持归档报告包下载')
      }
      const target = new URL(result.url, window.location.href)
      // 服务端可返回相对下载地址，但不允许把带 Cookie 的页面跳转到跨域或含凭据 URL。
      if (
        target.origin !== window.location.origin ||
        target.username ||
        target.password
      ) {
        throw new Error('归档报告包下载地址不是安全的同源地址')
      }
      clickDownload(target.href)
      return
    }
    if (typeof URL.createObjectURL !== 'function') {
      throw new Error('当前浏览器不支持归档报告包下载')
    }
    const objectUrl = URL.createObjectURL(result.blob)
    scheduleRelease(objectUrl)
    clickDownload(
      objectUrl,
      result.filename || `binaryscan-archive-${bundleId}.zip`,
    )
  }

  async function download(bundle: ArchiveReportBundle): Promise<void> {
    if (bundle.status !== 'ready' || downloadingId.value) return
    const importId = toValue(options.importId)
    const current = generation
    downloadingId.value = bundle.id
    operationError.value = ''
    try {
      const result = await api.downloadArchiveReportBundle(bundle.id)
      if (current !== generation || importId !== toValue(options.importId)) return
      await presentDownload(result, bundle.id)
    } catch (caught) {
      if (current !== generation || importId !== toValue(options.importId)) return
      operationError.value = message(caught, '归档报告包下载失败')
    } finally {
      if (current === generation) downloadingId.value = ''
    }
  }

  watch(
    () => toValue(options.importId),
    (importId) => {
      // importId 变化代表完全不同的数据域，所有在途操作、错误和幂等意图都作废。
      generation += 1
      bundles.value = []
      loading.value = false
      generating.value = false
      downloadingId.value = ''
      error.value = ''
      operationError.value = ''
      idempotencyKeys.clear()
      if (importId) void load()
    },
    { immediate: true },
  )

  onScopeDispose(() => {
    generation += 1
    for (const [objectUrl, timer] of releaseTimers) {
      globalThis.clearTimeout(timer)
      URL.revokeObjectURL(objectUrl)
    }
    releaseTimers.clear()
  })

  return {
    bundles: readonly(bundles),
    loading: readonly(loading),
    generating: readonly(generating),
    downloadingId: readonly(downloadingId),
    error: readonly(error),
    operationError: readonly(operationError),
    load,
    generate,
    download,
  }
}
