import { computed, onScopeDispose, shallowRef, toValue, watch, type MaybeRefOrGetter } from 'vue'

import { api, ApiError } from '@/api/client'
import type {
  DecompileResult,
  DecompileSourceFile,
  DecompileSourceFileContent,
  SourceNavigationTarget,
} from '@/api/types'
import type { TaskResultState } from '@/components/tasks/taskResultTypes'

const RESULT_PAGE_SIZE = 100

interface UseDecompileResultsOptions {
  taskId: MaybeRefOrGetter<string>
  enabled?: MaybeRefOrGetter<boolean>
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback
}

function supportsSource(result: DecompileResult | undefined): boolean {
  return Boolean(
    result &&
      !['queued', 'running', 'unsupported', 'failed', 'cancelled'].includes(
        result.status,
      ),
  )
}

function normalizedPath(value: string | undefined): string {
  return (value ?? '').replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '')
}

function normalizeTarget(target: SourceNavigationTarget): SourceNavigationTarget {
  const startLine = Math.max(Math.trunc(target.startLine) || 1, 1)
  const startColumn = Math.max(Math.trunc(target.startColumn) || 1, 1)
  const endLine = Math.max(Math.trunc(target.endLine) || startLine, startLine)
  const endColumn = Math.max(
    Math.trunc(target.endColumn) || (endLine === startLine ? startColumn + 1 : 1),
    endLine === startLine ? startColumn : 1,
  )
  return {
    projectId: target.projectId,
    ...(target.reveal !== undefined ? { reveal: target.reveal } : {}),
    ...(target.sourceFileId ? { sourceFileId: target.sourceFileId } : {}),
    ...(target.path ? { path: target.path } : {}),
    startLine,
    startColumn,
    endLine,
    endColumn,
  }
}

export function useDecompileResults(options: UseDecompileResultsOptions) {
  // 数据按“项目列表 -> 项目文件列表 -> 单文件内容”三级延迟加载。每一级都有独立
  // generation，切换项目或文件时只废弃对应请求，不必阻塞其他层的界面更新。
  const items = shallowRef<readonly DecompileResult[]>([])
  const nextCursor = shallowRef<string>()
  const selectedResultId = shallowRef('')
  const sourceFiles = shallowRef<readonly DecompileSourceFile[]>([])
  const selectedSourceFileId = shallowRef('')
  const sourceFile = shallowRef<DecompileSourceFileContent>()
  const source = computed(() => sourceFile.value?.content ?? '')
  const targetRange = shallowRef<SourceNavigationTarget>()
  const loading = shallowRef(false)
  const loadingMore = shallowRef(false)
  const sourceFilesLoading = shallowRef(false)
  const sourceLoading = shallowRef(false)
  const error = shallowRef('')
  const errorCode = shallowRef('')
  const sourceFilesError = shallowRef('')
  const sourceError = shallowRef('')
  let listGeneration = 0
  let sourceFilesGeneration = 0
  let sourceGeneration = 0

  const selectedResult = computed(() =>
    items.value.find((item) => item.id === selectedResultId.value),
  )
  const selectedSourceFile = computed(() =>
    sourceFiles.value.find((item) => item.id === selectedSourceFileId.value),
  )
  const hasMoreResults = computed(() => Boolean(nextCursor.value))
  const state = computed<TaskResultState>(() => {
    if (loading.value) {
      return {
        status: 'loading',
        title: '正在读取反编译结果',
        description: '正在加载反编译源码项目和能力状态。',
      }
    }
    if (error.value) {
      return {
        status: 'error',
        title: '反编译结果读取失败',
        description: error.value,
        ...(errorCode.value ? { errorCode: errorCode.value } : {}),
      }
    }
    if (items.value.length === 0) {
      return {
        status: 'empty',
        title: '暂无反编译结果',
        description: '分析器尚未产生可阅读的源码项目。',
      }
    }
    return { status: 'ready' }
  })

  function clearSourceFile(): void {
    sourceGeneration += 1
    selectedSourceFileId.value = ''
    sourceFile.value = undefined
    sourceLoading.value = false
    sourceError.value = ''
  }

  function resetProjectSource(): void {
    sourceFilesGeneration += 1
    clearSourceFile()
    sourceFiles.value = []
    sourceFilesLoading.value = false
    sourceFilesError.value = ''
    targetRange.value = undefined
  }

  async function readSourceFile(
    projectId: string,
    fileId: string,
  ): Promise<boolean> {
    const generation = ++sourceGeneration
    const taskId = toValue(options.taskId)
    selectedSourceFileId.value = fileId
    sourceFile.value = undefined
    sourceLoading.value = true
    sourceError.value = ''

    try {
      const content = await api.getDecompileSourceFileContent(
        taskId,
        projectId,
        fileId,
      )
      if (
        generation !== sourceGeneration ||
        taskId !== toValue(options.taskId) ||
        projectId !== selectedResultId.value ||
        fileId !== selectedSourceFileId.value
      ) {
        return false
      }
      if (content.id !== fileId || content.projectId !== projectId) {
        // 内容端点必须回显请求身份；校验失败视为契约/存储串线，不能交给 Monaco。
        throw new ApiError('源码文件内容与请求的项目或文件不匹配', 502, {
          code: 'SOURCE_FILE_IDENTITY_MISMATCH',
        })
      }
      sourceFile.value = content
      return true
    } catch (caught) {
      if (
        generation !== sourceGeneration ||
        taskId !== toValue(options.taskId) ||
        projectId !== selectedResultId.value ||
        fileId !== selectedSourceFileId.value
      ) {
        return false
      }
      sourceError.value = errorMessage(caught, '反编译源码文件读取失败')
      return false
    } finally {
      if (generation === sourceGeneration) sourceLoading.value = false
    }
  }

  function findTargetFile(
    files: readonly DecompileSourceFile[],
    target: SourceNavigationTarget,
  ): DecompileSourceFile | undefined {
    // 报告/检测结果优先使用不可变 fileId；兼容历史数据时再按标准化逻辑路径定位。
    if (target.sourceFileId) {
      const byId = files.find((file) => file.id === target.sourceFileId)
      if (byId) return byId
    }
    const path = normalizedPath(target.path)
    return path
      ? files.find((file) => normalizedPath(file.logicalPath) === path)
      : undefined
  }

  async function activateProject(
    projectId: string,
    requestedTarget?: SourceNavigationTarget,
  ): Promise<boolean> {
    // 先更新选中项目并清空上一项目源码，避免请求期间短暂展示“新项目 + 旧代码”。
    const project = items.value.find((item) => item.id === projectId)
    selectedResultId.value = projectId
    resetProjectSource()
    if (!supportsSource(project)) return requestedTarget === undefined

    const generation = ++sourceFilesGeneration
    const taskId = toValue(options.taskId)
    sourceFilesLoading.value = true
    try {
      const page = await api.listDecompileSourceFiles(taskId, projectId)
      if (
        generation !== sourceFilesGeneration ||
        taskId !== toValue(options.taskId) ||
        projectId !== selectedResultId.value
      ) {
        return false
      }
      if (page.files.some((file) => file.projectId !== projectId)) {
        // 文件清单只允许属于当前项目，防止跨任务/跨项目内容被错误展示。
        throw new ApiError('源码文件列表包含其他项目的文件', 502, {
          code: 'SOURCE_PROJECT_IDENTITY_MISMATCH',
        })
      }
      sourceFiles.value = page.files
      const normalizedTarget = requestedTarget
        ? normalizeTarget(requestedTarget)
        : undefined
      const targetFile = normalizedTarget
        ? findTargetFile(page.files, normalizedTarget)
        : undefined
      const nextFile = targetFile ?? page.files[0]
      if (!nextFile) {
        if (normalizedTarget) sourceFilesError.value = '定位的源码文件不存在'
        return normalizedTarget === undefined
      }
      if (normalizedTarget && targetFile) targetRange.value = normalizedTarget.reveal === false ? undefined : normalizedTarget
      const loaded = await readSourceFile(projectId, nextFile.id)
      if (normalizedTarget && !targetFile) {
        sourceFilesError.value = '定位的源码文件不存在，已打开项目中的第一个文件'
        return false
      }
      return loaded
    } catch (caught) {
      if (
        generation !== sourceFilesGeneration ||
        taskId !== toValue(options.taskId) ||
        projectId !== selectedResultId.value
      ) {
        return false
      }
      sourceFilesError.value = errorMessage(caught, '反编译源码文件列表读取失败')
      return false
    } finally {
      if (generation === sourceFilesGeneration) sourceFilesLoading.value = false
    }
  }

  function selectResult(resultId: string): void {
    if (!resultId || resultId === selectedResultId.value) return
    void activateProject(resultId)
  }

  function selectSourceFile(fileId: string): void {
    const projectId = selectedResultId.value
    if (
      !projectId ||
      fileId === selectedSourceFileId.value ||
      !sourceFiles.value.some((file) => file.id === fileId)
    ) {
      return
    }
    targetRange.value = undefined
    void readSourceFile(projectId, fileId)
  }

  async function load(append = false): Promise<void> {
    const taskId = toValue(options.taskId)
    if (!taskId || (options.enabled !== undefined && !toValue(options.enabled))) {
      return
    }
    if (append && (!nextCursor.value || loadingMore.value)) return

    const generation = ++listGeneration
    const previousProjectId = selectedResultId.value
    if (append) {
      loadingMore.value = true
    } else {
      loading.value = true
      error.value = ''
      errorCode.value = ''
      nextCursor.value = undefined
    }

    try {
      const page = await api.listDecompileResults(taskId, {
        page_size: RESULT_PAGE_SIZE,
        ...(append && nextCursor.value ? { cursor: nextCursor.value } : {}),
      })
      if (generation !== listGeneration || taskId !== toValue(options.taskId)) {
        return
      }
      // 游标追加不改变当前项目；完整刷新则尽量恢复原选择，否则打开首个项目。
      items.value = append ? [...items.value, ...page.items] : page.items
      nextCursor.value = page.next_cursor

      if (!append) {
        const nextProject = items.value.find((item) => item.id === previousProjectId)
          ?? items.value[0]
        if (nextProject) void activateProject(nextProject.id)
        else {
          selectedResultId.value = ''
          resetProjectSource()
        }
      }
    } catch (caught) {
      if (generation !== listGeneration || taskId !== toValue(options.taskId)) {
        return
      }
      error.value = errorMessage(caught, '反编译结果读取失败')
      errorCode.value = caught instanceof ApiError ? (caught.code ?? '') : ''
      if (!append) {
        items.value = []
        selectedResultId.value = ''
        resetProjectSource()
      }
    } finally {
      if (generation === listGeneration) {
        loading.value = false
        loadingMore.value = false
      }
    }
  }

  function loadMoreResults(): void {
    void load(true)
  }

  function refresh(): void {
    void load()
  }

  async function ensureProject(projectId: string): Promise<DecompileResult | undefined> {
    // 深链接可能指向尚未加载的后续页。最多追 32 页，既支持定位也避免异常游标
    // 导致无界请求。
    let target = items.value.find((item) => item.id === projectId)
    if (!target) {
      await load()
      target = items.value.find((item) => item.id === projectId)
    }
    let pages = 0
    while (!target && nextCursor.value && pages < 32) {
      await load(true)
      target = items.value.find((item) => item.id === projectId)
      pages += 1
    }
    return target
  }

  async function openResult(projectId: string): Promise<boolean> {
    if (!projectId) return false
    const project = await ensureProject(projectId)
    if (!project) return false
    await activateProject(project.id)
    return true
  }

  async function openSource(target: SourceNavigationTarget): Promise<boolean> {
    if (!target.projectId) return false
    const normalizedTarget = normalizeTarget(target)
    const project = await ensureProject(normalizedTarget.projectId)
    if (!project) return false

    if (
      selectedResultId.value === project.id &&
      sourceFiles.value.length > 0 &&
      !sourceFilesLoading.value
    ) {
      const file = findTargetFile(sourceFiles.value, normalizedTarget)
      if (!file) {
        sourceFilesError.value = '定位的源码文件不存在'
        return false
      }
      targetRange.value = normalizedTarget.reveal === false ? undefined : normalizedTarget
      if (file.id === selectedSourceFileId.value && sourceFile.value) return true
      return readSourceFile(project.id, file.id)
    }
    return activateProject(project.id, normalizedTarget)
  }

  watch(
    [() => toValue(options.taskId), () => options.enabled === undefined || toValue(options.enabled)],
    ([taskId, enabled]) => {
      // taskId 是源码数据的安全边界；切换时同时递增三级版本并清空旧内容。
      listGeneration += 1
      sourceFilesGeneration += 1
      sourceGeneration += 1
      items.value = []
      selectedResultId.value = ''
      sourceFiles.value = []
      selectedSourceFileId.value = ''
      sourceFile.value = undefined
      targetRange.value = undefined
      error.value = ''
      errorCode.value = ''
      sourceFilesError.value = ''
      sourceError.value = ''
      nextCursor.value = undefined
      loading.value = false
      loadingMore.value = false
      sourceFilesLoading.value = false
      sourceLoading.value = false
      if (taskId && enabled) void load()
    },
    { immediate: true },
  )

  onScopeDispose(() => {
    listGeneration += 1
    sourceFilesGeneration += 1
    sourceGeneration += 1
  })

  return {
    items,
    selectedResult,
    selectedResultId,
    sourceFiles,
    selectedSourceFile,
    selectedSourceFileId,
    sourceFile,
    source,
    targetRange,
    loading,
    loadingMore,
    sourceFilesLoading,
    sourceLoading,
    sourceFilesError,
    sourceError,
    state,
    hasMoreResults,
    selectResult,
    selectSourceFile,
    loadMoreResults,
    openResult,
    openSource,
    refresh,
  }
}
