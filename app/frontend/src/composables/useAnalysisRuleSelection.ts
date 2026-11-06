import { computed, onScopeDispose, readonly, shallowRef, toValue, watch, type MaybeRefOrGetter } from 'vue'

import { api, ApiError } from '@/api/client'
import type { AnalysisRuleCatalog, AnalysisRuleSelectionInput } from '@/api/types'
import { validateRuleSelection } from '@/components/tasks/analysis-rules/ruleSelection'

interface RuleSelectionOptions {
  taskId: MaybeRefOrGetter<string>
  projectId: MaybeRefOrGetter<string>
  language: AnalysisRuleCatalog['language']
  canCreate: MaybeRefOrGetter<boolean>
  enabled?: MaybeRefOrGetter<boolean>
  createRun: (input: AnalysisRuleSelectionInput) => Promise<void>
  operationError: MaybeRefOrGetter<string>
  clearOperationError: () => void
}

export function useAnalysisRuleSelection(options: RuleSelectionOptions) {
  const open = shallowRef(false)
  const catalog = shallowRef<AnalysisRuleCatalog | null>(null)
  const loading = shallowRef(false)
  const submitting = shallowRef(false)
  const errorMessage = shallowRef('')
  const stale = computed(() => catalog.value?.freshness === 'stale')
  let generation = 0
  let disposed = false
  let target: { taskId: string; projectId: string } | null = null

  function enabled(): boolean { return options.enabled === undefined || toValue(options.enabled) }
  function reset(): void {
    generation += 1
    open.value = false
    catalog.value = null
    loading.value = false
    submitting.value = false
    errorMessage.value = ''
    target = null
  }
  function close(): void { if (!submitting.value) reset() }
  function current(request: number): boolean {
    return !disposed && open.value && request === generation && enabled()
      && target?.taskId === toValue(options.taskId) && target?.projectId === toValue(options.projectId)
  }
  function checkCatalog(value: AnalysisRuleCatalog): void {
    if (value.language !== options.language) throw new Error('规则目录与当前源码项目的语言不一致，请重新读取。')
  }
  function unavailable(value: AnalysisRuleCatalog): string {
    if (value.freshness === 'stale') return '规则目录已过期，请重新读取后确认。'
    if (value.freshness === 'conflict') return '检测引擎规则目录不一致，请检查引擎后重新读取。'
    return value.detail || '当前检测引擎没有可用的规则目录。'
  }

  async function reload(): Promise<void> {
    if (disposed || !open.value || !target || submitting.value) return
    const request = ++generation
    const context = { ...target }
    loading.value = true
    errorMessage.value = ''
    options.clearOperationError()
    try {
      const value = await api.getAnalysisRuleCatalog(context.taskId, context.projectId)
      if (!current(request)) return
      checkCatalog(value)
      catalog.value = value
      if (!value.available || value.freshness !== 'fresh') errorMessage.value = unavailable(value)
    } catch (error) {
      if (current(request)) errorMessage.value = error instanceof ApiError || error instanceof Error ? error.message : '无法读取检测规则，请重试。'
    } finally {
      if (current(request)) loading.value = false
    }
  }

  async function openDialog(): Promise<void> {
    if (disposed || submitting.value || !enabled() || !toValue(options.canCreate)) return
    const taskId = toValue(options.taskId)
    const projectId = toValue(options.projectId)
    if (!taskId || !projectId) return
    reset()
    target = { taskId, projectId }
    open.value = true
    await reload()
  }

  async function confirm(input: AnalysisRuleSelectionInput): Promise<void> {
    if (disposed || !open.value || !target || loading.value || submitting.value || errorMessage.value || !toValue(options.canCreate)) return
    const selection = validateRuleSelection(catalog.value, input)
    if (!selection) {
      errorMessage.value = '请从当前规则目录中至少选择一条规则后再开始检测。'
      return
    }
    const request = ++generation
    const context = { ...target }
    submitting.value = true
    options.clearOperationError()
    try {
      // Recheck immediately before creating: an open dialog may outlive a
      // Worker heartbeat or an engine/catalog upgrade.
      const value = await api.getAnalysisRuleCatalog(context.taskId, context.projectId)
      if (!current(request)) return
      checkCatalog(value)
      catalog.value = value
      if (!value.available || value.freshness !== 'fresh') { errorMessage.value = unavailable(value); return }
      if (value.catalogVersion !== selection.catalog_version) {
        errorMessage.value = '规则目录已更新，请检查新目录并重新确认本次选择。'
        return
      }
      const verified = validateRuleSelection(value, selection)
      if (!verified || !toValue(options.canCreate)) {
        errorMessage.value = '当前项目或规则选择已变化，请重新读取后确认。'
        return
      }
      await options.createRun(verified)
      if (!current(request)) return
      const operationError = toValue(options.operationError)
      if (operationError) errorMessage.value = operationError
      else reset()
    } catch (error) {
      if (current(request)) errorMessage.value = error instanceof Error ? error.message : '无法开始检测，请重试。'
    } finally {
      if (current(request)) submitting.value = false
    }
  }

  watch([() => toValue(options.taskId), () => toValue(options.projectId), enabled], () => {
    if (open.value && (target?.taskId !== toValue(options.taskId)
      || target?.projectId !== toValue(options.projectId) || !enabled())) reset()
  }, { flush: 'sync' })
  onScopeDispose(() => { disposed = true; reset() })

  return { open: readonly(open), catalog: readonly(catalog), loading: readonly(loading),
    submitting: readonly(submitting), errorMessage: readonly(errorMessage), stale,
    openDialog, close, retry: reload, confirm }
}
