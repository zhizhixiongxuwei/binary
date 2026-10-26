import { computed, onScopeDispose, reactive, shallowRef, toValue, watch, type MaybeRefOrGetter } from 'vue'

import { ApiError } from '@/api/client'
import { getLLMStatus, listExplanations, llmErrorMessage, streamExplanation } from '@/api/llm'
import type { ExplanationInput, ExplanationRecord, LLMStatus, SourceIdentity, SourceSelection } from '@/api/llmTypes'
import type { UserRole } from '@/api/types'
import { createIdempotencyKey } from '@/utils/idempotency'

export interface ExplanationSource extends SourceIdentity {
  sourceSha256?: string | undefined
  source: string
  filename: string
  lineCount: number
  loading: boolean
  selection: SourceSelection | null
}

interface FileState {
  history: ExplanationRecord[]
  selected: ExplanationRecord | null
  phase: 'idle' | 'generating' | 'completed' | 'cancelled' | 'failed'
  error: string
  historyError: string
  historyLoading: boolean
  historyGeneration: number
  requestRange: ReturnType<typeof explanationRange> | null
}

const identityKey = (value: SourceIdentity) => JSON.stringify([value.taskId, value.projectId, value.fileId])

export function explanationRange(source: ExplanationSource, scope: ExplanationInput['scope']) {
  // Match the server's CRLF normalization before counting or previewing code.
  const content = source.source.replace(/\r\n/g, '\n')
  const lines = content.split('\n')
  const startLine = scope === 'selection' ? source.selection?.startLine ?? 0 : 1
  const endLine = scope === 'selection' ? source.selection?.endLine ?? 0 : lines.length
  const valid = Number.isInteger(startLine) && Number.isInteger(endLine) && startLine >= 1 && endLine >= startLine && endLine <= lines.length
  const text = valid ? (scope === 'file' ? content : lines.slice(startLine - 1, endLine).join('\n')) : ''
  return { startLine, endLine, text, valid, chars: Array.from(text).length }
}

export function useAIExplanation(options: {
  source: MaybeRefOrGetter<ExplanationSource>
  open: MaybeRefOrGetter<boolean>
  role: MaybeRefOrGetter<UserRole | null>
}) {
  const states = reactive(new Map<string, FileState>())
  const status = shallowRef<LLMStatus | null>(null)
  const statusLoading = shallowRef(false)
  const statusError = shallowRef('')
  const scope = shallowRef<ExplanationInput['scope']>('file')
  const source = computed(() => toValue(options.source))
  const key = computed(() => identityKey(source.value))
  let statusGeneration = 0
  let running: { controller: AbortController; key: string; state: FileState } | null = null
  let disposed = false

  function stateFor(value: string): FileState {
    if (!states.has(value)) states.set(value, { history: [], selected: null, phase: 'idle', error: '', historyError: '', historyLoading: false, historyGeneration: 0, requestRange: null })
    return states.get(value)!
  }
  const current = computed(() => stateFor(key.value))
  const generating = computed(() => current.value.phase === 'generating')
  const canGenerate = computed(() => ['administrator', 'operator'].includes(toValue(options.role) ?? ''))
  const range = computed(() => generating.value && current.value.requestRange ? current.value.requestRange : explanationRange(source.value, scope.value))
  const blockedReason = computed(() => {
    if (!canGenerate.value) return '只读账号可以查看历史解释，生成解释请联系管理员或操作员。'
    if (source.value.loading) return '正在读取源码，请稍候。'
    if (!source.value.fileId || !source.value.projectId || !source.value.taskId || !source.value.source.trim()) return '请选择一个有源码内容的文件。'
    if (statusLoading.value) return '正在读取模型服务状态。'
    if (statusError.value) return statusError.value
    if (!status.value?.enabled || !status.value.configured) return '模型服务尚未启用或配置，请联系管理员。'
    if (!range.value.valid) return '请先在源码中选择有效的行范围。'
    if (range.value.chars > status.value.maxInputChars) return `代码超过 ${status.value.maxInputChars.toLocaleString()} 字符上限，请选择较小的代码片段。`
    return ''
  })

  function remember(state: FileState, record: ExplanationRecord): void {
    state.selected = record
    state.history = [record, ...state.history.filter((item) => item.id !== record.id)].slice(0, 30)
  }

  function stop(): void {
    if (!running) return
    const active = running
    running = null
    active.controller.abort()
    if (active.state.phase !== 'generating') return
    active.state.phase = 'cancelled'
    active.state.error = ''
    if (active.state.selected?.status === 'generating') remember(active.state, { ...active.state.selected, status: 'cancelled' })
  }

  async function refreshStatus(): Promise<void> {
    const generation = ++statusGeneration
    statusLoading.value = true
    statusError.value = ''
    try {
      const result = await getLLMStatus()
      if (!disposed && generation === statusGeneration) status.value = result
    } catch (error) {
      if (!disposed && generation === statusGeneration) { status.value = null; statusError.value = llmErrorMessage(error) }
    } finally {
      if (!disposed && generation === statusGeneration) statusLoading.value = false
    }
  }

  async function refreshHistory(): Promise<void> {
    const identity = { taskId: source.value.taskId, projectId: source.value.projectId, fileId: source.value.fileId }
    if (!identity.taskId || !identity.projectId || !identity.fileId) return
    const state = stateFor(identityKey(identity))
    const generation = ++state.historyGeneration
    state.historyLoading = true
    state.historyError = ''
    try {
      const items = (await listExplanations(identity)).filter((item) => identityKey(item) === identityKey(identity))
      if (disposed || generation !== state.historyGeneration) return
      // Preserve an in-memory partial response if cancellation reached the server later.
      const merged = new Map(state.history.map((item) => [item.id, item]))
      for (const item of items) {
        const local = merged.get(item.id)
        if (local?.status === 'generating' || (local?.status === 'cancelled' && item.status === 'generating')) continue
        merged.set(item.id, item)
      }
      state.history = [...merged.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 30)
      if (!state.selected) state.selected = state.history[0] ?? null
      else if (state.phase !== 'generating') state.selected = merged.get(state.selected.id) ?? state.selected
    } catch (error) {
      if (!disposed && generation === state.historyGeneration) state.historyError = llmErrorMessage(error)
    } finally {
      if (!disposed && generation === state.historyGeneration) state.historyLoading = false
    }
  }

  async function generate(regenerate = false): Promise<void> {
    if (generating.value || running || !toValue(options.open)) return
    if (blockedReason.value) { current.value.error = blockedReason.value; return }
    const snapshot = { ...source.value }
    const selectedRange = { ...range.value }
    const identity = { taskId: snapshot.taskId, projectId: snapshot.projectId, fileId: snapshot.fileId }
    const state = current.value
    let requestId: string
    try { requestId = createIdempotencyKey() }
    catch (error) { state.error = llmErrorMessage(error); return }
    const controller = new AbortController()
    const active = { controller, key: key.value, state }
    running = active
    state.phase = 'generating'
    state.requestRange = selectedRange
    state.error = ''
    const input: ExplanationInput = {
      scope: scope.value, requestId, regenerate,
      ...(scope.value === 'selection' ? { startLine: selectedRange.startLine, endLine: selectedRange.endLine } : {}),
      ...(snapshot.sourceSha256 ? { sourceSha256: snapshot.sourceSha256 } : {}),
    }
    const draft: ExplanationRecord = {
      ...identity, id: requestId, sourceSha256: snapshot.sourceSha256 ?? '', scope: input.scope,
      startLine: selectedRange.startLine, endLine: selectedRange.endLine,
      provider: status.value!.provider, model: status.value!.model,
      text: '', status: 'generating', createdAt: new Date().toISOString(),
    }
    state.selected = draft
    let terminal = false
    try {
      await streamExplanation(identity, input, (event) => {
        if (disposed || controller.signal.aborted || running !== active) return
        if (event.type === 'meta' || event.type === 'done') {
          if (identityKey(event.data) !== active.key) throw new Error('解释记录与当前源码文件不匹配，请重试')
          remember(state, { ...event.data })
          if (event.type === 'done') { terminal = true; state.phase = event.data.status === 'completed' ? 'completed' : event.data.status === 'cancelled' ? 'cancelled' : 'failed' }
        } else if (event.type === 'delta') {
          if (state.selected) state.selected.text += event.data.text
        } else {
          terminal = true
          state.phase = 'failed'
          state.error = llmErrorMessage(new ApiError(event.data.message, 502, { code: event.data.code }))
          if (state.selected) remember(state, { ...state.selected, status: 'failed' })
        }
      }, controller.signal, { source: snapshot.source, filename: snapshot.filename })
      if (!terminal && !controller.signal.aborted) throw new Error('模型连接提前断开，请重试')
    } catch (error) {
      if (!disposed && !controller.signal.aborted && running === active) {
        state.phase = 'failed'
        state.error = llmErrorMessage(error)
        if (state.selected) remember(state, { ...state.selected, status: 'failed' })
      }
    } finally {
      if (running === active) running = null
    }
  }

  function selectHistory(id: string): void {
    if (generating.value) return
    current.value.selected = current.value.history.find((item) => item.id === id) ?? current.value.selected
    current.value.error = ''
    current.value.phase = 'idle'
  }

  watch([key, () => source.value.sourceSha256, () => source.value.source, () => source.value.loading], () => { stop() }, { flush: 'sync' })
  // The editor may clear the previous file's selection after its file ID changes.
  // Never infer a new file's scope from that transient, previous-file selection.
  watch(key, () => { scope.value = 'file' }, { flush: 'sync' })
  watch([() => source.value.selection, generating], ([selection, busy]) => {
    if (!busy && !selection && scope.value === 'selection') scope.value = 'file'
  }, { flush: 'sync' })
  watch(() => toValue(options.role), () => { if (!canGenerate.value) stop() }, { flush: 'sync' })
  watch(() => [toValue(options.open), key.value] as const, ([open], previous) => {
    if (!open) { stop(); return }
    if (!previous?.[0] && source.value.selection) scope.value = 'selection'
    void refreshStatus()
    void refreshHistory()
  }, { immediate: true })
  onScopeDispose(() => { stop(); disposed = true; statusGeneration += 1 })

  return { current, scope, status, statusLoading, statusError, range, generating, canGenerate, blockedReason, generate, stop, refreshStatus, refreshHistory, selectHistory }
}
