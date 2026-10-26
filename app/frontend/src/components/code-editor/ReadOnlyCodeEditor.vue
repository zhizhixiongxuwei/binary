<script setup lang="ts">
import { Copy, Hash, LoaderCircle, Search, TriangleAlert } from 'lucide-vue-next'
import { computed, nextTick, onMounted, onScopeDispose, shallowRef, useTemplateRef, watch } from 'vue'

import type { SourceNavigationTarget } from '@/api/types'
import { loadMonacoEditor, resolveMonacoLanguage, supportsMonacoRuntime, type MonacoModule, type ReadOnlyCodeLanguage } from './monacoLoader'
import { createTargetRevealGuard, formatCodeCopy, sourceViewStates, type CodeSelection } from './readingState'

type EditorState = 'fallback' | 'loading' | 'ready' | 'error'
const props = withDefaults(defineProps<{
  source: string
  language: ReadOnlyCodeLanguage
  label: string
  modelUri?: string | undefined
  targetRange?: SourceNavigationTarget | undefined
  filename?: string | undefined
  loading?: boolean
  error?: string
  available?: boolean
}>(), { filename: '', loading: false, error: '', available: true })
const emit = defineEmits<{ selectionChange: [selection: CodeSelection | null] }>()
const editorHost = useTemplateRef<HTMLDivElement>('editorHost')
const fallbackSource = useTemplateRef<HTMLElement>('fallbackSource')
const lineInput = useTemplateRef<HTMLInputElement>('lineInput')
const state = shallowRef<EditorState>('fallback')
const monacoModule = shallowRef<MonacoModule>()
const editor = shallowRef<ReturnType<MonacoModule['editor']['create']>>()
const model = shallowRef<ReturnType<MonacoModule['editor']['createModel']>>()
const selection = shallowRef<CodeSelection | null>(null)
const copyFilename = shallowRef(false)
const copyLineNumbers = shallowRef(false)
const copyMessage = shallowRef('')
const jumpOpen = shallowRef(false)
const jumpLine = shallowRef('1')
const jumpError = shallowRef('')
const fallbackModelUri = `inmemory://binaryscan/read-only/${Math.random().toString(36).slice(2)}`
const requestedUri = computed(() => props.modelUri || fallbackModelUri)
const blocked = computed(() => props.loading || Boolean(props.error) || !props.available)
const lineCount = computed(() => Math.max(1, props.source.split('\n').length))
const showFallback = computed(() => state.value !== 'ready')
let currentUri = ''
let targetDecorations: string[] = []
let cursorSubscription: { dispose(): void } | undefined
let disposed = false
let fallbackSelectionListener: (() => void) | undefined
const targetRevealGuard = createTargetRevealGuard()
let pendingViewSaved = false

const statusText = computed(() => {
  if (props.loading) return '正在读取源码'
  if (props.error) return '源码读取失败'
  if (!props.available) return '选择文件开始阅读'
  if (state.value === 'loading') return '正在加载编辑器'
  if (state.value === 'error') return '只读文本模式'
  return `${lineCount.value} 行 · 只读${selection.value ? ` · 已选 ${selection.value.startLine}–${selection.value.endLine} 行` : ''}`
})

function publishSelection(value: CodeSelection | null): void {
  selection.value = value
  emit('selectionChange', value)
}
function readSelection(): void {
  const selected = editor.value?.getSelection()
  const current = model.value
  if (blocked.value || !selected || selected.isEmpty() || !current) return publishSelection(null)
  const endLine = selected.endColumn === 1 && selected.endLineNumber > selected.startLineNumber
    ? selected.endLineNumber - 1 : selected.endLineNumber
  publishSelection({ startLine: selected.startLineNumber, endLine, text: current.getValueInRange(selected) })
}
function readFallbackSelection(): void {
  const host = fallbackSource.value
  const selected = window.getSelection()
  if (blocked.value || !showFallback.value || !host || !selected?.rangeCount || selected.isCollapsed) {
    if (showFallback.value) publishSelection(null)
    return
  }
  const range = selected.getRangeAt(0)
  if (!host.contains(range.startContainer) || !host.contains(range.endContainer)) return
  const prefix = range.cloneRange()
  prefix.selectNodeContents(host)
  prefix.setEnd(range.startContainer, range.startOffset)
  const startLine = prefix.toString().split('\n').length
  const text = selected.toString()
  const endLine = startLine + text.replace(/\n$/, '').split('\n').length - 1
  publishSelection(text ? { startLine, endLine, text } : null)
}
function saveViewState(): void {
  if (!currentUri) return
  const monaco = model.value ? editor.value?.saveViewState() : undefined
  const host = fallbackSource.value
  sourceViewStates.set(currentUri, {
    ...sourceViewStates.get(currentUri),
    ...(monaco ? { monaco } : {}),
    ...(host ? { fallbackTop: host.scrollTop, fallbackLeft: host.scrollLeft } : {}),
  })
}
function restoreViewState(): void {
  const cached = sourceViewStates.get(currentUri)
  if (cached?.monaco && editor.value) editor.value.restoreViewState(cached.monaco)
  else {
    editor.value?.setPosition({ lineNumber: 1, column: 1 })
    editor.value?.setScrollPosition({ scrollTop: 0, scrollLeft: 0 })
  }
  if (fallbackSource.value) {
    fallbackSource.value.scrollTop = cached?.fallbackTop ?? 0
    fallbackSource.value.scrollLeft = cached?.fallbackLeft ?? 0
  }
}
function clearDecorations(): void {
  if (editor.value) targetDecorations = editor.value.deltaDecorations(targetDecorations, [])
}
function revealLines(startLine: number, endLine = startLine): void {
  if (blocked.value) return
  const start = Math.max(1, Math.min(lineCount.value, Math.trunc(startLine) || 1))
  const end = Math.max(start, Math.min(lineCount.value, Math.trunc(endLine) || start))
  if (editor.value && model.value) {
    const range = model.value.validateRange({ startLineNumber: start, startColumn: 1, endLineNumber: end, endColumn: model.value.getLineMaxColumn(end) })
    targetDecorations = editor.value.deltaDecorations(targetDecorations, [{ range, options: { isWholeLine: true, className: 'source-target-line' } }])
    editor.value.setSelection(range)
    editor.value.revealRangeInCenter(range)
  } else if (fallbackSource.value) {
    const lineHeight = Number.parseFloat(getComputedStyle(fallbackSource.value).lineHeight) || 20
    fallbackSource.value.scrollTop = Math.max(0, (start - 1) * lineHeight - fallbackSource.value.clientHeight / 3)
    fallbackSource.value.focus({ preventScroll: true })
  }
}
function applyTargetRange(): void {
  const target = props.targetRange
  if (!target || target.reveal === false) { targetRevealGuard.reset(); clearDecorations(); return }
  if (blocked.value || currentUri !== requestedUri.value) return
  const key = `${currentUri}:${target.startLine}:${target.startColumn}:${target.endLine}:${target.endColumn}`
  if (!targetRevealGuard.accept(key)) return
  if (editor.value && model.value) {
    const range = model.value.validateRange({ startLineNumber: target.startLine, startColumn: target.startColumn, endLineNumber: target.endLine, endColumn: target.endColumn })
    targetDecorations = editor.value.deltaDecorations(targetDecorations, [{ range, options: { isWholeLine: true, className: 'source-target-line', inlineClassName: 'source-target-inline' } }])
    editor.value.setSelection(range)
    editor.value.revealRangeInCenter(range)
  } else revealLines(target.startLine, target.endLine)
}
function syncSource(): void {
  if (blocked.value) return
  const changed = currentUri !== requestedUri.value
  if (changed) {
    if (!pendingViewSaved) saveViewState()
    clearDecorations()
    const previous = model.value
    currentUri = requestedUri.value
    targetRevealGuard.reset()
    if (monacoModule.value && editor.value) {
      const next = monacoModule.value.editor.createModel(props.source, resolveMonacoLanguage(props.language), monacoModule.value.Uri.parse(currentUri))
      model.value = next
      editor.value.setModel(next)
      previous?.dispose()
    }
    restoreViewState()
  } else if (model.value && model.value.getValue() !== props.source) {
    const view = editor.value?.saveViewState()
    model.value.setValue(props.source)
    if (view) editor.value?.restoreViewState(view)
  }
  if (model.value && monacoModule.value) monacoModule.value.editor.setModelLanguage(model.value, resolveMonacoLanguage(props.language))
  pendingViewSaved = false
  editor.value?.layout()
  applyTargetRange()
}
async function mountEditor(): Promise<void> {
  if (!supportsMonacoRuntime()) { syncSource(); return }
  state.value = 'loading'
  try {
    const monaco = await loadMonacoEditor()
    await nextTick()
    if (disposed || !editorHost.value) return
    monacoModule.value = monaco
    editor.value = monaco.editor.create(editorHost.value, {
      model: null, readOnly: true, domReadOnly: true, automaticLayout: true,
      ariaLabel: props.label, minimap: { enabled: false }, overviewRulerLanes: 0,
      renderLineHighlight: 'line', scrollBeyondLastLine: false, smoothScrolling: true,
      wordWrap: 'on', wrappingIndent: 'same', fontFamily: '"IBM Plex Mono", "SFMono-Regular", Consolas, monospace',
      fontSize: 13, lineHeight: 21, lineNumbersMinChars: 3, folding: true,
      padding: { top: 14, bottom: 18 }, find: { addExtraSpaceOnTop: false, seedSearchStringFromSelection: 'always' },
    })
    cursorSubscription = editor.value.onDidChangeCursorSelection(readSelection)
    state.value = 'ready'
    // The fallback may already have a URI; force an initial model without losing its saved viewport.
    if (!pendingViewSaved) saveViewState()
    currentUri = ''
    syncSource()
  } catch {
    if (disposed) return
    state.value = 'error'
    await nextTick()
    syncSource()
  }
}
function focusSearch(): void {
  if (blocked.value) return
  if (editor.value) { editor.value.focus(); void editor.value.getAction('actions.find')?.run() }
  else fallbackSource.value?.focus({ preventScroll: true })
}
function focusEditor(): void {
  const input = editor.value?.getDomNode()?.querySelector<HTMLTextAreaElement>('textarea.inputarea, textarea')
  if (input) input.focus({ preventScroll: true })
  else fallbackSource.value?.focus({ preventScroll: true })
}
async function openGoToLine(): Promise<void> {
  if (blocked.value) return
  jumpOpen.value = true
  jumpError.value = ''
  await nextTick()
  lineInput.value?.focus({ preventScroll: true })
  lineInput.value?.select()
}
function goToLine(): void {
  const line = Number(jumpLine.value)
  if (!Number.isInteger(line) || line < 1 || line > lineCount.value) {
    jumpError.value = `请输入 1–${lineCount.value} 的行号`
    return
  }
  revealLines(line)
  jumpOpen.value = false
  focusEditor()
}
function handleKeys(event: KeyboardEvent): void {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'g') {
    event.preventDefault(); event.stopPropagation(); void openGoToLine()
  }
}
async function copyCode(selectedOnly: boolean): Promise<void> {
  if (blocked.value) return
  const selected = selectedOnly ? selection.value : null
  if (selectedOnly && !selected) return
  const text = formatCodeCopy(selected?.text ?? props.source, { filename: props.filename || props.label, includeFilename: copyFilename.value, includeLineNumbers: copyLineNumbers.value, startLine: selected?.startLine ?? 1 })
  try {
    if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(text)
    else {
      const field = document.createElement('textarea')
      field.value = text; field.style.position = 'fixed'; field.style.opacity = '0'
      const previous = document.activeElement as HTMLElement | null
      document.body.append(field)
      field.focus({ preventScroll: true }); field.select()
      const copied = document.execCommand('copy')
      field.remove(); previous?.focus({ preventScroll: true })
      if (!copied) throw new Error('copy failed')
    }
    copyMessage.value = selected ? '已复制所选片段' : '已复制全文'
  } catch { copyMessage.value = '复制失败，请选中代码后使用系统复制快捷键' }
}
// Snapshot the old viewport before Vue clears fallback text or covers a pending file.
watch(() => [props.loading, props.available, props.error, requestedUri.value], () => {
  if (currentUri && !pendingViewSaved && (blocked.value || currentUri !== requestedUri.value)) {
    saveViewState()
    pendingViewSaved = true
  }
}, { flush: 'sync' })
watch(() => [props.modelUri, props.source, props.language, props.loading, props.available, props.error], () => {
  if (blocked.value || currentUri !== requestedUri.value) publishSelection(null)
  copyMessage.value = ''
  syncSource()
}, { flush: 'post' })
watch(() => props.targetRange, () => {
  // A fresh explicit request must reveal its target again, even if the reader
  // scrolled away after an earlier request with exactly the same coordinates.
  targetRevealGuard.reset()
  applyTargetRange()
}, { deep: true, flush: 'post' })
watch(() => props.label, label => editor.value?.updateOptions({ ariaLabel: label }))
onMounted(() => {
  fallbackSelectionListener = readFallbackSelection
  document.addEventListener('selectionchange', fallbackSelectionListener)
  void mountEditor()
})
onScopeDispose(() => {
  disposed = true
  if (!pendingViewSaved) saveViewState()
  if (fallbackSelectionListener) document.removeEventListener('selectionchange', fallbackSelectionListener)
  cursorSubscription?.dispose()
  clearDecorations()
  editor.value?.dispose()
  model.value?.dispose()
})
defineExpose({ revealLines, openGoToLine, focusSearch, focusEditor })
</script>

<template>
  <div class="read-only-editor" :data-editor-state="state" :aria-busy="loading" @keydown.capture="handleKeys">
    <div class="read-only-editor__toolbar">
      <span class="read-only-editor__status" role="status" aria-live="polite">{{ statusText }}</span>
      <div class="editor-commands">
        <button type="button" :disabled="blocked" title="在代码中查找" @click="focusSearch"><Search :size="14" />查找</button>
        <button type="button" :disabled="blocked" title="跳转到行（Ctrl / ⌘ G）" @click="openGoToLine"><Hash :size="14" />跳行</button>
        <button type="button" :disabled="blocked" @click="copyCode(false)"><Copy :size="14" />复制全文</button>
        <button type="button" :disabled="blocked || !selection" @click="copyCode(true)">复制所选</button>
        <label><input v-model="copyFilename" type="checkbox" />文件名</label>
        <label><input v-model="copyLineNumbers" type="checkbox" />行号</label>
      </div>
    </div>
    <div class="read-only-editor__stage">
      <div ref="editorHost" class="read-only-editor__host" :class="{ 'editor-hidden': blocked }" :aria-hidden="state !== 'ready' || blocked" :inert="blocked" />
      <pre v-if="showFallback" ref="fallbackSource" class="code-panel__source" :class="{ 'editor-hidden': blocked }" tabindex="0" :aria-label="label" :aria-hidden="blocked" :inert="blocked"><code>{{ blocked ? '' : source }}</code></pre>
      <div v-if="blocked" class="editor-overlay" :role="error ? 'alert' : 'status'">
        <LoaderCircle v-if="loading" :size="22" class="spin" aria-hidden="true" />
        <TriangleAlert v-else-if="error" :size="22" aria-hidden="true" />
        <strong>{{ loading ? '正在读取源码，请稍候' : (error || '该项目暂时没有可阅读的源码文件') }}</strong>
      </div>
      <form v-if="jumpOpen && !blocked" class="jump-dialog" aria-label="跳转到代码行" @submit.prevent="goToLine" @keydown.esc="jumpOpen = false">
        <label for="source-line-number">跳转到行（1–{{ lineCount }}）</label>
        <div><input id="source-line-number" ref="lineInput" v-model="jumpLine" type="number" min="1" :max="lineCount" /><button type="submit">跳转</button><button type="button" @click="jumpOpen = false">取消</button></div>
        <span v-if="jumpError" role="alert">{{ jumpError }}</span>
      </form>
    </div>
    <p class="editor-feedback" role="status" aria-live="polite">{{ copyMessage || (state === 'error' ? '编辑器增强功能不可用；当前使用安全只读文本，支持跳行与复制。' : 'Ctrl / ⌘ G 跳行 · 选中代码可复制或请求 AI 解释') }}</p>
  </div>
</template>

<style scoped>
.read-only-editor { display: flex; flex-direction: column; width: 100%; min-width: 0; height: 100%; min-height: 360px; overflow: hidden; background: var(--surface); }
.read-only-editor__toolbar { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; padding: 9px 12px; border-bottom: 1px solid var(--line); background: var(--surface-raised); }
.read-only-editor__status { color: var(--ink-600); font-size: 12px; }
.editor-commands { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
.editor-commands button, .jump-dialog button { display: inline-flex; min-height: 30px; align-items: center; gap: 4px; padding: 4px 8px; border: 1px solid var(--line-strong); border-radius: 6px; color: var(--ink-700); background: var(--surface); font: inherit; font-size: 12px; cursor: pointer; }
.editor-commands button:hover:not(:disabled), .jump-dialog button:hover { color: var(--primary); border-color: var(--primary); background: var(--primary-soft); }
.editor-commands button:disabled { opacity: .5; cursor: not-allowed; }
.editor-commands label { display: inline-flex; gap: 3px; align-items: center; color: var(--ink-600); font-size: 11px; white-space: nowrap; }
.editor-commands input { accent-color: var(--primary); }
.read-only-editor__stage { position: relative; flex: 1; width: 100%; min-width: 0; min-height: 260px; overflow: hidden; }
.read-only-editor__host { position: absolute; inset: 0; width: 100%; height: 100%; }
.editor-hidden { visibility: hidden; }
.read-only-editor__host :deep(.source-target-line) { background: rgb(245 158 11 / 12%); box-shadow: inset 3px 0 0 var(--warning); }
.read-only-editor__host :deep(.source-target-inline) { border-bottom: 1px solid var(--warning); background: rgb(245 158 11 / 15%); }
.code-panel__source { position: absolute; inset: 0; margin: 0; overflow: auto; padding: 14px 18px; color: var(--ink-800); background: var(--surface); font: 13px/21px "IBM Plex Mono", Consolas, monospace; tab-size: 4; white-space: pre; }
.editor-overlay { position: absolute; inset: 0; z-index: 2; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px; padding: 24px; color: var(--ink-600); background: var(--surface); text-align: center; }
.editor-overlay strong { max-width: 520px; font-size: 13px; overflow-wrap: anywhere; }
.editor-overlay[role="alert"] { color: var(--danger); }
.jump-dialog { position: absolute; z-index: 4; top: 12px; right: 16px; width: min(330px, calc(100% - 32px)); padding: 14px; border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--surface); box-shadow: var(--shadow-panel); color: var(--ink-700); font-size: 12px; }
.jump-dialog div { display: flex; gap: 6px; margin-top: 8px; }
.jump-dialog input { min-width: 0; width: 100%; padding: 5px 8px; border: 1px solid var(--line-strong); border-radius: 6px; font: inherit; }
.jump-dialog span { display: block; margin-top: 6px; color: var(--danger); }
.editor-feedback { min-height: 29px; flex-shrink: 0; margin: 0; padding: 6px 12px; border-top: 1px solid var(--line); color: var(--ink-600); background: var(--surface-raised); font-size: 11px; line-height: 17px; }
.spin { animation: source-spinner 1s linear infinite; }
@keyframes source-spinner { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spin { animation: none; } }
</style>
