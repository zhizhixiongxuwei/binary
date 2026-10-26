<script setup lang="ts">
import { computed, nextTick, onMounted, onScopeDispose, shallowRef, useTemplateRef, watch } from 'vue'
import { ChevronDown, ChevronRight, ChevronUp, Copy, RefreshCw, Sparkles, Square, X } from 'lucide-vue-next'

import type { ExplanationRecord, SourceSelection } from '@/api/llmTypes'
import { isDemoMode } from '@/api/runtime'
import { explanationBlocks, explanationLineParts } from '@/components/tasks/results/explanationText'
import { clampExplanationWidth, explanationMaximumWidth, explanationWidthPreference, EXPLANATION_DEFAULT_WIDTH } from '@/components/tasks/results/explanationPanelLayout'
import { useAIExplanation } from '@/composables/useAIExplanation'
import { useSessionStore } from '@/stores/session'

const props = withDefaults(defineProps<{
  open: boolean; taskId: string; projectId: string; fileId: string; sourceSha256?: string | undefined
  source: string; filename: string; lineCount: number; loading: boolean; selection: SourceSelection | null
  embedded?: boolean; paneVisible?: boolean; availableWidth?: number; resizable?: boolean
}>(), { embedded: false, paneVisible: true, resizable: true })
const emit = defineEmits<{ 'update:open': [value: boolean]; navigate: [value: { startLine: number; endLine: number }]; resize: [width: number] }>()
const session = useSessionStore()
const model = useAIExplanation({ source: () => props, open: () => props.open, role: () => session.user?.role ?? null })
const folded = shallowRef(false)
const copyFeedback = shallowRef('')
const panel = useTemplateRef<HTMLElement>('panel')
const widthPreference = 'binaryscan.ai-explanation.width'
const preferredWidth = shallowRef(EXPLANATION_DEFAULT_WIDTH)
const viewportWidth = shallowRef(typeof window === 'undefined' ? 1280 : window.innerWidth)
const maxWidth = computed(() => explanationMaximumWidth(props.availableWidth ?? viewportWidth.value - 32))
const panelWidth = computed(() => clampExplanationWidth(preferredWidth.value, maxWidth.value))
const resizing = shallowRef(false)
let dragStartX = 0
let dragStartWidth = 480
let previousFocus: HTMLElement | null = null
const selected = computed(() => model.current.value.selected)
const blocks = computed(() => explanationBlocks(selected.value?.text ?? ''))
const sourceLines = computed(() => props.source.split('\n').length)
const stale = (record: ExplanationRecord) => Boolean(record.stale || (props.sourceSha256 && record.sourceSha256 && props.sourceSha256 !== record.sourceSha256))
const isStale = computed(() => selected.value ? stale(selected.value) : false)
const provider = computed(() => model.status.value?.provider === 'deepseek' ? 'DeepSeek' : model.status.value?.provider || '未配置')
const preview = computed(() => model.range.value.text.slice(0, 6000))
const historyLabel = (record: ExplanationRecord) => `${record.scope === 'file' ? '整文件' : `L${record.startLine}–L${record.endLine}`} · ${record.model} · ${new Date(record.createdAt).toLocaleString('zh-CN')}${stale(record) ? ' · 旧版本' : ''}`
const statusLabels = { generating: '生成中', completed: '已完成', cancelled: '已停止 · 保留部分内容', failed: '生成失败 · 保留部分内容' }

watch(() => [props.open, props.paneVisible] as const, async ([open, visible], previous) => {
  if (open && !previous?.[0]) {
    previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    folded.value = false
  }
  if (open && visible) {
    await nextTick()
    if (props.open && props.paneVisible) panel.value?.focus({ preventScroll: true })
  } else if (!open && previous?.[0] && previousFocus?.isConnected) previousFocus.focus({ preventScroll: true })
}, { immediate: true })
watch(() => [props.taskId, props.projectId, props.fileId], () => { copyFeedback.value = '' })
watch(panelWidth, width => emit('resize', width))

async function copy(): Promise<void> {
  if (!selected.value?.text) return
  try {
    if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(selected.value.text)
    else {
      const field = document.createElement('textarea')
      field.value = selected.value.text
      field.style.position = 'fixed'
      field.style.opacity = '0'
      const previous = document.activeElement as HTMLElement | null
      document.body.append(field)
      try {
        field.focus({ preventScroll: true }); field.select()
        if (!document.execCommand('copy')) throw new Error('copy failed')
      } finally { field.remove(); previous?.focus({ preventScroll: true }) }
    }
    copyFeedback.value = '已复制解释'
  }
  catch { copyFeedback.value = '浏览器未开放剪贴板，请选择解释文本手动复制。' }
}
function navigate(startLine: number, endLine: number): void {
  if (!isStale.value) emit('navigate', { startLine, endLine })
}
function setWidth(value: number): void { preferredWidth.value = clampExplanationWidth(value, maxWidth.value) }
function saveWidth(): void { try { localStorage.setItem(widthPreference, String(preferredWidth.value)) } catch { /* UI preference storage may be unavailable. */ } }
function startResize(event: PointerEvent): void {
  if (event.button !== 0 || !props.resizable) return
  event.preventDefault()
  dragStartX = event.clientX
  dragStartWidth = panelWidth.value
  resizing.value = true
  ;(event.currentTarget as HTMLElement).setPointerCapture(event.pointerId)
}
function resize(event: PointerEvent): void { if (resizing.value) setWidth(dragStartWidth + dragStartX - event.clientX) }
function finishResize(): void { if (resizing.value) { resizing.value = false; saveWidth() } }
function resizeWithKeyboard(event: KeyboardEvent): void {
  if (!props.resizable || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
  event.preventDefault()
  setWidth(event.key === 'Home' ? 280 : event.key === 'End' ? maxWidth.value : panelWidth.value + (event.key === 'ArrowLeft' ? 24 : -24))
  saveWidth()
}
function foldPanel(): void {
  if (props.embedded) emit('update:open', false)
  else folded.value = !folded.value
}
function windowResized(): void { viewportWidth.value = window.innerWidth }
onMounted(() => {
  try { preferredWidth.value = explanationWidthPreference(localStorage.getItem(widthPreference)) } catch { /* Keep the default width. */ }
  emit('resize', panelWidth.value)
  window.addEventListener('resize', windowResized)
})
onScopeDispose(() => { window.removeEventListener('resize', windowResized) })
</script>

<template>
  <Teleport to="body" :disabled="embedded">
    <aside v-if="open" v-show="paneVisible" ref="panel" class="ai-panel" :class="{ 'ai-panel--embedded': embedded, 'ai-panel--folded': folded, 'ai-panel--resizing': resizing }" :style="{ '--ai-panel-width': `${panelWidth}px` }" role="complementary" aria-label="AI 源码解释" tabindex="-1" @keydown.esc.stop="emit('update:open', false)">
      <div v-if="resizable" v-show="!folded" class="ai-resize-handle" role="separator" aria-label="调整 AI 解释面板宽度" aria-orientation="vertical" :aria-valuemin="280" :aria-valuemax="maxWidth" :aria-valuenow="panelWidth" tabindex="0" title="拖动调整宽度；左右方向键微调" @pointerdown="startResize" @pointermove="resize" @pointerup="finishResize" @pointercancel="finishResize" @lostpointercapture="finishResize" @keydown="resizeWithKeyboard" />
      <header class="ai-panel__header">
        <div><Sparkles :size="19" /><strong>AI 源码解释</strong><span v-if="model.generating.value">生成中</span></div>
        <button type="button" :aria-label="embedded ? '收起解释面板' : folded ? '展开解释面板' : '折叠解释面板'" :title="embedded ? '收起解释面板并停止生成' : folded ? '展开解释面板' : '折叠解释面板'" :aria-expanded="!folded" @click="foldPanel"><ChevronRight v-if="embedded" :size="18" /><ChevronDown v-else-if="folded" :size="18" /><ChevronUp v-else :size="18" /></button>
        <button type="button" aria-label="关闭 AI 解释" title="关闭并停止生成" @click="emit('update:open', false)"><X :size="18" /></button>
      </header>
      <div v-show="!folded" class="ai-panel__body">
        <p class="ai-file" :title="filename">{{ filename || '尚未选择源码文件' }}</p>
        <p v-if="isDemoMode" class="ai-note">界面预览：仅生成内存示例，不会向外部服务发送代码。</p>
        <template v-if="model.canGenerate.value">
          <section class="ai-request" aria-label="代码发送范围确认">
            <div class="ai-section-heading"><h3>确认发送范围</h3><button type="button" class="ai-text-button" :disabled="model.generating.value || model.statusLoading.value" @click="model.refreshStatus"><RefreshCw :size="13" />刷新服务</button></div>
            <dl class="ai-destination"><div><dt>接收服务</dt><dd>{{ provider }} · {{ model.status.value?.model || '未配置' }}</dd></div><div><dt>接口地址</dt><dd>{{ model.status.value?.baseUrl || '尚未读取' }}</dd></div></dl>
            <fieldset class="ai-scope" :disabled="model.generating.value || loading"><legend class="sr-only">解释范围</legend><label><input v-model="model.scope.value" type="radio" value="file">当前文件</label><label><input v-model="model.scope.value" type="radio" value="selection" :disabled="!selection">所选行</label></fieldset>
            <p class="ai-range">L{{ model.range.value.startLine }}–L{{ model.range.value.endLine }} · {{ model.range.value.chars.toLocaleString() }} 字符<span v-if="model.status.value"> / 上限 {{ model.status.value.maxInputChars.toLocaleString() }}</span></p>
            <p v-if="model.scope.value === 'selection'" class="ai-help">按所选起止行发送完整代码行；选区变化后请重新核对。</p>
            <details class="ai-preview"><summary>查看将发送的源码{{ model.range.value.text.length > 6000 ? '（预览前 6,000 字符）' : '' }}</summary><pre>{{ preview || '暂无可发送内容' }}</pre></details>
            <p class="ai-help">确认后，服务端会将上述范围的源码发送至此接口。解释用于辅助理解，推断请结合源码验证。</p>
            <p v-if="model.blockedReason.value" class="ai-note">{{ model.blockedReason.value }}<RouterLink v-if="session.user?.role === 'administrator' && !loading && (!model.status.value?.enabled || !model.status.value.configured)" :to="{ name: 'system' }" @click="emit('update:open', false)">前往系统维护 → 大模型设置</RouterLink></p>
            <div class="ai-actions">
              <el-button v-if="model.generating.value" :icon="Square" type="danger" plain @click="model.stop">停止生成</el-button>
              <template v-else>
                <el-button type="primary" :icon="Sparkles" :disabled="Boolean(model.blockedReason.value)" @click="model.generate()">{{ model.current.value.phase === 'failed' || model.current.value.phase === 'cancelled' ? '确认发送并重试' : '确认发送并生成' }}</el-button>
                <el-button v-if="selected?.status === 'completed'" :disabled="Boolean(model.blockedReason.value)" @click="model.generate(true)">确认重新生成</el-button>
              </template>
            </div>
          </section>
        </template>
        <p v-else class="ai-note">只读账号可查看历史解释，生成解释请联系管理员或操作员。</p>
        <section class="ai-history" aria-label="解释历史">
          <div class="ai-section-heading"><h3>解释历史</h3><button type="button" class="ai-text-button" :disabled="model.current.value.historyLoading || model.generating.value" @click="model.refreshHistory"><RefreshCw :size="13" />刷新历史</button></div>
          <select v-if="model.current.value.history.length" class="ai-history-select" aria-label="选择历史解释" :value="selected?.id" :disabled="model.generating.value" @change="model.selectHistory(($event.target as HTMLSelectElement).value)"><option v-for="record in model.current.value.history" :key="record.id" :value="record.id">{{ historyLabel(record) }}</option></select>
          <p v-if="model.current.value.historyLoading" class="ai-help" role="status">正在读取历史解释…</p>
          <p v-if="model.current.value.historyError" class="ai-error" role="alert">{{ model.current.value.historyError }}</p>
          <p v-if="!selected && !model.current.value.historyLoading" class="ai-empty">暂无解释。生成后可在这里查看历史结果。</p>
        </section>
        <p v-if="model.current.value.error" class="ai-error" role="alert">{{ model.current.value.error }}</p>
        <section v-if="selected" class="ai-result" aria-label="源码解释结果" :aria-busy="model.generating.value">
          <div class="ai-section-heading"><h3>{{ statusLabels[selected.status] }}</h3><button type="button" class="ai-text-button" :disabled="!selected.text" @click="copy"><Copy :size="14" />复制</button></div>
          <p class="ai-result__meta">{{ selected.provider }} · {{ selected.model }}<br>{{ new Date(selected.createdAt).toLocaleString('zh-CN') }} · L{{ selected.startLine }}–L{{ selected.endLine }}<span v-if="selected.cacheHit" class="ai-cache">缓存命中</span></p>
          <p v-if="isStale" class="ai-note">这是旧版本源码的解释，行号跳转已停用；请为当前源码重新生成。</p>
          <p v-if="copyFeedback" class="ai-help" role="status">{{ copyFeedback }}</p>
          <p v-if="!selected.text && model.generating.value" class="ai-empty" role="status">正在等待模型响应…</p>
          <div class="ai-explanation-text">
            <template v-for="(block, index) in blocks" :key="index">
              <pre v-if="block.kind === 'code'" class="ai-code">{{ block.text }}</pre>
              <component :is="block.kind === 'heading' ? 'h4' : 'p'" v-else :class="{ 'ai-bullet': block.kind === 'bullet' }">
                <template v-for="(part, partIndex) in explanationLineParts(block.text, sourceLines)" :key="partIndex"><button v-if="part.startLine && part.endLine" type="button" class="ai-line-link" :disabled="isStale || loading" :aria-label="`定位源码 ${part.text}`" @click="navigate(part.startLine, part.endLine)">{{ part.text }}</button><span v-else>{{ part.text }}</span></template>
              </component>
            </template>
          </div>
        </section>
      </div>
    </aside>
  </Teleport>
</template>

<style scoped>
.ai-panel { position: fixed; z-index: 2100; top: 76px; right: 16px; bottom: 16px; display: flex; width: min(var(--ai-panel-width, 480px), calc(100vw - 32px)); min-height: 0; flex-direction: column; overflow: hidden; border: 1px solid var(--line-strong); border-radius: 16px; background: var(--surface); box-shadow: 0 16px 56px rgb(15 23 42 / 22%); outline: none; }
.ai-panel--embedded { position: relative; z-index: auto; inset: auto; width: 100%; height: 100%; min-width: 0; border: 0; border-left: 1px solid var(--line); border-radius: 0; box-shadow: none; }
.ai-panel--embedded .ai-resize-handle { top: 0; }
.ai-resize-handle { position: absolute; z-index: 1; inset: 62px auto 0 0; width: 7px; cursor: ew-resize; touch-action: none; }.ai-resize-handle:hover, .ai-resize-handle:focus-visible { background: var(--primary-border); }.ai-panel--resizing { user-select: none; }
.ai-panel--folded { bottom: auto; }
.ai-panel__header { display: flex; flex: 0 0 auto; align-items: center; gap: 8px; padding: 15px 18px; border-bottom: 1px solid var(--line); }
.ai-panel__header > div { display: flex; min-width: 0; flex: 1; align-items: center; gap: 8px; color: var(--primary); }
.ai-panel__header strong { color: var(--ink-950); font-size: 15px; }.ai-panel__header span { font-size: 11px; }
.ai-panel__header > button { display: grid; width: 30px; height: 30px; place-items: center; border: 0; border-radius: 6px; background: transparent; color: var(--ink-600); cursor: pointer; }
.ai-panel__header > button:hover { background: var(--surface-muted); }
.ai-panel__body { flex: 1; min-height: 0; overflow: auto; overscroll-behavior: contain; padding: 18px; }
.ai-file { margin: 0 0 16px; overflow-wrap: anywhere; color: var(--ink-800); font-size: 13px; font-weight: 600; }
.ai-request, .ai-history, .ai-result { margin-bottom: 18px; }.ai-request { padding-bottom: 18px; border-bottom: 1px solid var(--line); }
.ai-section-heading { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 12px; }.ai-section-heading h3 { margin: 0; font-size: 13px; color: var(--ink-800); }
.ai-text-button { display: inline-flex; align-items: center; gap: 5px; padding: 3px 0; border: 0; background: transparent; color: var(--primary); font-size: 12px; cursor: pointer; }
button:disabled { opacity: .5; cursor: not-allowed; }.ai-destination { margin: 0; padding: 12px; border-radius: 8px; background: var(--surface-raised); font-size: 12px; }.ai-destination div { display: grid; grid-template-columns: 60px minmax(0, 1fr); gap: 10px; }.ai-destination div + div { margin-top: 7px; }.ai-destination dt { color: var(--ink-500); }.ai-destination dd { margin: 0; color: var(--ink-800); overflow-wrap: anywhere; }
.ai-scope { display: flex; gap: 18px; margin: 15px 0 10px; padding: 0; border: 0; font-size: 13px; }.ai-scope label { display: flex; gap: 6px; align-items: center; }.ai-scope input { accent-color: var(--primary); }.ai-range { color: var(--ink-800); font-size: 12px; }.ai-range span { color: var(--ink-500); }
.ai-preview { padding: 10px 12px; border: 1px solid var(--line); border-radius: 8px; font-size: 12px; }.ai-preview summary { cursor: pointer; color: var(--ink-700); }.ai-preview pre { max-height: 190px; margin-bottom: 0; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; font: 11px/1.6 Consolas, monospace; color: var(--ink-800); }
.ai-help, .ai-note, .ai-empty, .ai-error, .ai-result__meta { font-size: 12px; line-height: 1.7; overflow-wrap: anywhere; }.ai-help, .ai-empty, .ai-result__meta { color: var(--ink-500); }.ai-note { padding: 10px 12px; border-radius: 8px; color: var(--ink-700); background: var(--primary-soft); }.ai-note a { display: block; margin-top: 4px; color: var(--primary); }.ai-error { padding: 10px 12px; color: var(--danger); border: 1px solid var(--danger-border); border-radius: 8px; background: var(--danger-soft); }
.ai-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }.ai-actions :deep(.el-button + .el-button) { margin-left: 0; }.ai-actions :deep(.el-button) { font-size: 12px; }
.ai-history-select { width: 100%; padding: 9px; border: 1px solid var(--line-strong); border-radius: 8px; background: var(--surface); color: var(--ink-800); font-size: 12px; }.ai-result { padding-top: 16px; border-top: 1px solid var(--line); }.ai-result__meta { margin-top: 0; }.ai-cache { margin-left: 8px; padding: 2px 5px; border-radius: 4px; color: var(--success); background: var(--success-soft); }
.ai-explanation-text { color: var(--ink-800); font-size: 13px; line-height: 1.85; overflow-wrap: anywhere; }.ai-explanation-text h4 { margin: 20px 0 8px; color: var(--ink-950); font-size: 14px; }.ai-explanation-text p { margin: 8px 0; white-space: pre-wrap; }.ai-bullet { padding-left: 15px; border-left: 2px solid var(--primary-border); }.ai-code { padding: 12px; overflow: auto; border-radius: 8px; background: var(--surface-muted); white-space: pre-wrap; font: 11px/1.7 Consolas, monospace; }.ai-line-link { padding: 0 2px; border: 0; border-bottom: 1px dotted currentColor; color: var(--primary); background: transparent; font: inherit; cursor: pointer; }
@media (max-width: 640px) { .ai-panel:not(.ai-panel--embedded) { inset: 12px 8px; width: auto; border-radius: 12px; }.ai-panel--folded { bottom: auto; }.ai-panel__body { padding: 15px; }.ai-resize-handle { display: none; } }
</style>
