<script setup lang="ts">
import { ChevronRight, Copy, FileCode2, FolderTree, Info, Maximize2, Minimize2, PanelLeftClose, PanelLeftOpen, Sparkles, TriangleAlert, X } from 'lucide-vue-next'
import { computed, nextTick, onMounted, onScopeDispose, shallowRef, useTemplateRef, watch } from 'vue'
import type { DecompileResult, DecompileSourceFile, DecompileSourceFileContent, JsonValue, SourceNavigationTarget } from '@/api/types'
import ReadOnlyCodeEditor from '@/components/code-editor/ReadOnlyCodeEditor.vue'
import type { CodeSelection } from '@/components/code-editor/readingState'
import type { ReadOnlyCodeLanguage } from '@/components/code-editor/monacoLoader'
import AIExplanationPanel from './AIExplanationPanel.vue'
import SourceProjectExplorer from './SourceProjectExplorer.vue'
import BytecodeAnalyzerSummary from './BytecodeAnalyzerSummary.vue'
import BytecodeMethodIndexPanel from './BytecodeMethodIndexPanel.vue'
import { parseAnalyzerSummary } from './analyzerSummary'
import { neutralizeUnsafeDisplayCharacters } from './displayText'
import { parseBytecodeMethodIndex } from './jvmMethodIndex'
import { adjacentSourceTab, rememberSourceTab, sourceTabKey, sourceWorkbenchLayout, type SourceTab } from './sourceWorkspaceState'

const props = defineProps<{
  taskId: string
  items: readonly DecompileResult[]
  selectedId: string
  sourceFiles: readonly DecompileSourceFile[]
  selectedSourceFileId: string
  sourceFile: DecompileSourceFileContent | undefined
  source: string
  sourceFilesLoading: boolean
  sourceFilesError: string
  sourceLoading: boolean
  sourceError: string
  targetRange: SourceNavigationTarget | undefined
  hasMoreResults: boolean
  loadingMoreResults: boolean
}>()
const emit = defineEmits<{
  select: [resultId: string]
  selectSourceFile: [fileId: string]
  loadMoreResults: []
  openSource: [target: SourceNavigationTarget]
}>()

const workspaceRoot = useTemplateRef<HTMLElement>('workspaceRoot')
const splitBody = useTemplateRef<HTMLElement>('splitBody')
const explorer = useTemplateRef<InstanceType<typeof SourceProjectExplorer>>('explorer')
const codeEditor = useTemplateRef<InstanceType<typeof ReadOnlyCodeEditor>>('codeEditor')
const focusButton = useTemplateRef<HTMLButtonElement>('focusButton')
const tabStrip = useTemplateRef<HTMLElement>('tabStrip')
const readingFocus = shallowRef(false)
const directoryOpen = shallowRef(true)
const aiOpen = shallowRef(false)
const activePane = shallowRef<'code' | 'ai'>('code')
const selection = shallowRef<CodeSelection | null>(null)
const directoryWidth = shallowRef(260)
const aiWidth = shallowRef(400)
const workspaceWidth = shallowRef(1000)
const copyFeedback = shallowRef('')
const tabs = shallowRef<SourceTab[]>([])
const selectedBytecodeMethodKey = shallowRef('')
const selectedResult = computed(() => props.items.find(item => item.id === props.selectedId))
const selectedSourceFile = computed(() => props.sourceFiles.find(file => file.id === props.selectedSourceFileId))
const currentTabKey = computed(() => sourceTabKey({ projectId: props.selectedId, fileId: props.selectedSourceFileId }))
const layout = computed(() => sourceWorkbenchLayout(workspaceWidth.value, directoryOpen.value, aiOpen.value, directoryWidth.value, aiWidth.value))
const columns = computed(() => {
  const parts: string[] = []
  if (directoryOpen.value && !layout.value.compact) parts.push(layout.value.directoryWidth + 'px', '6px')
  parts.push('minmax(0, 1fr)')
  if (layout.value.docked) parts.push(layout.value.aiWidth + 'px')
  return parts.join(' ')
})
const codeVisible = computed(() => !aiOpen.value || layout.value.docked || activePane.value === 'code')
const aiVisible = computed(() => aiOpen.value && (layout.value.docked || activePane.value === 'ai'))
const directoryVisible = computed(() => directoryOpen.value && (!layout.value.compact || activePane.value === 'code'))
const directoryMaximum = computed(() => Math.max(180, Math.min(360, workspaceWidth.value - 400)))
const pathParts = computed(() => (selectedSourceFile.value?.logicalPath || '').replace(/\\/g, '/').split('/').filter(Boolean))
const statusLabels: Record<string, string> = { complete: '已完成', partial: '部分输出', bytecode_only: '字节码', unsupported: '暂不支持', failed: '失败', cancelled: '已取消', queued: '排队中', running: '处理中' }
const statusLabel = computed(() => statusLabels[selectedResult.value?.status || ''] || '未选择')
const editorModelUri = computed(() => 'binaryscan-source:///' + [props.taskId, props.selectedId || 'project', props.selectedSourceFileId || 'file'].map(encodeURIComponent).join('/'))
const bytecodeMethodIndex = computed(() => parseBytecodeMethodIndex(selectedResult.value?.diagnostics))
const analyzerSummary = computed(() => parseAnalyzerSummary(selectedResult.value?.diagnostics))
const activeBytecodeMethodKey = computed(() => bytecodeMethodIndex.value.methods.some(method => method.key === selectedBytecodeMethodKey.value) ? selectedBytecodeMethodKey.value : bytecodeMethodIndex.value.methods[0]?.key ?? '')
const isJvmBytecodeResult = computed(() => /java.*bytecode/i.test(selectedResult.value?.language ?? ''))
const editorLanguage = computed<ReadOnlyCodeLanguage>(() => {
  const language = (selectedSourceFile.value?.language ?? selectedResult.value?.language ?? '').trim().toLowerCase()
  if (language.includes('java') && language.includes('bytecode')) return 'jvm-bytecode'
  if (language.includes('java')) return 'java'
  if (language.includes('smali') || language.includes('dex')) return 'smali'
  if (language.includes('pyc') || language.includes('python-bytecode')) return 'python-bytecode'
  if (language.includes('python') || language === 'py') return 'python'
  return 'c'
})
const languageLabel = computed(() => ({ 'jvm-bytecode': 'JVM 字节码', java: 'Java', smali: 'Smali', 'python-bytecode': 'Python 字节码', python: 'Python', c: '伪 C' })[editorLanguage.value])
const capabilityMessage = computed(() => {
  switch (selectedResult.value?.status) {
    case 'partial': return '仅生成部分输出，符号、类型或控制流可能缺失。'
    case 'bytecode_only': return '当前为字节码视图，未恢复为高层语言。'
    case 'unsupported': return '当前分析器暂不支持该输入。'
    case 'failed': return '反编译失败，请展开详情查看分析器诊断。'
    case 'cancelled': return '反编译已取消，已保存的输出仍可阅读。'
    case 'queued': return '反编译排队中，暂时没有源码输出。'
    case 'running': return '反编译处理中，结果可能继续更新。'
    default: return '反编译输出不是原始源码；变量名、类型和控制流可能失真。'
  }
})
const diagnosticMessage = computed(() => {
  const value: JsonValue | undefined = selectedResult.value?.diagnostics
  let text = typeof value === 'string' ? value : ''
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const record = value as Readonly<Record<string, JsonValue>>
    for (const field of ['message', 'warning', 'limitation', 'detail']) {
      const candidate = record[field]
      if (typeof candidate === 'string' && candidate.trim()) { text = candidate; break }
    }
  }
  return neutralizeUnsafeDisplayCharacters(text.slice(0, 4096)).trim() + (text.length > 4096 ? '…' : '')
})
const showNotice = computed(() => Boolean(selectedResult.value && selectedResult.value.status !== 'complete'))

let resizeObserver: ResizeObserver | undefined
let dragging = false
let dragX = 0
let dragWidth = 260
let focusScroll = { x: 0, y: 0 }
let focusOrigin: HTMLElement | null = null
let unlockBody: (() => void) | undefined
let disposed = false
const DIRECTORY_WIDTH_KEY = 'binary.source-directory-width.v1'

function setDirectoryWidth(width: number, persist = true): void {
  directoryWidth.value = Math.round(Math.max(180, Math.min(directoryMaximum.value, width)))
  if (persist) { try { localStorage.setItem(DIRECTORY_WIDTH_KEY, String(directoryWidth.value)) } catch { /* UI preferences are optional. */ } }
}
function startResize(event: PointerEvent): void {
  if (event.button !== 0) return
  dragging = true; dragX = event.clientX; dragWidth = layout.value.directoryWidth
  ;(event.currentTarget as HTMLElement).setPointerCapture(event.pointerId)
  event.preventDefault()
}
function resizeDirectory(event: PointerEvent): void { if (dragging) setDirectoryWidth(dragWidth + event.clientX - dragX) }
function resizeWithKeyboard(event: KeyboardEvent): void {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
  event.preventDefault()
  setDirectoryWidth(event.key === 'Home' ? 180 : event.key === 'End' ? directoryMaximum.value : directoryWidth.value + (event.key === 'ArrowRight' ? 1 : -1) * (event.shiftKey ? 40 : 16))
}
async function focusFileSearch(): Promise<void> {
  directoryOpen.value = true; activePane.value = 'code'
  await nextTick(); explorer.value?.focusSearch()
}
function openAI(): void { aiOpen.value = !aiOpen.value; if (aiOpen.value) activePane.value = 'ai' }
function switchPane(value: 'code' | 'ai', focus = false): void {
  activePane.value = value
  if (focus) void nextTick(() => workspaceRoot.value?.querySelector<HTMLButtonElement>(value === 'code' ? '#source-code-tab' : '#source-ai-tab')?.focus({ preventScroll: true }))
}
function selectFileFromExplorer(fileId: string): void {
  emit('selectSourceFile', fileId)
  activePane.value = 'code'
  if (layout.value.compact) directoryOpen.value = false
}
function navigateExplanation(range: { startLine: number; endLine: number }): void {
  activePane.value = 'code'
  void nextTick(() => { codeEditor.value?.revealLines(range.startLine, range.endLine); codeEditor.value?.focusEditor() })
}
function activateTab(tab: SourceTab): void {
  if (sourceTabKey(tab) === currentTabKey.value) return
  activePane.value = 'code'
  emit('openSource', { projectId: tab.projectId, sourceFileId: tab.fileId, path: tab.path, startLine: 1, startColumn: 1, endLine: 1, endColumn: 1, reveal: false })
}
function focusSourceTab(tab: SourceTab): void {
  void nextTick(() => [...(tabStrip.value?.querySelectorAll<HTMLButtonElement>('[data-source-key]') ?? [])].find(button => button.dataset.sourceKey === sourceTabKey(tab))?.focus({ preventScroll: true }))
}
function closeTab(tab: SourceTab): void {
  if (tabs.value.length <= 1) return
  const key = sourceTabKey(tab)
  const next = adjacentSourceTab(tabs.value, key)
  tabs.value = tabs.value.filter(item => sourceTabKey(item) !== key)
  if (key === currentTabKey.value && next) { activateTab(next); focusSourceTab(next) }
}
function closeOtherTabs(): void {
  const current = tabs.value.find(tab => sourceTabKey(tab) === currentTabKey.value)
  if (current) { tabs.value = [current]; focusSourceTab(current) }
}
function tabKeydown(event: KeyboardEvent, tab: SourceTab): void {
  const current = tabs.value.findIndex(item => sourceTabKey(item) === sourceTabKey(tab))
  if (event.key === 'Delete') { event.preventDefault(); closeTab(tab); return }
  let index = current
  if (event.key === 'ArrowRight') index = (current + 1) % tabs.value.length
  else if (event.key === 'ArrowLeft') index = (current - 1 + tabs.value.length) % tabs.value.length
  else if (event.key === 'Home') index = 0
  else if (event.key === 'End') index = tabs.value.length - 1
  else return
  event.preventDefault()
  const target = tabs.value[index]
  if (target) {
    activateTab(target)
    void nextTick(() => tabStrip.value?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[index]?.focus({ preventScroll: true }))
  }
}
async function locateDirectory(index: number): Promise<void> {
  directoryOpen.value = true; activePane.value = 'code'
  await nextTick()
  explorer.value?.locateDirectory(pathParts.value.slice(0, index + 1).join('/'))
}
async function copyPath(): Promise<void> {
  const path = selectedSourceFile.value?.logicalPath
  if (!path) return
  try {
    if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(path)
    else {
      const field = document.createElement('textarea'); field.value = path; field.style.position = 'fixed'; field.style.opacity = '0'
      const previous = document.activeElement as HTMLElement | null
      document.body.append(field); field.focus({ preventScroll: true }); field.select()
      const copied = document.execCommand('copy'); field.remove(); previous?.focus({ preventScroll: true })
      if (!copied) throw new Error('copy failed')
    }
    copyFeedback.value = '路径已复制'
  } catch { copyFeedback.value = '复制失败，请从路径提示中手动复制' }
}
function workspaceKeys(event: KeyboardEvent): void {
  if (!workspaceRoot.value?.getClientRects().length || event.defaultPrevented) return
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'p') { event.preventDefault(); event.stopPropagation(); void focusFileSearch() }
  else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'g') { event.preventDefault(); event.stopPropagation(); activePane.value = 'code'; void nextTick(() => codeEditor.value?.openGoToLine()) }
  else if (event.key === 'Escape' && readingFocus.value) {
    const element = event.target as HTMLElement | null
    // Let menus, editor widgets and nested dialogs consume Escape first.
    if (element?.closest('[role="dialog"], .el-select, .find-widget, .jump-dialog')) return
    readingFocus.value = false
  }
}
function leaveFocus(): void {
  unlockBody?.(); unlockBody = undefined
  window.dispatchEvent(new CustomEvent('binaryscan:reading-focus', { detail: { active: false } }))
  window.scrollTo({ left: focusScroll.x, top: focusScroll.y, behavior: 'instant' })
  if (focusOrigin?.isConnected) focusOrigin.focus({ preventScroll: true })
}
watch(readingFocus, async active => {
  if (active) {
    focusScroll = { x: window.scrollX, y: window.scrollY }
    focusOrigin = document.activeElement instanceof HTMLElement ? document.activeElement : focusButton.value
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'; unlockBody = () => { document.body.style.overflow = previous }
    window.dispatchEvent(new CustomEvent('binaryscan:reading-focus', { detail: { active: true } }))
    await nextTick(); if (readingFocus.value && !disposed) workspaceRoot.value?.focus({ preventScroll: true })
  } else {
    await nextTick(); if (!disposed) leaveFocus()
  }
})
watch(() => [props.taskId, props.selectedId, props.selectedSourceFileId], () => { selection.value = null; copyFeedback.value = '' })
watch(() => props.taskId, () => { tabs.value = []; readingFocus.value = false; activePane.value = 'code' })
watch(() => props.selectedId, () => { selectedBytecodeMethodKey.value = '' })
watch(() => [props.selectedId, props.selectedSourceFileId, selectedSourceFile.value] as const, () => {
  const file = selectedSourceFile.value
  if (!file || file.projectId !== props.selectedId) return
  tabs.value = rememberSourceTab(tabs.value, { projectId: props.selectedId, fileId: file.id, path: file.logicalPath, projectName: selectedResult.value?.display_name || props.selectedId })
  void nextTick(() => {
    const active = tabStrip.value?.querySelector<HTMLElement>('[aria-selected="true"]')
    if (active && tabStrip.value) {
      const host = tabStrip.value
      if (active.offsetLeft < host.scrollLeft) host.scrollLeft = active.offsetLeft
      else if (active.offsetLeft + active.offsetWidth > host.scrollLeft + host.clientWidth) host.scrollLeft = active.offsetLeft + active.offsetWidth - host.clientWidth
    }
  })
}, { immediate: true })
watch(aiOpen, value => { if (!value) activePane.value = 'code' })
watch(() => layout.value.compact, compact => { if (compact) directoryOpen.value = false })
onMounted(() => {
  try { const stored = Number(localStorage.getItem(DIRECTORY_WIDTH_KEY)); if (stored >= 180) directoryWidth.value = stored } catch { /* Keep default width. */ }
  if (splitBody.value) {
    workspaceWidth.value = splitBody.value.clientWidth
    resizeObserver = new ResizeObserver(() => { if (splitBody.value) workspaceWidth.value = splitBody.value.clientWidth })
    resizeObserver.observe(splitBody.value)
  }
  window.addEventListener('keydown', workspaceKeys)
})
onScopeDispose(() => {
  disposed = true; resizeObserver?.disconnect(); window.removeEventListener('keydown', workspaceKeys)
  if (unlockBody) leaveFocus()
})
</script>

<template>
  <section ref="workspaceRoot" class="source-workbench" :class="{ 'source-workbench--focused': readingFocus, 'source-workbench--compact': layout.compact }" tabindex="-1" aria-label="反编译源码工作台">
    <header class="workbench-toolbar">
      <div class="workbench-title"><FileCode2 :size="18" /><strong>源码工作台</strong><span class="language-tag">{{ languageLabel }}</span><span class="status-tag" :class="{ 'status-tag--warning': showNotice }">{{ statusLabel }}</span></div>
      <div class="workbench-actions">
        <button type="button" :aria-pressed="directoryOpen" title="显示或隐藏源码目录" @click="directoryOpen = !directoryOpen"><PanelLeftClose v-if="directoryOpen" :size="16" /><PanelLeftOpen v-else :size="16" /><span>目录</span></button>
        <button type="button" title="查找文件（Ctrl / ⌘ P）" @click="focusFileSearch"><FolderTree :size="16" /><span>查找文件</span></button>
        <button ref="focusButton" type="button" :aria-pressed="readingFocus" @click="readingFocus = !readingFocus"><Minimize2 v-if="readingFocus" :size="16" /><Maximize2 v-else :size="16" /><span>{{ readingFocus ? '退出专注' : '专注阅读' }}</span></button>
        <button type="button" class="ai-command" :aria-expanded="aiOpen" @click="openAI"><Sparkles :size="16" /><span>AI 解释</span></button>
      </div>
    </header>
    <details class="workbench-details">
      <summary><Info :size="14" /><span>{{ isJvmBytecodeResult && bytecodeMethodIndex.present ? '详情与方法索引' : '反编译详情' }}</span><span class="details-hint">{{ selectedResult?.engine_name || '引擎信息' }}</span></summary>
      <div class="workbench-details__content">
        <p>{{ capabilityMessage }}</p>
        <dl><div><dt>项目</dt><dd>{{ selectedResult?.display_name || '未选择' }}</dd></div><div><dt>引擎</dt><dd>{{ selectedResult?.engine_name || '未知' }} {{ selectedResult?.engine_version }}</dd></div><div><dt>签名 / 说明</dt><dd>{{ selectedResult?.signature || selectedResult?.detail || '暂无' }}</dd></div><div><dt>任务</dt><dd>{{ taskId }}</dd></div></dl>
        <p v-if="diagnosticMessage" class="workbench-diagnostic"><TriangleAlert :size="14" />{{ diagnosticMessage }}</p>
        <BytecodeAnalyzerSummary v-if="analyzerSummary.present" :summary="analyzerSummary" />
        <BytecodeMethodIndexPanel v-if="isJvmBytecodeResult && bytecodeMethodIndex.present" :key="selectedId" :index="bytecodeMethodIndex" :selected-key="activeBytecodeMethodKey" @select="selectedBytecodeMethodKey = $event" />
      </div>
    </details>
    <div v-if="showNotice" class="workbench-notice" role="status"><TriangleAlert :size="14" /><span>{{ capabilityMessage }}</span></div>
    <div v-if="aiOpen && !layout.docked" class="workbench-pane-switch" role="tablist" aria-label="代码与解释视图">
      <button id="source-code-tab" type="button" role="tab" :aria-selected="activePane === 'code'" aria-controls="source-code-pane" :tabindex="activePane === 'code' ? 0 : -1" @click="activePane = 'code'" @keydown.right.prevent="switchPane('ai', true)" @keydown.left.prevent="switchPane('ai', true)" @keydown.home.prevent="switchPane('code', true)" @keydown.end.prevent="switchPane('ai', true)"><FileCode2 :size="15" />代码</button>
      <button id="source-ai-tab" type="button" role="tab" :aria-selected="activePane === 'ai'" aria-controls="source-ai-pane" :tabindex="activePane === 'ai' ? 0 : -1" @click="activePane = 'ai'" @keydown.right.prevent="switchPane('code', true)" @keydown.left.prevent="switchPane('code', true)" @keydown.home.prevent="switchPane('code', true)" @keydown.end.prevent="switchPane('ai', true)"><Sparkles :size="15" />AI 解释</button>
    </div>
    <div ref="splitBody" class="workbench-body" :style="{ gridTemplateColumns: columns }" :class="{ 'workbench-body--directory-open': directoryVisible, 'workbench-body--ai-only': !codeVisible }">
      <aside v-show="directoryVisible" class="workbench-directory" aria-label="源码目录">
        <button v-if="layout.compact" class="directory-close" type="button" @click="directoryOpen = false"><X :size="15" />收起目录</button>
        <SourceProjectExplorer ref="explorer" :items="items" :selected-id="selectedId" :source-files="sourceFiles" :selected-source-file-id="selectedSourceFileId" :source-files-loading="sourceFilesLoading" :source-files-error="sourceFilesError" :has-more-results="hasMoreResults" :loading-more-results="loadingMoreResults" @select="emit('select', $event)" @select-source-file="selectFileFromExplorer" @load-more-results="emit('loadMoreResults')" />
      </aside>
      <div v-show="directoryVisible && !layout.compact" class="reading-divider" role="separator" tabindex="0" aria-label="调整目录宽度" aria-orientation="vertical" :aria-valuemin="180" :aria-valuemax="directoryMaximum" :aria-valuenow="layout.directoryWidth" @pointerdown="startResize" @pointermove="resizeDirectory" @pointerup="dragging = false" @pointercancel="dragging = false" @lostpointercapture="dragging = false" @keydown="resizeWithKeyboard" @dblclick="setDirectoryWidth(260)" />
      <div id="source-code-pane" v-show="codeVisible" class="workbench-code" :role="aiOpen && !layout.docked ? 'tabpanel' : 'region'" :aria-labelledby="aiOpen && !layout.docked ? 'source-code-tab' : ''" aria-label="源码编辑区域">
        <div class="source-tabs-row">
          <div ref="tabStrip" class="source-tabs" role="tablist" aria-label="已打开的源码文件">
            <div v-for="tab in tabs" :key="sourceTabKey(tab)" class="source-tab" :class="{ 'source-tab--active': sourceTabKey(tab) === currentTabKey }">
              <button type="button" role="tab" :data-source-key="sourceTabKey(tab)" aria-controls="source-reader-surface" :aria-selected="sourceTabKey(tab) === currentTabKey" :tabindex="sourceTabKey(tab) === currentTabKey ? 0 : -1" :aria-label="'打开文件 ' + tab.path + '，项目 ' + tab.projectName" :title="tab.projectName + ' / ' + tab.path" @click="activateTab(tab)" @keydown="tabKeydown($event, tab)"><FileCode2 :size="14" /><span>{{ tab.path.replace(/\\/g, '/').split('/').pop() }}</span></button>
              <button type="button" class="source-tab__close" :disabled="tabs.length <= 1" :aria-label="'关闭文件页签 ' + tab.path" :title="tabs.length <= 1 ? '保留当前唯一文件' : '关闭文件页签'" @click="closeTab(tab)"><X :size="12" /></button>
            </div>
            <span v-if="!tabs.length" class="tabs-empty">选择源码文件开始阅读</span>
          </div>
          <button v-if="tabs.length > 1" type="button" class="close-other-tabs" title="仅保留当前文件页签" @click="closeOtherTabs">关闭其他</button>
        </div>
        <div class="source-breadcrumbs" :title="selectedSourceFile?.logicalPath || ''">
          <nav aria-label="当前源码路径"><template v-for="(part, index) in pathParts" :key="index"><ChevronRight v-if="index" :size="11" /><button v-if="index < pathParts.length - 1" type="button" :title="'定位目录 ' + pathParts.slice(0, index + 1).join('/')" @click="locateDirectory(index)">{{ part }}</button><span v-else>{{ part }}</span></template><span v-if="!pathParts.length">尚未选择文件</span></nav>
          <button type="button" :disabled="!selectedSourceFile" aria-label="复制源码完整路径" title="复制完整路径" @click="copyPath"><Copy :size="13" /></button>
          <span v-if="copyFeedback" class="path-feedback" role="status">{{ copyFeedback }}</span>
        </div>
        <div id="source-reader-surface" class="code-reader-frame" role="tabpanel" :aria-label="selectedSourceFile?.logicalPath || '源码内容'"><ReadOnlyCodeEditor ref="codeEditor" :source="source" :language="editorLanguage" :label="'只读' + languageLabel + '反编译代码'" :filename="selectedSourceFile?.logicalPath" :model-uri="editorModelUri" :target-range="targetRange" :loading="sourceLoading || sourceFilesLoading" :error="sourceError" :available="Boolean(sourceFile)" @selection-change="selection = $event" /></div>
      </div>
      <div v-if="selectedResult && aiOpen" id="source-ai-pane" v-show="aiVisible" class="workbench-ai" :role="!layout.docked ? 'tabpanel' : 'region'" :aria-labelledby="!layout.docked ? 'source-ai-tab' : ''" aria-label="源码解释面板">
        <AIExplanationPanel v-model:open="aiOpen" embedded :pane-visible="aiVisible" :resizable="layout.docked" :available-width="layout.aiMaximum" :task-id="taskId" :project-id="selectedResult.id" :file-id="selectedSourceFileId" :source-sha256="sourceFile?.sha256" :source="source" :filename="selectedSourceFile?.logicalPath || ''" :line-count="selectedSourceFile?.lineCount || 0" :loading="sourceLoading || sourceFilesLoading || !sourceFile" :selection="selection" @navigate="navigateExplanation" @resize="aiWidth = $event" />
      </div>
    </div>
  </section>
</template>

<style scoped>
.source-workbench { display: flex; min-width: 0; height: clamp(540px, calc(100dvh - 250px), 850px); flex-direction: column; overflow: hidden; border: 1px solid var(--line); border-radius: 12px; background: var(--surface); outline: none; box-shadow: 0 3px 14px rgb(30 58 138 / 3%); }
.source-workbench--focused { position: fixed; z-index: 20; inset: 12px 12px 12px calc(var(--sidebar-width, 68px) + 12px); height: auto; box-shadow: 0 12px 50px rgb(15 23 42 / 15%); }
.workbench-toolbar { position: sticky; top: 0; z-index: 4; display: flex; flex: 0 0 auto; min-height: 52px; align-items: center; justify-content: space-between; gap: 12px; padding: 8px 12px; border-bottom: 1px solid var(--line); background: var(--surface); }
.workbench-title, .workbench-actions { display: flex; min-width: 0; align-items: center; gap: 7px; }.workbench-title > svg { color: var(--primary); flex-shrink: 0; }.workbench-title strong { font-size: 14px; white-space: nowrap; color: var(--ink-900); }.language-tag,.status-tag { border-radius: 5px; padding: 3px 6px; background: var(--surface-raised); color: var(--ink-500); font-size: 10px; white-space: nowrap; }.status-tag { color: var(--success); background: var(--success-soft); }.status-tag--warning { color: var(--warning); background: var(--warning-soft); }
.workbench-actions button { display: inline-flex; align-items: center; gap: 5px; min-height: 32px; padding: 5px 8px; border: 1px solid transparent; border-radius: 6px; background: transparent; color: var(--ink-600); font: inherit; font-size: 12px; cursor: pointer; white-space: nowrap; }
.workbench-actions button:hover,.workbench-actions button[aria-pressed="true"] { color: var(--primary); background: var(--primary-soft); }.workbench-actions .ai-command { color: var(--primary); border-color: var(--primary-border); background: var(--primary-soft); }
.workbench-details { flex: 0 0 auto; border-bottom: 1px solid var(--line); font-size: 11px; color: var(--ink-500); }.workbench-details > summary { display: flex; align-items: center; gap: 6px; min-height: 29px; padding: 4px 12px; cursor: pointer; list-style: none; }.workbench-details > summary::after { content: '展开'; margin-left: auto; color: var(--primary); }.workbench-details[open] > summary::after { content: '收起'; }.details-hint { margin-left: 8px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }.workbench-details__content { max-height: 35vh; overflow: auto; padding: 4px 14px 12px; background: var(--surface-raised); line-height: 1.7; }.workbench-details__content dl { display: grid; gap: 5px; }.workbench-details__content dl > div { display: grid; grid-template-columns: 80px minmax(0,1fr); gap: 8px; }.workbench-details__content dd { margin: 0; overflow-wrap: anywhere; color: var(--ink-700); }.workbench-diagnostic { display: flex; align-items: flex-start; gap: 6px; color: var(--warning); }.workbench-notice { display: flex; align-items: center; gap: 7px; flex: 0 0 auto; padding: 6px 12px; background: var(--warning-soft); color: var(--ink-700); font-size: 11px; }
.workbench-body { position: relative; display: grid; flex: 1; min-height: 0; min-width: 0; overflow: hidden; }.workbench-body--ai-only { grid-template-columns: minmax(0,1fr) !important; }.workbench-body--ai-only .workbench-directory,.workbench-body--ai-only .reading-divider { display: none !important; }.workbench-directory { display: flex; flex-direction: column; min-width: 0; min-height: 0; overflow: hidden; background: var(--surface-raised); }.reading-divider { position: relative; cursor: col-resize; touch-action: none; background: var(--surface-muted); }.reading-divider::after { content: ''; position: absolute; top: 45%; left: 2px; height: 30px; width: 2px; border-radius: 2px; background: var(--line-strong); }.reading-divider:hover,.reading-divider:focus-visible { background: var(--primary-border); outline: none; }
.workbench-code { display: flex; flex-direction: column; min-width: 0; min-height: 0; overflow: hidden; background: var(--surface); }.code-reader-frame { flex: 1; min-height: 0; overflow: hidden; }.code-reader-frame :deep(.read-only-editor), .code-reader-frame :deep(.read-only-editor__stage) { min-height: 0; }.source-tabs-row { display: flex; min-height: 37px; flex: 0 0 auto; border-bottom: 1px solid var(--line); background: var(--surface-raised); }.source-tabs { display: flex; flex: 1; min-width: 0; overflow-x: auto; scrollbar-width: thin; }.source-tab { display: flex; flex: 0 0 auto; max-width: 240px; min-width: 110px; border-right: 1px solid var(--line); border-top: 2px solid transparent; }.source-tab--active { border-top-color: var(--primary); background: var(--surface); }.source-tab > button[role="tab"] { display: flex; min-width: 0; flex: 1; align-items: center; gap: 6px; padding: 8px 7px 8px 11px; border: 0; background: transparent; color: var(--ink-600); font: inherit; font-size: 12px; cursor: pointer; }.source-tab--active > button[role="tab"] { color: var(--primary); font-weight: 600; }.source-tab > button[role="tab"] span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }.source-tab > button[role="tab"] svg { flex-shrink: 0; }.source-tab__close { align-self: center; display: grid; width: 22px; height: 24px; margin-right: 4px; place-items: center; border: 0; border-radius: 4px; background: transparent; color: var(--ink-400); cursor: pointer; }.source-tab__close:hover { background: var(--surface-muted); color: var(--ink-800); }.source-tab__close:disabled { opacity: .35; cursor: default; }.close-other-tabs { flex: 0 0 auto; padding: 5px 9px; border: 0; border-left: 1px solid var(--line); background: transparent; color: var(--ink-500); font-size: 10px; cursor: pointer; }.tabs-empty { align-self: center; padding: 8px 12px; color: var(--ink-400); font-size: 12px; }
.source-breadcrumbs { position: relative; display: flex; min-height: 29px; flex: 0 0 auto; align-items: center; gap: 6px; padding: 3px 10px; border-bottom: 1px solid var(--line); font-size: 11px; color: var(--ink-500); }.source-breadcrumbs nav { display: flex; flex: 1; min-width: 0; align-items: center; gap: 4px; overflow-x: auto; scrollbar-width: none; white-space: nowrap; }.source-breadcrumbs nav > * { flex: 0 0 auto; }.source-breadcrumbs button { display: inline-flex; align-items: center; min-height: 22px; padding: 2px; border: 0; border-radius: 3px; background: transparent; color: var(--ink-500); font: inherit; cursor: pointer; }.source-breadcrumbs button:hover { color: var(--primary); background: var(--primary-soft); }.source-breadcrumbs nav > span { color: var(--ink-800); }.path-feedback { position: absolute; right: 30px; bottom: 2px; padding: 3px 6px; background: var(--surface); color: var(--primary); font-size: 10px; }.workbench-ai { min-width: 0; min-height: 0; overflow: hidden; border-left: 1px solid var(--line); }.workbench-pane-switch { display: flex; flex: 0 0 auto; gap: 8px; padding: 4px 12px; border-bottom: 1px solid var(--line); background: var(--primary-soft); }.workbench-pane-switch button { display: flex; align-items: center; gap: 6px; padding: 6px 12px; border: 0; border-radius: 5px; background: transparent; color: var(--ink-600); font: inherit; font-size: 12px; cursor: pointer; }.workbench-pane-switch button[aria-selected="true"] { background: var(--surface); color: var(--primary); box-shadow: var(--shadow-sm); }.directory-close { display: flex; align-items: center; justify-content: flex-end; gap: 4px; min-height: 28px; border: 0; border-bottom: 1px solid var(--line); background: var(--surface); color: var(--primary); font-size: 11px; cursor: pointer; }
.source-workbench--compact .workbench-directory { position: absolute; inset: 0 auto 0 0; z-index: 8; width: min(280px,85%); border-right: 1px solid var(--line-strong); box-shadow: 8px 0 25px rgb(15 23 42 / 12%); }.source-workbench--compact .workbench-toolbar { align-items: flex-start; flex-wrap: wrap; gap: 6px; }.source-workbench--compact .workbench-actions { width: 100%; justify-content: space-between; }.source-workbench--compact .workbench-actions button { padding: 5px; }.source-workbench--compact .workbench-code { grid-column: 1; }
@media (max-width:840px) { .source-workbench--focused { inset: 8px; }.source-workbench { height: max(540px,calc(100dvh - 200px)); }.source-workbench--focused { height: auto; } }
@media (prefers-reduced-motion:reduce) { .source-workbench { scroll-behavior: auto; } }
</style>
