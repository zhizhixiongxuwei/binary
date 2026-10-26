<script setup lang="ts">
import { computed, nextTick, shallowRef, useTemplateRef, watch } from 'vue'
import { ChevronDown, ChevronRight, ChevronsDownUp, Crosshair, FileCode2, Folder, FolderOpen, LoaderCircle, Search, TriangleAlert, X } from 'lucide-vue-next'
import type { DecompileResult, DecompileSourceFile } from '@/api/types'
import { neutralizeUnsafeDisplayCharacters } from './displayText'
import { ancestorDirectoryKeys, buildSourceTree, directoryKey, filterSourceTree, flattenSourceTree, matchesProjectCapability, matchesProjectQuery, treeKeyboardDestination, type ProjectCapabilityFilter, type SourceTreeNode, type SourceTreeRow } from './sourceExplorer'

const props = defineProps<{
  items: readonly DecompileResult[]
  selectedId: string
  sourceFiles: readonly DecompileSourceFile[]
  selectedSourceFileId: string
  sourceFilesLoading: boolean
  sourceFilesError: string
  hasMoreResults: boolean
  loadingMoreResults: boolean
}>()
const emit = defineEmits<{ select: [resultId: string]; selectSourceFile: [fileId: string]; loadMoreResults: [] }>()
const fileSearch = useTemplateRef<HTMLInputElement>('fileSearch')
const treeViewport = useTemplateRef<HTMLElement>('treeViewport')
const query = shallowRef('')
const projectQuery = shallowRef('')
const capability = shallowRef<ProjectCapabilityFilter>('all')
const manualExpanded = shallowRef(new Set<string>())
const searchExpanded = shallowRef(new Set<string>())
const focusedKey = shallowRef('')
const highlightedKey = shallowRef('')
const rowLimit = shallowRef(400)
const expansionByProject = new Map<string, Set<string>>()
const tree = computed(() => buildSourceTree(props.sourceFiles))
const matches = computed(() => filterSourceTree(tree.value, query.value))
const expanded = computed(() => matches.value ? searchExpanded.value : manualExpanded.value)
const rows = computed(() => flattenSourceTree(tree.value, expanded.value, matches.value))
const visibleRows = computed(() => rows.value.slice(0, rowLimit.value))
const remainingRows = computed(() => Math.max(0, rows.value.length - visibleRows.value.length))
const selectedProject = computed(() => props.items.find(item => item.id === props.selectedId))
const projects = computed(() => props.items.filter(item => matchesProjectCapability(item, capability.value) && matchesProjectQuery(item, projectQuery.value)))
const counts = computed(() => ({ all: props.items.length, source: props.items.filter(item => matchesProjectCapability(item, 'source')).length, bytecode: props.items.filter(item => matchesProjectCapability(item, 'bytecode')).length, issues: props.items.filter(item => matchesProjectCapability(item, 'issues')).length }))
const filters: { value: ProjectCapabilityFilter; label: string }[] = [{ value: 'all', label: '全部' }, { value: 'source', label: '源码' }, { value: 'bytecode', label: '字节码' }, { value: 'issues', label: '异常' }]
const statusLabels: Record<string, string> = { complete: '已完成', partial: '部分完成', bytecode_only: '仅字节码', unsupported: '不支持', failed: '失败', cancelled: '已取消', queued: '排队中', running: '处理中' }
const safe = (value: string) => neutralizeUnsafeDisplayCharacters(value)
const projectLabel = (item: DecompileResult) => `${safe(item.display_name || item.symbol_key || '未命名项目')} · ${safe(item.language || '文本')}`
const treeTabKey = computed(() => visibleRows.value.some(row => row.node.key === focusedKey.value) ? focusedKey.value : visibleRows.value.find(row => row.node.kind === 'file' && row.node.file.id === props.selectedSourceFileId)?.node.key ?? visibleRows.value[0]?.node.key)
function rowState(row: SourceTreeRow): Record<string, string> { return row.node.kind === 'directory' ? { 'aria-expanded': String(row.expanded) } : { 'aria-selected': String(row.node.file.id === props.selectedSourceFileId) } }
function rowTitle(node: SourceTreeNode): string { return node.kind === 'file' ? `${safe(node.path)} · ${safe(node.file.language)} · ${node.file.lineCount} 行` : safe(node.path) }

function selectCapability(value: ProjectCapabilityFilter): void {
  capability.value = value
  projectQuery.value = ''
  if (selectedProject.value && matchesProjectCapability(selectedProject.value, value)) return
  const first = props.items.find(item => matchesProjectCapability(item, value))
  if (first) emit('select', first.id)
}
function selectProject(value: unknown): void { if (typeof value === 'string') emit('select', value); projectQuery.value = '' }
function rememberExpanded(): void { expansionByProject.set(props.selectedId, new Set(manualExpanded.value)) }
function setExpanded(key: string, open: boolean): void {
  const next = new Set(expanded.value)
  if (open) next.add(key); else next.delete(key)
  if (matches.value) searchExpanded.value = next
  else { manualExpanded.value = next; rememberExpanded() }
}
function activate(node: SourceTreeNode): void {
  focusedKey.value = node.key
  highlightedKey.value = ''
  if (node.kind === 'directory') setExpanded(node.key, !expanded.value.has(node.key))
  else emit('selectSourceFile', node.file.id)
}
function collapseFolders(): void {
  if (matches.value) searchExpanded.value = new Set()
  else { manualExpanded.value = new Set(); rememberExpanded() }
  focusedKey.value = ''
}
async function focusSearch(): Promise<void> { await nextTick(); fileSearch.value?.focus({ preventScroll: true }); fileSearch.value?.select() }
function rowElement(key: string): HTMLElement | undefined {
  return Array.from(treeViewport.value?.querySelectorAll<HTMLElement>('[data-explorer-key]') ?? []).find(element => element.dataset.explorerKey === key)
}
function keepRowVisible(element: HTMLElement): void {
  const viewport = treeViewport.value
  if (!viewport) return
  // scrollIntoView would move the entire task page as well as this pane.
  const top = element.getBoundingClientRect().top - viewport.getBoundingClientRect().top + viewport.scrollTop
  if (top < viewport.scrollTop) viewport.scrollTop = Math.max(0, top - 8)
  else if (top + element.offsetHeight > viewport.scrollTop + viewport.clientHeight) viewport.scrollTop = top + element.offsetHeight - viewport.clientHeight + 8
}
async function focusRow(key: string, focus = true): Promise<void> {
  focusedKey.value = key
  const index = rows.value.findIndex(row => row.node.key === key)
  if (index >= rowLimit.value) rowLimit.value = Math.ceil((index + 1) / 400) * 400
  await nextTick()
  const element = rowElement(key)
  if (element) { if (focus) element.focus({ preventScroll: true }); keepRowVisible(element) }
}
async function revealNode(key: string, includeSelf: boolean): Promise<void> {
  if (!tree.value.byKey.has(key)) return
  query.value = ''
  const next = new Set(manualExpanded.value)
  for (const ancestor of ancestorDirectoryKeys(tree.value, key)) next.add(ancestor)
  if (includeSelf) next.add(key)
  manualExpanded.value = next
  rememberExpanded()
  highlightedKey.value = key
  // Clearing search schedules its own expansion/window reset before rendering.
  await nextTick()
  await focusRow(key, false)
}
async function locateCurrentFile(): Promise<void> {
  const file = tree.value.byFileId.get(props.selectedSourceFileId)
  if (file) await revealNode(file.key, false)
}
async function locateDirectory(path: string): Promise<void> {
  const key = directoryKey(path)
  if (tree.value.byKey.has(key)) await revealNode(key, true)
  else await locateCurrentFile()
}
async function handleTreeKey(event: KeyboardEvent, row: SourceTreeRow): Promise<void> {
  if (event.altKey || event.ctrlKey || event.metaKey) return
  const key = event.key
  if (!['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight', 'Home', 'End', 'Enter', ' '].includes(key)) return
  event.preventDefault()
  if (key === 'Enter' || key === ' ') { activate(row.node); return }
  if (row.node.kind === 'directory' && key === 'ArrowRight' && !row.expanded) { setExpanded(row.node.key, true); return }
  if (row.node.kind === 'directory' && key === 'ArrowLeft' && row.expanded) { setExpanded(row.node.key, false); return }
  const destination = treeKeyboardDestination(rows.value, row.node.key, key)
  if (destination) await focusRow(destination)
}
function openFirstSearchResult(): void {
  const first = rows.value.find(row => row.node.kind === 'file')
  if (first?.node.kind === 'file') { emit('selectSourceFile', first.node.file.id); void focusRow(first.node.key) }
}

watch(() => props.selectedId, (_id, previous) => {
  if (previous) expansionByProject.set(previous, new Set(manualExpanded.value))
  manualExpanded.value = new Set(expansionByProject.get(props.selectedId) ?? [])
  query.value = ''; focusedKey.value = ''; highlightedKey.value = ''; rowLimit.value = 400
  if (selectedProject.value && !matchesProjectCapability(selectedProject.value, capability.value)) capability.value = 'all'
})
watch([matches, tree], () => {
  searchExpanded.value = new Set(matches.value?.directories ?? [])
  rowLimit.value = 400
  if (!tree.value.byKey.has(focusedKey.value)) focusedKey.value = ''
})
watch([() => props.selectedSourceFileId, () => props.sourceFilesLoading, tree], async () => {
  if (props.sourceFilesLoading) return
  const current = tree.value.byFileId.get(props.selectedSourceFileId)
  if (!current) return
  // Initial deep links and tab navigation reveal the selection in its folder;
  // manual collapse remains respected until the selection changes again.
  const next = new Set(manualExpanded.value)
  for (const ancestor of ancestorDirectoryKeys(tree.value, current.key)) next.add(ancestor)
  manualExpanded.value = next
  rememberExpanded()
  await focusRow(current.key, false)
}, { immediate: true, flush: 'post' })

defineExpose({ focusSearch, locateCurrentFile, locateDirectory })
</script>

<template>
  <div class="source-explorer" aria-label="源码项目与目录">
    <header class="explorer-project">
      <div class="explorer-heading"><strong>源码项目</strong><span>{{ items.length }} 项</span></div>
      <el-select :model-value="selectedId" class="project-selector" popper-class="source-project-options" filterable :filter-method="(value: string) => projectQuery = value" aria-label="切换源码项目" placeholder="选择或搜索项目" no-match-text="没有匹配的项目" no-data-text="此分类暂无项目" :title="selectedProject ? safe(selectedProject.location || selectedProject.display_name) : ''" @change="selectProject" @visible-change="(open: boolean) => { if (!open) projectQuery = '' }">
        <el-option v-for="item in projects" :key="item.id" :value="item.id" :label="projectLabel(item)">
          <div class="project-option"><strong>{{ safe(item.display_name || item.symbol_key || '未命名项目') }}</strong><small>{{ safe(item.location || item.group_name || item.language) }} · {{ statusLabels[item.status] || item.status }}</small></div>
        </el-option>
      </el-select>
      <div class="project-filters" role="group" aria-label="按反编译能力筛选"><button v-for="filter in filters" :key="filter.value" type="button" :aria-pressed="capability === filter.value" :title="`${filter.label}项目 ${counts[filter.value]} 项`" @click="selectCapability(filter.value)"><span>{{ filter.label }}</span><small>{{ counts[filter.value] }}</small></button></div>
      <p v-if="!counts[capability] && items.length" class="project-empty-filter" role="status">此分类暂无项目，当前源码仍可阅读。<button type="button" @click="selectCapability('all')">查看全部</button></p>
      <button v-if="hasMoreResults" type="button" class="explorer-load-projects" :disabled="loadingMoreResults" @click="emit('loadMoreResults')"><LoaderCircle v-if="loadingMoreResults" class="spin" :size="13" /><ChevronDown v-else :size="13" />{{ loadingMoreResults ? '正在加载项目…' : '加载更多项目' }}</button>
    </header>
    <section class="explorer-files" aria-label="项目文件目录">
      <header class="explorer-files__heading"><strong>文件目录</strong><span>{{ matches ? matches.fileCount + ' / ' : '' }}{{ sourceFiles.length }}</span><div><button type="button" aria-label="定位当前文件" title="定位当前文件" :disabled="!selectedSourceFileId || sourceFilesLoading" @click="locateCurrentFile"><Crosshair :size="15" /></button><button type="button" aria-label="折叠全部目录" title="折叠全部目录" :disabled="sourceFilesLoading" @click="collapseFolders"><ChevronsDownUp :size="15" /></button></div></header>
      <label class="explorer-search"><Search :size="14" aria-hidden="true" /><input ref="fileSearch" v-model="query" type="search" aria-label="搜索当前项目源码文件" placeholder="搜索文件 · Ctrl / ⌘ P" autocomplete="off" @keydown.enter.prevent="openFirstSearchResult"><button v-if="query" type="button" aria-label="清除文件搜索" @click="query = ''; fileSearch?.focus({ preventScroll: true })"><X :size="13" /></button></label>
      <div ref="treeViewport" class="explorer-tree-viewport" :aria-busy="sourceFilesLoading">
        <div v-if="sourceFilesLoading" class="explorer-state" role="status"><LoaderCircle class="spin" :size="17" /><span>正在读取文件目录…</span></div>
        <div v-else-if="sourceFilesError && !sourceFiles.length" class="explorer-state explorer-state--error" role="alert"><TriangleAlert :size="17" /><span>{{ sourceFilesError }}</span></div>
        <template v-else>
          <div v-if="visibleRows.length" class="explorer-tree" role="tree" aria-label="项目源码文件">
            <button v-for="row in visibleRows" :key="row.node.key" v-bind="rowState(row)" class="explorer-tree-row" :class="{ 'explorer-tree-row--directory': row.node.kind === 'directory', 'explorer-tree-row--selected': row.node.kind === 'file' && row.node.file.id === selectedSourceFileId, 'explorer-tree-row--located': highlightedKey === row.node.key }" type="button" role="treeitem" :data-explorer-key="row.node.key" :aria-level="row.depth + 1" :tabindex="treeTabKey === row.node.key ? 0 : -1" :title="rowTitle(row.node)" :style="{ '--tree-depth': Math.min(row.depth, 10) }" @focus="focusedKey = row.node.key" @click="activate(row.node)" @keydown="handleTreeKey($event, row)">
              <component :is="row.expanded ? ChevronDown : ChevronRight" v-if="row.node.kind === 'directory'" class="tree-disclosure" :size="12" aria-hidden="true" /><span v-else class="tree-disclosure" />
              <component :is="row.node.kind === 'file' ? FileCode2 : row.expanded ? FolderOpen : Folder" class="tree-file-icon" :size="15" aria-hidden="true" />
              <span class="tree-node-name">{{ safe(row.node.name) }}</span>
              <small v-if="row.node.kind === 'directory'" class="tree-node-count">{{ row.node.fileCount }}</small><small v-else class="tree-node-lines">{{ row.node.file.lineCount }}<span> 行</span></small>
            </button>
          </div>
          <div v-else class="explorer-state" role="status"><Search v-if="query" :size="18" /><Folder v-else :size="20" /><span>{{ query ? '没有匹配的源码文件' : '此项目暂无源码文件' }}</span><button v-if="query" type="button" @click="query = ''">清除搜索</button></div>
          <button v-if="remainingRows" type="button" class="explorer-load-files" @click="rowLimit += 400">继续显示 {{ Math.min(remainingRows, 400) }} 项<span>剩余 {{ remainingRows }} 项</span></button>
          <p v-if="sourceFilesError && sourceFiles.length" class="explorer-inline-error" role="alert">{{ sourceFilesError }}</p>
        </template>
      </div>
      <footer class="explorer-footer"><span>{{ query ? '搜索会展开匹配目录' : '方向键浏览 · Enter 打开' }}</span><span v-if="sourceFilesLoading">读取中</span></footer>
    </section>
  </div>
</template>

<style scoped>
.source-explorer { container-type: inline-size; display: flex; width: 100%; height: 100%; min-height: 0; min-width: 0; flex-direction: column; color: var(--ink-700); background: var(--surface); }
.explorer-project { flex: 0 0 auto; padding: 14px 12px 12px; border-bottom: 1px solid var(--line); }
.explorer-heading, .explorer-files__heading { display: flex; align-items: center; min-width: 0; gap: 8px; }
.explorer-heading { margin-bottom: 10px; }.explorer-heading strong, .explorer-files__heading strong { font-size: 12px; font-weight: 650; color: var(--ink-800); }.explorer-heading > span { margin-left: auto; color: var(--ink-500); font: 11px Consolas, monospace; }
.project-selector { width: 100%; }.project-selector :deep(.el-select__wrapper) { min-height: 34px; padding: 5px 9px; border-radius: 8px; box-shadow: 0 0 0 1px var(--line-strong) inset; }.project-selector :deep(.el-select__selected-item) { font-size: 12px; }.project-selector :deep(.el-select__wrapper.is-focused) { box-shadow: 0 0 0 1px var(--primary) inset; }
.project-option { display: flex; min-width: 0; max-width: 480px; height: 100%; flex-direction: column; justify-content: center; gap: 3px; line-height: 1.5; }.project-option strong { overflow: hidden; text-overflow: ellipsis; font-size: 12px; font-weight: 550; }.project-option small { overflow: hidden; text-overflow: ellipsis; color: var(--ink-500); font-size: 10px; }
:global(.source-project-options) { max-width: calc(100vw - 24px); }:global(.source-project-options .el-select-dropdown__item) { height: auto; min-height: 46px; padding-block: 7px; line-height: normal; }
.project-filters { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 10px; }.project-filters button { display: inline-flex; flex: 1 0 auto; align-items: center; justify-content: center; gap: 4px; padding: 4px 5px; border: 1px solid transparent; border-radius: 6px; color: var(--ink-500); background: var(--surface-muted); font: inherit; font-size: 10px; cursor: pointer; }.project-filters button small { font: 10px Consolas, monospace; opacity: .8; }.project-filters button[aria-pressed="true"] { border-color: var(--primary-border); color: var(--primary); background: var(--primary-soft); }
.project-empty-filter { margin: 8px 0 0; color: var(--ink-500); font-size: 10px; line-height: 1.6; }.project-empty-filter button { border: 0; background: transparent; color: var(--primary); font: inherit; cursor: pointer; }
.explorer-load-projects, .explorer-load-files { display: flex; align-items: center; justify-content: center; gap: 5px; width: 100%; padding: 7px; border: 0; border-radius: 6px; color: var(--primary); background: var(--primary-soft); font: inherit; font-size: 11px; cursor: pointer; }.explorer-load-projects { margin-top: 8px; }.explorer-load-files { width: calc(100% - 16px); margin: 6px 8px; flex-wrap: wrap; }.explorer-load-files span { color: var(--ink-500); font-size: 10px; }
.explorer-files { display: flex; flex: 1; flex-direction: column; min-height: 0; }.explorer-files__heading { flex: 0 0 auto; padding: 12px 12px 8px; }.explorer-files__heading > span { color: var(--ink-500); font: 10px Consolas, monospace; }.explorer-files__heading > div { display: flex; margin-left: auto; gap: 3px; }.explorer-files__heading button { display: grid; width: 25px; height: 25px; padding: 0; place-items: center; border: 0; border-radius: 5px; color: var(--ink-500); background: transparent; cursor: pointer; }
.explorer-search { display: flex; flex: 0 0 auto; min-width: 0; align-items: center; gap: 6px; margin: 0 10px 9px; padding: 7px 8px; border: 1px solid var(--line); border-radius: 7px; color: var(--ink-500); background: var(--surface-raised); }.explorer-search > svg { flex-shrink: 0; }.explorer-search:focus-within { border-color: var(--primary); box-shadow: 0 0 0 2px var(--primary-soft); }.explorer-search input { min-width: 0; width: 100%; padding: 0; border: 0; outline: 0; color: var(--ink-800); background: transparent; font: inherit; font-size: 11px; }.explorer-search input::-webkit-search-cancel-button { display: none; }.explorer-search button { display: grid; place-items: center; flex: 0 0 16px; width: 16px; height: 16px; padding: 0; border: 0; color: var(--ink-500); background: transparent; cursor: pointer; }
.explorer-tree-viewport { min-height: 0; flex: 1; overflow: auto; overscroll-behavior: contain; scrollbar-width: thin; }.explorer-tree { min-width: 0; padding: 3px 6px 10px; }.explorer-tree-row { display: flex; position: relative; width: 100%; min-width: 0; min-height: 32px; align-items: center; gap: 6px; padding: 5px 7px 5px calc(5px + var(--tree-depth) * 12px); border: 1px solid transparent; border-radius: 6px; color: var(--ink-700); background: transparent; font: inherit; font-size: 12px; text-align: left; cursor: pointer; }.tree-disclosure { flex: 0 0 12px; width: 12px; color: var(--ink-400); }.tree-file-icon { flex: 0 0 15px; color: var(--ink-500); }.explorer-tree-row--directory .tree-file-icon { color: var(--primary); opacity: .8; }.tree-node-name { min-width: 0; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }.tree-node-count, .tree-node-lines { flex-shrink: 0; margin-left: 3px; color: var(--ink-400); font: 10px Consolas, monospace; }.tree-node-lines { opacity: 0; transition: opacity 120ms ease; }.explorer-tree-row:hover .tree-node-lines, .explorer-tree-row:focus-visible .tree-node-lines, .explorer-tree-row--selected .tree-node-lines { opacity: 1; }
.explorer-tree-row:hover { color: var(--ink-950); background: var(--surface-muted); }.explorer-tree-row--selected { color: var(--primary); background: var(--primary-soft); font-weight: 600; }.explorer-tree-row--selected::before { position: absolute; left: -1px; top: 7px; bottom: 7px; width: 3px; border-radius: 3px; background: var(--primary); content: ''; }.explorer-tree-row--selected .tree-file-icon { color: var(--primary); }.explorer-tree-row--located { box-shadow: 0 0 0 1px var(--primary-border) inset; }.explorer-tree-row:focus-visible, button:focus-visible { outline: 2px solid var(--primary); outline-offset: -2px; }.explorer-files__heading button:hover { color: var(--primary); background: var(--primary-soft); }button:disabled { opacity: .45; cursor: not-allowed; }
.explorer-state { display: flex; min-height: 130px; align-items: center; justify-content: center; flex-direction: column; gap: 10px; padding: 18px 12px; color: var(--ink-500); font-size: 12px; text-align: center; }.explorer-state button { border: 0; background: transparent; color: var(--primary); font: inherit; cursor: pointer; }.explorer-state--error, .explorer-inline-error { color: var(--danger); }.explorer-inline-error { margin: 8px 12px; font-size: 11px; line-height: 1.6; }.explorer-footer { display: flex; flex: 0 0 auto; justify-content: space-between; gap: 8px; padding: 8px 11px; border-top: 1px solid var(--line); color: var(--ink-400); font-size: 10px; }
.spin { animation: explorer-spin .9s linear infinite; }@keyframes explorer-spin { to { transform: rotate(360deg); } }
@container (max-width: 230px) { .explorer-project { padding: 11px 8px 10px; }.explorer-files__heading { padding-inline: 8px; }.explorer-search { margin-inline: 7px; }.project-filters button { padding: 4px; font-size: 10px; }.tree-node-lines { display: none; }.explorer-tree-row { gap: 3px; padding-left: calc(2px + min(var(--tree-depth), 4) * 9px); font-size: 11px; }.explorer-footer { font-size: 9px; padding-inline: 8px; } }
@media (prefers-reduced-motion: reduce) { .tree-node-lines { transition: none; }.spin { animation: none; } }
</style>
