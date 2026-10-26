<script setup lang="ts">
import {
  Box,
  Braces,
  ChevronDown,
  Code2,
  FileCode2,
  ListTree,
  LoaderCircle,
  Search,
  TriangleAlert,
} from 'lucide-vue-next'
import { computed, shallowRef, watch, type Component } from 'vue'

import type {
  DecompileResult,
  DecompileSourceFile,
  DecompileSourceFileContent,
  DecompileSymbolKind,
  JsonValue,
  SourceNavigationTarget,
} from '@/api/types'
import ReadOnlyCodeEditor from '@/components/code-editor/ReadOnlyCodeEditor.vue'
import type { ReadOnlyCodeLanguage } from '@/components/code-editor/monacoLoader'
import BytecodeAnalyzerSummary from '@/components/tasks/results/BytecodeAnalyzerSummary.vue'
import BytecodeMethodIndexPanel from '@/components/tasks/results/BytecodeMethodIndexPanel.vue'
import { parseAnalyzerSummary } from '@/components/tasks/results/analyzerSummary'
import { neutralizeUnsafeDisplayCharacters } from '@/components/tasks/results/displayText'
import { parseBytecodeMethodIndex } from '@/components/tasks/results/jvmMethodIndex'

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
}>()

interface ResultGroup {
  name: string
  items: readonly DecompileResult[]
}

type ResultFilter = 'all' | 'source' | 'bytecode' | 'issues'
const MAX_DIAGNOSTIC_PREVIEW_LENGTH = 4_096
const MAX_RENDERED_SOURCE_FILES = 500

const query = shallowRef('')
const resultFilter = shallowRef<ResultFilter>('all')
const selectedBytecodeMethodKey = shallowRef('')
const normalizedQuery = computed(() =>
  query.value.trim().toLocaleLowerCase('zh-CN'),
)
const selectedResult = computed(() =>
  props.items.find((item) => item.id === props.selectedId),
)
const selectedSourceFile = computed(() =>
  props.sourceFiles.find((item) => item.id === props.selectedSourceFileId),
)
const filteredSourceFiles = computed(() => {
  if (!normalizedQuery.value) return props.sourceFiles
  return props.sourceFiles.filter((file) =>
    [file.logicalPath, file.language, file.sha256]
      .join(' ')
      .toLocaleLowerCase('zh-CN')
      .includes(normalizedQuery.value),
  )
})
const visibleSourceFiles = computed(() => {
  // 大型 Ghidra 项目可能包含数千文件，侧栏只渲染前 500 项以控制 DOM；当前选中
  // 文件即使不在截断窗口内也必须保留，避免源码与选中项视觉脱节。
  const visible = filteredSourceFiles.value.slice(0, MAX_RENDERED_SOURCE_FILES)
  const selected = selectedSourceFile.value
  if (selected && !visible.some((file) => file.id === selected.id)) {
    return [...visible, selected]
  }
  return visible
})
const sourceFilesTruncated = computed(
  () => filteredSourceFiles.value.length > visibleSourceFiles.value.length,
)
const isJvmBytecodeResult = computed(() => {
  const language = selectedResult.value?.language.trim().toLocaleLowerCase('en-US') ?? ''
  return language.includes('java') && language.includes('bytecode')
})
const bytecodeMethodIndex = computed(() =>
  parseBytecodeMethodIndex(selectedResult.value?.diagnostics),
)
const analyzerSummary = computed(() =>
  parseAnalyzerSummary(selectedResult.value?.diagnostics),
)
const activeBytecodeMethodKey = computed(() => {
  const methods = bytecodeMethodIndex.value.methods
  return methods.some((method) => method.key === selectedBytecodeMethodKey.value)
    ? selectedBytecodeMethodKey.value
    : methods[0]?.key ?? ''
})
const filterCounts = computed<Record<ResultFilter, number>>(() => ({
  all: props.items.length,
  source: props.items.filter((item) =>
    item.status === 'complete' || item.status === 'partial',
  ).length,
  bytecode: props.items.filter((item) => item.status === 'bytecode_only').length,
  issues: props.items.filter((item) =>
    ['unsupported', 'failed', 'cancelled'].includes(item.status),
  ).length,
}))
const filteredItems = computed(() => {
  const statusFiltered = props.items.filter((item) =>
    matchesResultFilter(item, resultFilter.value),
  )
  if (!normalizedQuery.value) return statusFiltered
  return statusFiltered.filter((item) => {
    // 文件清单只为当前项目加载，因此文件路径命中只能提升当前项目，不能误认为
    // 其他尚未展开项目也不匹配。
    const selectedProjectHasMatchingFile =
      item.id === props.selectedId &&
      props.sourceFiles.some((file) =>
        [file.logicalPath, file.language, file.sha256]
          .join(' ')
          .toLocaleLowerCase('zh-CN')
          .includes(normalizedQuery.value),
      )
    const searchable = [
      item.display_name,
      item.group_name,
      item.location,
      item.signature,
      item.detail,
      item.language,
      item.engine_name,
      item.symbol_key,
    ]
      .join(' ')
      .toLocaleLowerCase('zh-CN')
    return searchable.includes(normalizedQuery.value) || selectedProjectHasMatchingFile
  })
})
const groupedItems = computed<readonly ResultGroup[]>(() => {
  const groups = new Map<string, DecompileResult[]>()
  filteredItems.value.forEach((item) => {
    const groupName = item.group_name || '未分组符号'
    const group = groups.get(groupName) ?? []
    group.push(item)
    groups.set(groupName, group)
  })
  return [...groups].map(([name, items]) => ({ name, items }))
})
const editorLanguage = computed<ReadOnlyCodeLanguage>(() => {
  // 后端语言名称包含能力降级信息（如 java bytecode / python-bytecode），先匹配
  // 具体形态再匹配通用语言，保证 Monaco 语法和字节码视图一致。
  const language = (
    selectedSourceFile.value?.language ?? selectedResult.value?.language ?? ''
  ).trim().toLowerCase()
  if (language.includes('java') && language.includes('bytecode')) {
    return 'jvm-bytecode'
  }
  if (language.includes('java')) return 'java'
  if (language.includes('smali') || language.includes('dex')) return 'smali'
  if (language.includes('pyc') || language.includes('python-bytecode')) {
    return 'python-bytecode'
  }
  if (language.includes('python') || language === 'py') return 'python'
  return 'c'
})
const languageLabel = computed(() => {
  const language = (
    selectedSourceFile.value?.language ?? selectedResult.value?.language
  )?.trim()
  if (!language) return '反编译文本'
  const normalized = language.toLowerCase()
  if (normalized.includes('java') && normalized.includes('bytecode')) {
    return 'JVM 字节码索引'
  }
  if (normalized.includes('smali') || normalized.includes('dex')) return 'Smali'
  if (normalized.includes('pyc') || normalized.includes('python-bytecode')) {
    return 'Python 字节码'
  }
  if (normalized.includes('python') || normalized === 'py') return 'Python'
  if (normalized.includes('java')) return 'Java 形态'
  if (normalized.includes('c')) return '伪 C'
  return language
})
const editorModelUri = computed(() => {
  // 每个任务/项目/文件使用稳定且隔离的 Monaco URI，避免模型缓存把同名源码串线。
  const taskId = encodeURIComponent(props.taskId)
  const projectId = encodeURIComponent(props.selectedId || 'project')
  const fileId = encodeURIComponent(props.selectedSourceFileId || 'file')
  return `binaryscan-source:///${taskId}/${projectId}/${fileId}`
})
const capabilityMessage = computed(() => {
  const result = selectedResult.value
  if (!result) return ''
  switch (result.status) {
    case 'partial':
      return '分析器仅生成部分输出；符号、类型或控制流可能缺失。'
    case 'bytecode_only':
      return '能力已降级为字节码视图，未恢复为高层语言。'
    case 'unsupported':
      return '当前分析器不支持该符号或输入格式。'
    case 'failed':
      return '分析器处理失败，请结合诊断信息定位原因。'
    case 'cancelled':
      return '反编译任务已取消，已完成的输出仍可阅读。'
    case 'queued':
      return '该反编译单元正在排队，暂时没有源码输出。'
    case 'running':
      return '该反编译单元仍在处理中，结果可能继续更新。'
    default:
      return '反编译输出不是原始源码；变量名、类型、注释和控制流可能失真。'
  }
})
const diagnosticMessage = computed(() =>
  diagnosticText(selectedResult.value?.diagnostics),
)

watch(
  () => props.selectedId,
  () => {
    selectedBytecodeMethodKey.value = ''
  },
)

const unitIcons: Readonly<Record<DecompileSymbolKind, Component>> = {
  function: Braces,
  class: Box,
  method: Code2,
  module: FileCode2,
  unknown: FileCode2,
}

const unitLabels: Readonly<Record<DecompileSymbolKind, string>> = {
  function: '函数',
  class: '类',
  method: '方法',
  module: '模块',
  unknown: '符号',
}

const resultFilters: readonly {
  value: ResultFilter
  label: string
  icon: Component
}[] = [
  { value: 'all', label: '全部', icon: ListTree },
  { value: 'source', label: '源码形态', icon: FileCode2 },
  { value: 'bytecode', label: '仅字节码', icon: Code2 },
  { value: 'issues', label: '异常', icon: TriangleAlert },
]

function diagnosticText(value: JsonValue | undefined): string {
  if (typeof value === 'string') return diagnosticPreview(value)
  if (!value || typeof value !== 'object' || Array.isArray(value)) return ''
  const record = value as Readonly<Record<string, JsonValue>>
  for (const key of ['message', 'warning', 'limitation', 'detail']) {
    const candidate = record[key]
    if (typeof candidate === 'string' && candidate.trim()) {
      return diagnosticPreview(candidate)
    }
  }
  return ''
}

function diagnosticPreview(value: string): string {
  const truncated = value.length > MAX_DIAGNOSTIC_PREVIEW_LENGTH
  const safeValue = neutralizeUnsafeDisplayCharacters(
    value.slice(0, MAX_DIAGNOSTIC_PREVIEW_LENGTH),
  ).trim()
  return truncated && safeValue ? `${safeValue}...` : safeValue
}

function matchesResultFilter(
  item: DecompileResult,
  filter: ResultFilter,
): boolean {
  switch (filter) {
    case 'source':
      return item.status === 'complete' || item.status === 'partial'
    case 'bytecode':
      return item.status === 'bytecode_only'
    case 'issues':
      return ['unsupported', 'failed', 'cancelled'].includes(item.status)
    default:
      return true
  }
}

function selectFilter(filter: ResultFilter): void {
  resultFilter.value = filter
  // 当前项目被筛掉时主动选择该分类第一个项目，确保右侧详情始终属于可见列表。
  const selected = selectedResult.value
  if (selected && matchesResultFilter(selected, filter)) return
  const firstVisible = props.items.find((item) => matchesResultFilter(item, filter))
  if (firstVisible) emit('select', firstVisible.id)
}

function selectBytecodeMethod(methodKey: string): void {
  selectedBytecodeMethodKey.value = methodKey
}

function sourceFilePathParts(file: DecompileSourceFile): string[] {
  return file.logicalPath.replace(/\\/g, '/').split('/').filter(Boolean)
}

function sourceFileName(file: DecompileSourceFile): string {
  const parts = sourceFilePathParts(file)
  return parts[parts.length - 1] ?? file.logicalPath
}

function sourceFileDirectory(file: DecompileSourceFile): string {
  const parts = sourceFilePathParts(file)
  return parts.slice(0, -1).join('/') || '项目根目录'
}

function sourceFileDepth(file: DecompileSourceFile): number {
  return Math.min(Math.max(sourceFilePathParts(file).length - 1, 0), 12)
}
</script>

<template>
  <div class="decompile-workspace">
    <section class="capability-strip" aria-labelledby="capability-title">
      <div class="capability-strip__identity">
        <Code2 :size="17" aria-hidden="true" />
        <span>
          <small id="capability-title">反编译能力</small>
          <strong>{{ languageLabel }}</strong>
        </span>
      </div>
      <p>{{ capabilityMessage }}</p>
      <span
        v-if="selectedResult"
        class="capability-strip__engine"
        :class="`capability-strip__engine--${selectedResult.status}`"
      >
        {{ selectedResult.engine_name || '未知引擎' }}
        {{ selectedResult.engine_version }}
        · {{ selectedResult.status }}
      </span>
    </section>

    <div
      v-if="diagnosticMessage"
      class="capability-warning"
      role="note"
    >
      <TriangleAlert :size="16" aria-hidden="true" />
      <strong>分析器诊断</strong>
      <span>{{ diagnosticMessage }}</span>
    </div>

    <div class="decompile-workspace__body">
      <aside class="symbol-panel" aria-label="反编译源码项目和文件列表">
        <div class="symbol-panel__heading">
          <div>
            <strong>源码项目</strong>
            <span>{{ filteredItems.length }} / {{ items.length }}</span>
          </div>
          <label class="symbol-search">
            <span class="sr-only">搜索源码项目、文件路径或语言</span>
            <Search :size="14" aria-hidden="true" />
            <input
              v-model="query"
              type="search"
              autocomplete="off"
              placeholder="搜索项目、文件路径或语言"
            >
          </label>
          <div class="result-filters" role="group" aria-label="按反编译能力筛选">
            <button
              v-for="filter in resultFilters"
              :key="filter.value"
              type="button"
              :class="{ 'result-filter--active': resultFilter === filter.value }"
              :aria-pressed="resultFilter === filter.value"
              @click="selectFilter(filter.value)"
            >
              <component :is="filter.icon" :size="12" aria-hidden="true" />
              <span>{{ filter.label }}</span>
              <code>{{ filterCounts[filter.value] }}</code>
            </button>
          </div>
        </div>

        <div
          v-if="groupedItems.length"
          class="symbol-tree"
          role="tree"
          aria-label="反编译源码项目"
        >
          <section
            v-for="group in groupedItems"
            :key="group.name"
            class="symbol-group"
            role="group"
            :aria-label="group.name"
          >
            <h4>{{ group.name }}</h4>
            <button
              v-for="item in group.items"
              :key="item.id"
              class="symbol-row"
              :class="{ 'symbol-row--active': selectedId === item.id }"
              type="button"
              role="treeitem"
              :aria-selected="selectedId === item.id"
              @click="emit('select', item.id)"
            >
              <component
                :is="unitIcons[item.symbol_kind] ?? FileCode2"
                :size="14"
                aria-hidden="true"
              />
              <span class="symbol-row__main">
                <strong>{{ item.display_name || item.symbol_key }}</strong>
                <small class="mono">{{ item.location || '位置未知' }}</small>
              </span>
              <span class="symbol-row__kind">
                {{ unitLabels[item.symbol_kind] ?? '符号' }}
              </span>
            </button>
          </section>
        </div>
        <div v-else class="symbol-panel__empty" role="status">
          没有匹配的源码项目
        </div>
        <button
          v-if="hasMoreResults"
          class="load-more"
          type="button"
          :disabled="loadingMoreResults"
          :aria-busy="loadingMoreResults"
          @click="emit('loadMoreResults')"
        >
          <LoaderCircle
            v-if="loadingMoreResults"
            class="spin"
            :size="14"
            aria-hidden="true"
          />
          <ChevronDown v-else :size="14" aria-hidden="true" />
          加载更多源码项目
        </button>

        <section
          v-if="selectedResult"
          class="source-file-group"
          aria-labelledby="source-file-heading"
        >
          <header>
            <strong id="source-file-heading">项目文件</strong>
            <span>{{ filteredSourceFiles.length }} / {{ sourceFiles.length }}</span>
          </header>
          <div v-if="sourceFilesLoading" class="source-file-state" role="status">
            <LoaderCircle class="spin" :size="14" aria-hidden="true" />
            正在读取文件树
          </div>
          <div
            v-else-if="sourceFilesError && sourceFiles.length === 0"
            class="source-file-state source-file-state--error"
            role="alert"
          >
            <TriangleAlert :size="14" aria-hidden="true" />
            {{ sourceFilesError }}
          </div>
          <div
            v-else-if="visibleSourceFiles.length"
            class="source-file-tree"
            role="tree"
            aria-label="项目源码文件"
          >
            <button
              v-for="file in visibleSourceFiles"
              :key="file.id"
              class="source-file-row"
              :class="{ 'source-file-row--active': selectedSourceFileId === file.id }"
              type="button"
              role="treeitem"
              :aria-selected="selectedSourceFileId === file.id"
              :aria-level="sourceFileDepth(file) + 1"
              :title="file.logicalPath"
              :style="{ paddingLeft: `${12 + sourceFileDepth(file) * 10}px` }"
              @click="emit('selectSourceFile', file.id)"
            >
              <FileCode2 :size="13" aria-hidden="true" />
              <span>
                <strong>{{ sourceFileName(file) }}</strong>
                <small>{{ sourceFileDirectory(file) }} · {{ file.language }} · {{ file.lineCount }} 行</small>
              </span>
            </button>
            <p v-if="sourceFilesTruncated" class="source-file-limit" role="status">
              文件较多，仅渲染前 {{ MAX_RENDERED_SOURCE_FILES }} 项；可用上方搜索定位其余文件。
            </p>
          </div>
          <div v-else class="source-file-state" role="status">
            该项目没有匹配的源码文件
          </div>
        </section>
      </aside>

      <section class="code-panel" aria-label="只读反编译输出">
        <template v-if="selectedResult">
          <header class="code-panel__heading">
            <div class="code-panel__title">
              <span>
                <strong>
                  {{ selectedSourceFile?.logicalPath || selectedResult.display_name || selectedResult.symbol_key }}
                </strong>
                <small>
                  {{ selectedSourceFile ? '源码文件' : (unitLabels[selectedResult.symbol_kind] ?? '项目') }}
                </small>
              </span>
              <code>
                {{ selectedSourceFile ? `${selectedSourceFile.lineCount} 行 · ${selectedSourceFile.sizeBytes} bytes` : (selectedResult.signature || '项目元数据不可用') }}
              </code>
            </div>
            <div class="code-panel__badges" aria-label="代码属性">
              <span>{{ languageLabel }}</span>
              <span>只读</span>
              <span>非原始源码</span>
            </div>
          </header>

          <div class="code-panel__meta">
            <span>路径 <code>{{ selectedSourceFile?.logicalPath || selectedResult.location || '未知' }}</code></span>
            <span>{{ selectedResult.detail || '无附加符号信息' }}</span>
            <span class="mono">task: {{ taskId }}</span>
          </div>

          <BytecodeAnalyzerSummary
            v-if="analyzerSummary.present"
            :summary="analyzerSummary"
          />

          <BytecodeMethodIndexPanel
            v-if="isJvmBytecodeResult && bytecodeMethodIndex.present"
            :key="selectedResult.id"
            :index="bytecodeMethodIndex"
            :selected-key="activeBytecodeMethodKey"
            @select="selectBytecodeMethod"
          />

          <div
            v-if="sourceLoading && !source"
            class="code-panel__state"
            role="status"
          >
            <LoaderCircle class="spin" :size="22" aria-hidden="true" />
            <strong>正在安全读取反编译输出</strong>
          </div>
          <div
            v-else-if="sourceError && !source"
            class="code-panel__state code-panel__state--error"
            role="alert"
          >
            <TriangleAlert :size="22" aria-hidden="true" />
            <strong>{{ sourceError }}</strong>
          </div>
          <ReadOnlyCodeEditor
            v-else-if="sourceFile"
            :source="source"
            :language="editorLanguage"
            :label="`只读${languageLabel}反编译输出`"
            :model-uri="editorModelUri"
            :target-range="targetRange"
          />
          <div v-else class="code-panel__state" role="status">
            <FileCode2 :size="24" aria-hidden="true" />
            <strong>该单元没有可读取的文本输出</strong>
            <span>{{ capabilityMessage }}</span>
          </div>

          <footer class="code-panel__footnote">
            <span>此内容由反编译或字节码分析产生，不代表原始源代码。</span>
            <span v-if="sourceFilesError" class="code-panel__footnote-error">
              {{ sourceFilesError }}
            </span>
          </footer>
        </template>
      </section>
    </div>
  </div>
</template>

<style scoped>
.decompile-workspace {
  min-width: 0;
}

.capability-strip {
  display: grid;
  min-height: 62px;
  grid-template-columns: minmax(180px, auto) minmax(220px, 1fr) auto;
  align-items: center;
  gap: 16px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--line);
  background: var(--surface-raised);
}

.capability-strip__identity {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 9px;
  color: var(--primary-hover);
}

.capability-strip__identity span {
  display: grid;
  gap: 2px;
}

.capability-strip small,
.capability-strip p {
  margin: 0;
  color: var(--ink-600);
  font-size: 12px;
  line-height: 1.45;
}

.capability-strip strong {
  color: var(--ink-800);
  font-size: 13px;
}

.capability-strip__engine {
  max-width: 260px;
  overflow: hidden;
  padding: 4px 7px;
  border: 1px solid var(--primary-border);
  border-radius: var(--radius-sm);
  color: var(--primary);
  background: var(--surface);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.capability-strip__engine--partial,
.capability-strip__engine--bytecode_only,
.capability-strip__engine--unsupported,
.capability-strip__engine--failed,
.capability-strip__engine--cancelled {
  border-color: var(--warning-border);
  color: var(--warning);
  background: var(--warning-soft);
}

.capability-warning {
  display: flex;
  min-width: 0;
  align-items: flex-start;
  gap: 8px;
  padding: 8px 14px;
  border-bottom: 1px solid var(--warning-border);
  color: var(--warning);
  background: var(--warning-soft);
  font-size: 12px;
  line-height: 1.5;
}

.capability-warning svg {
  flex: 0 0 auto;
}

.capability-warning strong {
  white-space: nowrap;
}

.capability-warning span {
  min-width: 0;
  overflow-wrap: anywhere;
}

.decompile-workspace__body {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(250px, 31%) minmax(0, 1fr);
}

.symbol-panel {
  min-width: 0;
  border-right: 1px solid var(--line);
  background: var(--surface);
}

.symbol-panel__heading {
  display: grid;
  gap: 9px;
  padding: 12px;
  border-bottom: 1px solid var(--line);
}

.symbol-panel__heading > div {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.symbol-panel__heading strong {
  color: var(--ink-800);
  font-size: 12px;
}

.symbol-panel__heading span {
  color: var(--ink-600);
  font-size: 11px;
}

.symbol-search {
  display: grid;
  height: 32px;
  grid-template-columns: 18px minmax(0, 1fr);
  align-items: center;
  gap: 4px;
  padding: 0 8px;
  border: 1px solid var(--line-strong);
  border-radius: var(--radius-sm);
  color: var(--ink-600);
  background: var(--surface);
}

.symbol-search:focus-within {
  border-color: var(--primary);
  box-shadow: 0 0 0 2px rgb(37 99 235 / 12%);
}

.symbol-search input {
  min-width: 0;
  border: 0;
  outline: 0;
  color: var(--ink-800);
  background: transparent;
  font: inherit;
  font-size: 12px;
}

.result-filters {
  display: grid;
  min-width: 0;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  border: 1px solid var(--line-strong);
  border-radius: var(--radius-sm);
  overflow: hidden;
  background: var(--surface);
}

.result-filters button {
  display: grid;
  min-width: 0;
  min-height: 38px;
  grid-template-columns: 13px minmax(0, 1fr);
  grid-template-rows: auto auto;
  align-items: center;
  column-gap: 3px;
  padding: 4px 3px;
  border: 0;
  border-right: 1px solid var(--line-strong);
  color: var(--ink-600);
  background: transparent;
  cursor: pointer;
  font: inherit;
  text-align: left;
}

.result-filters button:last-child {
  border-right: 0;
}

.result-filters button:hover {
  background: var(--primary-soft);
}

.result-filters button:focus-visible {
  position: relative;
  z-index: 1;
  outline: 2px solid var(--primary);
  outline-offset: -2px;
}

.result-filters button > span {
  overflow: hidden;
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.result-filters button > code {
  grid-column: 2;
  color: inherit;
  font-size: 11px;
}

.result-filters .result-filter--active {
  color: var(--primary-hover);
  background: var(--primary-soft);
  box-shadow: inset 0 -2px 0 var(--primary);
}

.symbol-tree {
  max-height: 620px;
  overflow: auto;
  padding: 8px 0 12px;
}

.symbol-group h4 {
  margin: 0;
  overflow: hidden;
  padding: 8px 12px 5px;
  color: var(--ink-600);
  font-size: 11px;
  font-weight: 700;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.symbol-row {
  display: grid;
  width: 100%;
  min-height: 47px;
  grid-template-columns: 16px minmax(0, 1fr) auto;
  align-items: center;
  gap: 7px;
  padding: 6px 10px 6px 12px;
  border: 0;
  border-left: 3px solid transparent;
  color: var(--ink-600);
  background: transparent;
  cursor: pointer;
  text-align: left;
}

.symbol-row:hover {
  background: var(--primary-soft);
}

.symbol-row:focus-visible {
  outline: 2px solid var(--primary);
  outline-offset: -2px;
}

.symbol-row--active {
  border-left-color: var(--primary);
  color: var(--primary-hover);
  background: var(--primary-soft);
}

.symbol-row__main {
  display: grid;
  min-width: 0;
  gap: 3px;
}

.symbol-row__main strong,
.symbol-row__main small {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.symbol-row__main strong {
  color: var(--ink-800);
  font-size: 12px;
}

.symbol-row__main small,
.symbol-row__kind {
  color: var(--ink-600);
  font-size: 11px;
}

.symbol-row__kind {
  padding: 2px 4px;
  border: 1px solid var(--line-strong);
  border-radius: var(--radius-sm);
  white-space: nowrap;
}

.symbol-panel__empty,
.code-panel__state {
  display: flex;
  min-height: 260px;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  gap: 8px;
  padding: 24px;
  color: var(--ink-600);
  font-size: 12px;
  text-align: center;
}

.load-more {
  display: flex;
  width: calc(100% - 24px);
  height: 32px;
  align-items: center;
  justify-content: center;
  gap: 6px;
  margin: 8px 12px 0;
  border: 1px solid var(--line-strong);
  border-radius: var(--radius-sm);
  color: var(--primary-hover);
  background: var(--surface);
  cursor: pointer;
  font: inherit;
  font-size: 11px;
}

.load-more:disabled {
  cursor: wait;
  opacity: 0.65;
}

.source-file-group {
  margin-top: 10px;
  border-top: 1px solid var(--line);
}

.source-file-group > header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 10px 12px 7px;
}

.source-file-group > header strong {
  color: var(--ink-800);
  font-size: 12px;
}

.source-file-group > header span {
  color: var(--ink-600);
  font-size: 11px;
}

.source-file-tree {
  max-height: 360px;
  overflow: auto;
  padding-bottom: 10px;
}

.source-file-row {
  display: grid;
  width: 100%;
  min-height: 42px;
  grid-template-columns: 16px minmax(0, 1fr);
  align-items: center;
  gap: 7px;
  padding: 6px 10px 6px 12px;
  border: 0;
  border-left: 3px solid transparent;
  color: var(--ink-600);
  background: transparent;
  cursor: pointer;
  text-align: left;
}

.source-file-row:hover {
  background: var(--primary-soft);
}

.source-file-row:focus-visible {
  outline: 2px solid var(--primary);
  outline-offset: -2px;
}

.source-file-row--active {
  border-left-color: var(--primary);
  color: var(--primary-hover);
  background: var(--primary-soft);
}

.source-file-row > span {
  display: grid;
  min-width: 0;
  gap: 3px;
}

.source-file-row strong,
.source-file-row small {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.source-file-row strong {
  color: var(--ink-800);
  font-size: 11px;
}

.source-file-row small {
  color: var(--ink-600);
  font-size: 11px;
}

.source-file-state {
  display: flex;
  min-height: 64px;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 12px;
  color: var(--ink-600);
  font-size: 11px;
  text-align: center;
}

.source-file-state--error,
.code-panel__footnote-error {
  color: var(--danger);
}

.source-file-limit {
  margin: 6px 12px 2px;
  padding: 7px 8px;
  border: 1px solid var(--line-strong);
  border-radius: var(--radius-sm);
  color: var(--ink-600);
  background: var(--surface-raised);
  font-size: 11px;
  line-height: 1.5;
}

.code-panel {
  min-width: 0;
  background: var(--surface);
}

.code-panel__heading {
  display: flex;
  min-height: 64px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 9px 14px;
  border-bottom: 1px solid var(--line);
}

.code-panel__title {
  display: grid;
  min-width: 0;
  gap: 5px;
}

.code-panel__title > span {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
}

.code-panel__title strong {
  overflow: hidden;
  color: var(--ink-800);
  font-size: 13px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.code-panel__title small,
.code-panel__badges span {
  padding: 2px 5px;
  border: 1px solid var(--line-strong);
  border-radius: var(--radius-sm);
  color: var(--ink-600);
  font-size: 11px;
  white-space: nowrap;
}

.code-panel__title code {
  overflow: hidden;
  color: var(--ink-600);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.code-panel__badges {
  display: flex;
  flex: 0 0 auto;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 5px;
}

.code-panel__meta {
  display: flex;
  min-height: 36px;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px 16px;
  padding: 7px 14px;
  border-bottom: 1px solid var(--line);
  color: var(--ink-600);
  background: var(--surface-raised);
  font-size: 11px;
}

.code-panel__meta code {
  color: var(--ink-800);
}

.code-panel__state {
  min-height: 380px;
  color: var(--ink-600);
  background: var(--surface);
}

.code-panel__state strong {
  color: var(--ink-800);
  font-size: 12px;
}

.code-panel__state--error {
  color: var(--danger);
}

.code-panel__footnote {
  display: flex;
  min-height: 38px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 7px 12px;
  border-top: 1px solid var(--line);
  color: var(--ink-600);
  background: var(--surface-raised);
  font-size: 11px;
}

.code-panel__footnote button {
  display: inline-flex;
  height: 25px;
  align-items: center;
  gap: 4px;
  padding: 0 7px;
  border: 1px solid var(--primary-border);
  border-radius: var(--radius-sm);
  color: var(--primary-hover);
  background: var(--surface);
  cursor: pointer;
  font: inherit;
  font-size: 11px;
}

.spin {
  animation: spin 0.9s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

@container (max-width: 720px) {
  .capability-strip {
    grid-template-columns: 1fr;
    gap: 7px;
  }

  .capability-strip__engine {
    max-width: 100%;
    width: fit-content;
  }

  .decompile-workspace__body {
    grid-template-columns: 1fr;
  }

  .symbol-panel {
    border-right: 0;
    border-bottom: 1px solid var(--line);
  }

  .symbol-tree {
    max-height: 310px;
  }
}

@media (max-width: 520px) {
  .code-panel__heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .code-panel__badges {
    justify-content: flex-start;
  }
}
</style>
