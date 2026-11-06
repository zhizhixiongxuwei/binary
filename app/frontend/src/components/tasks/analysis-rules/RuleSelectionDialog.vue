<script setup lang="ts">
import { computed, useId } from 'vue'
import { ListChecks, LoaderCircle, RefreshCw, Search } from 'lucide-vue-next'

import type { AnalysisRuleCatalog, AnalysisRuleSelectionInput } from '@/api/types'
import { analysisEngineLabel } from '@/utils/analysisPresentation'
import { ruleSeverityLabel } from './ruleSelection'
import { useRuleSelectionState } from './useRuleSelectionState'

const props = withDefaults(defineProps<{
  open: boolean
  catalog: AnalysisRuleCatalog | null
  loading?: boolean
  pending?: boolean
  errorMessage?: string
  stale?: boolean
  canStart?: boolean
}>(), { loading: false, pending: false, errorMessage: '', stale: false, canStart: true })

const emit = defineEmits<{
  confirm: [input: AnalysisRuleSelectionInput]
  close: []
  retry: []
}>()
const dialogId = `rule-selection-${useId().replace(/:/g, '')}`
const blocked = computed(() => props.loading || props.pending || Boolean(props.errorMessage)
  || !props.canStart || props.stale || !props.catalog?.available || props.catalog.freshness !== 'fresh')
const selection = useRuleSelectionState({ open: () => props.open, catalog: () => props.catalog, blocked: () => blocked.value })
const unavailableReason = computed(() => {
  if (props.errorMessage) return props.errorMessage
  if (!props.catalog) return props.loading ? '' : '尚未读取规则目录，请重试。'
  if (!props.canStart && !props.pending) return '当前项目暂时无法开始检测，请检查启动权限或等待正在执行的操作结束。'
  if (props.stale || props.catalog.freshness === 'stale') return '规则目录已过期，请重新读取后选择。'
  if (props.catalog.freshness === 'conflict') return '检测引擎的规则目录不一致，请检查引擎后重试。'
  if (!props.catalog.available || props.catalog.freshness === 'missing') return props.catalog.detail || '当前检测引擎尚未提供可用规则目录。'
  if (!props.catalog.rules.length) return '当前引擎没有可供选择的规则。'
  return ''
})

function close(): void { if (!props.pending) emit('close') }
function confirm(): void {
  const input = selection.confirmation()
  if (input) emit('confirm', input)
}
function checkboxId(id: string): string { return `${dialogId}-${encodeURIComponent(id)}` }
</script>

<template>
  <el-dialog
    :model-value="open"
    class="rule-selection-dialog"
    width="min(940px, calc(100vw - 28px))"
    align-center
    :close-on-click-modal="false"
    :close-on-press-escape="!pending"
    :show-close="!pending"
    destroy-on-close
    @update:model-value="(visible: boolean) => { if (!visible) close() }"
  >
    <template #header>
      <div class="rules-heading"><ListChecks :size="22" aria-hidden="true" /><div><h2>选择本次检测规则</h2><p>默认选择全部规则，可调整本次检测范围。</p></div></div>
    </template>
    <div class="rules-content" :aria-busy="loading || pending">
      <dl v-if="catalog" class="rules-engine" aria-label="当前检测引擎与规则目录">
        <div><dt>检测引擎</dt><dd>{{ analysisEngineLabel(catalog.engine.name) }}</dd></div>
        <div><dt>引擎版本</dt><dd class="mono">{{ catalog.engine.version || '未提供' }}</dd></div>
        <div><dt>规则总数</dt><dd><strong class="mono">{{ catalog.rules.length }}</strong> 条</dd></div>
        <div class="rules-engine__catalog"><dt>目录版本</dt><dd class="mono">{{ catalog.catalogVersion || '未提供' }}</dd></div>
      </dl>
      <p v-if="loading" class="rules-state" role="status"><LoaderCircle :size="17" class="spin" aria-hidden="true" />正在读取当前引擎规则…</p>
      <div v-if="unavailableReason" class="rules-error" role="alert"><span>{{ unavailableReason }}</span><button v-if="canStart" type="button" :disabled="loading || pending" @click="emit('retry')"><RefreshCw :size="14" aria-hidden="true" />重新读取规则</button></div>
      <template v-if="catalog?.rules.length">
        <div class="rules-filters">
          <label class="rules-keyword"><Search :size="15" aria-hidden="true" /><input v-model="selection.keyword.value" type="search" placeholder="搜索中文名称、说明、规则 ID 或 CWE" aria-label="搜索检测规则" :disabled="blocked" maxlength="200"></label>
          <label class="rules-category"><span>CWE 分类</span><select v-model="selection.cwe.value" aria-label="按 CWE 分类筛选规则" :disabled="blocked"><option value="">全部分类</option><option v-for="category in selection.categories.value" :key="category" :value="category">{{ category }}</option></select></label>
        </div>
        <div class="rules-selection-toolbar">
          <span>显示 {{ selection.filteredRules.value.length }} / {{ catalog.rules.length }} 条</span>
          <div><button type="button" :disabled="blocked" title="选择目录中的全部规则，包括筛选外的规则" @click="selection.selectAll">全选</button><button type="button" :disabled="blocked || !selection.selectedCount.value" @click="selection.clearSelection">清空选择</button></div>
        </div>
        <div class="rules-list" role="group" aria-label="本次启用的检测规则">
          <article v-for="rule in selection.filteredRules.value" :key="rule.id" class="rule-row" :class="{ 'rule-row--selected': selection.selectedIds.value.has(rule.id) }">
            <input :id="checkboxId(rule.id)" type="checkbox" :checked="selection.selectedIds.value.has(rule.id)" :disabled="blocked" :aria-describedby="`${checkboxId(rule.id)}-description`" @change="selection.toggle(rule.id)">
            <div class="rule-body">
              <div class="rule-title"><label :for="checkboxId(rule.id)">{{ rule.name }}</label><span class="rule-severity" :class="`rule-severity--${rule.severity.toLowerCase()}`" :title="`引擎默认严重度：${rule.severity}`">{{ ruleSeverityLabel(rule.severity) }}</span></div>
              <div class="rule-identifiers"><code>{{ rule.id }}</code><span v-for="category in rule.cwes" :key="category" class="mono">{{ category }}</span></div>
              <p :id="`${checkboxId(rule.id)}-description`" class="rule-description">{{ rule.description }}</p>
              <details v-if="rule.limitations.length" class="rule-limitations"><summary>适用范围与限制（{{ rule.limitations.length }}）</summary><ul><li v-for="limitation in rule.limitations" :key="limitation">{{ limitation }}</li></ul></details>
            </div>
          </article>
          <div v-if="!selection.filteredRules.value.length" class="rules-no-match" role="status"><span>没有符合筛选条件的规则。</span><button type="button" @click="selection.clearFilters">清除筛选</button></div>
        </div>
      </template>
      <p class="rules-scope">规则选择仅用于本次检测。严重度采用引擎默认值。</p>
    </div>
    <template #footer>
      <div class="rules-footer"><div aria-live="polite"><strong>已选 {{ selection.selectedCount.value }} / {{ catalog?.rules.length ?? 0 }} 条</strong><span v-if="catalog?.rules.length && !selection.selectedCount.value">请至少选择一条规则。</span></div><div><el-button :disabled="pending" @click="close">取消</el-button><el-button type="primary" :disabled="!selection.canConfirm.value" :loading="pending" data-confirm="analysis-rules" @click="confirm">{{ pending ? '正在确认…' : '开始检测' }}</el-button></div></div>
    </template>
  </el-dialog>
</template>

<style scoped>
.rules-heading { display: flex; align-items: center; gap: 11px; color: var(--primary); }
.rules-heading h2 { margin: 0; color: var(--ink-950); font-size: 18px; }
.rules-heading p { margin: 5px 0 0; color: var(--ink-500); font-size: 12px; }
.rules-content { min-width: 0; }
.rules-engine { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) 100px; gap: 13px 20px; margin: 0 0 17px; padding: 13px 15px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-raised); }
.rules-engine dt { color: var(--ink-500); font-size: 11px; }
.rules-engine dd { margin: 5px 0 0; color: var(--ink-800); font-size: 12px; overflow-wrap: anywhere; }
.rules-engine__catalog { grid-column: 1 / -1; }
.rules-engine__catalog dd { color: var(--ink-500); font-size: 11px; }
.rules-state, .rules-error { display: flex; align-items: center; gap: 8px; margin: 0 0 13px; padding: 11px 12px; border-radius: 6px; font-size: 12px; line-height: 1.6; }
.rules-state { color: var(--primary); background: var(--primary-soft); }
.rules-error { justify-content: space-between; flex-wrap: wrap; color: var(--danger); background: var(--danger-soft); }
.rules-error span { min-width: 0; overflow-wrap: anywhere; }
.rules-error button { display: inline-flex; align-items: center; flex-shrink: 0; gap: 5px; }
.rules-filters { display: grid; grid-template-columns: minmax(0, 1fr) minmax(140px, .4fr); gap: 10px; }
.rules-keyword { display: flex; min-width: 0; align-items: center; gap: 7px; padding: 0 10px; border: 1px solid var(--line-strong); border-radius: 6px; color: var(--ink-500); }
.rules-keyword input { width: 100%; min-width: 0; min-height: 35px; padding: 6px 0; border: 0; outline: 0; color: var(--ink-800); background: transparent; font: inherit; font-size: 12px; }
.rules-keyword:focus-within { outline: 2px solid var(--primary-border); }
.rules-category { display: flex; min-width: 0; align-items: center; gap: 7px; color: var(--ink-600); font-size: 12px; }
.rules-category > span { flex-shrink: 0; }
.rules-category select { min-width: 0; min-height: 35px; flex: 1; padding: 5px 7px; border: 1px solid var(--line-strong); border-radius: 6px; color: var(--ink-800); background: var(--surface); font-size: 12px; }
.rules-selection-toolbar { display: flex; justify-content: space-between; gap: 10px; margin: 12px 0 9px; color: var(--ink-500); font-size: 12px; }
.rules-selection-toolbar > div { display: flex; gap: 14px; }
.rules-content button { padding: 0; border: 0; color: var(--primary); background: transparent; font: inherit; font-size: 12px; cursor: pointer; }
.rules-content button:disabled { color: var(--ink-400); cursor: not-allowed; }
.rules-content button:focus-visible, .rule-row input:focus-visible, .rules-category select:focus-visible { outline: 2px solid var(--primary); outline-offset: 3px; }
.rules-list { max-height: min(46vh, 440px); overflow: auto; overscroll-behavior: contain; border: 1px solid var(--line); border-radius: 8px; }
.rule-row { display: grid; grid-template-columns: 18px minmax(0, 1fr); align-items: start; gap: 10px; padding: 13px 14px; border-bottom: 1px solid var(--line); }
.rule-row:last-child { border-bottom: 0; }
.rule-row--selected { background: var(--primary-soft); }
.rule-row > input { width: 16px; height: 16px; margin: 3px 0 0; accent-color: var(--primary); cursor: pointer; }
.rule-row > input:disabled { cursor: not-allowed; }
.rule-body { min-width: 0; }
.rule-title { display: flex; align-items: flex-start; justify-content: space-between; flex-wrap: wrap; gap: 6px 12px; }
.rule-title label { color: var(--ink-900); font-size: 13px; font-weight: 600; cursor: pointer; overflow-wrap: anywhere; }
.rule-severity { padding: 2px 6px; border: 1px solid var(--line-strong); border-radius: 4px; color: var(--ink-600); background: var(--surface); font-size: 10px; white-space: nowrap; }
.rule-severity--high, .rule-severity--critical { border-color: var(--danger-border); color: var(--danger); background: var(--danger-soft); }
.rule-severity--medium { border-color: var(--warning-border); color: var(--warning); background: var(--warning-soft); }
.rule-identifiers { display: flex; flex-wrap: wrap; gap: 5px 10px; margin-top: 6px; color: var(--ink-500); font-size: 11px; overflow-wrap: anywhere; }
.rule-identifiers code { color: var(--primary-hover); }
.rule-description { margin: 7px 0 0; color: var(--ink-700); font-size: 12px; line-height: 1.7; overflow-wrap: anywhere; }
.rule-limitations { margin-top: 7px; color: var(--ink-500); font-size: 11px; line-height: 1.6; }
.rule-limitations summary { cursor: pointer; }
.rule-limitations ul { margin: 5px 0 0; padding-left: 18px; }
.rules-no-match { display: grid; place-items: center; gap: 10px; min-height: 130px; padding: 20px; color: var(--ink-500); font-size: 12px; }
.rules-scope { margin: 12px 0 0; color: var(--ink-500); font-size: 12px; line-height: 1.6; }
.rules-footer { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; text-align: left; }
.rules-footer > div:first-child { display: grid; gap: 5px; color: var(--ink-700); font-size: 12px; }
.rules-footer > div:first-child span { color: var(--danger); }
.spin { animation: rules-spin 1s linear infinite; }
@keyframes rules-spin { to { transform: rotate(360deg); } }
@media(max-width: 600px) { .rules-filters { grid-template-columns: 1fr; } .rules-engine { grid-template-columns: repeat(2, minmax(0, 1fr)); } .rules-list { max-height: 40vh; } .rules-footer > div:last-child { display: flex; width: 100%; justify-content: flex-end; } }
@media(prefers-reduced-motion: reduce) { .spin { animation: none; } }
</style>
