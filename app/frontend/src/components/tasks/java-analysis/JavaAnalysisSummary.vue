<script setup lang="ts">
import { AlertTriangle, CircleCheck, Cpu, FileWarning } from 'lucide-vue-next'
import { computed } from 'vue'

import type { JavaAnalysisDiagnostic, JavaAnalysisRun, JavaAnalysisSeverity, SourceNavigationTarget } from '@/api/types'
import RuleSelectionSummary from '@/components/tasks/analysis-rules/RuleSelectionSummary.vue'
import { formatBytes, formatDateTime } from '@/utils/formatters'
import { analysisEngineLabel, analysisMessage } from '@/utils/analysisPresentation'

const props = defineProps<{
  run: JavaAnalysisRun
}>()

const emit = defineEmits<{ openSource: [target: SourceNavigationTarget] }>()
const summary = computed(() => props.run.analysis_summary)
const engineLabels: Record<string, string> = { complete: '已完成', partial: '部分完成', skipped: '已跳过', not_requested: '未选择', failed: '失败', unknown: '未知' }
const reasonLabels: Record<string, string> = { input_too_large: '输入超过分析上限', timeout: '分析超时' }
const scopeCounts = computed(() => {
  const scope = summary.value?.scope
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) return undefined
  const modules = (scope as Record<string, unknown>).modules
  if (!Array.isArray(modules)) return undefined
  return { application: modules.filter((item) => item && typeof item === 'object' && !Array.isArray(item) && item.role === 'application').length,
    dependency: modules.filter((item) => item && typeof item === 'object' && !Array.isArray(item) && item.role === 'dependency').length }
})
function openDiagnostic(item: JavaAnalysisDiagnostic) {
  if (!item.path || !item.line) return
  emit('openSource', { projectId: props.run.source_project_id, path: item.path, startLine: item.line, endLine: item.line, startColumn: item.column ?? 1, endColumn: item.column ?? 1 })
}
const statusLabels: Readonly<Record<JavaAnalysisRun['status'], string>> = {
  queued: '排队中',
  running: '检测中',
  succeeded: '已完成',
  partial: '部分完成',
  failed: '失败',
  cancel_requested: '正在取消',
  cancelled: '已取消',
}
const severityMetrics: readonly {
  id: JavaAnalysisSeverity
  label: string
}[] = [
  { id: 'CRITICAL', label: '严重' },
  { id: 'HIGH', label: '高危' },
  { id: 'MEDIUM', label: '中危' },
  { id: 'LOW', label: '低危' },
]
const coveragePercent = computed(() =>
  props.run.coverage.total_files > 0 && props.run.coverage.analyzed_files !== null
    ? Math.round(
        (props.run.coverage.analyzed_files /
          props.run.coverage.total_files) *
          100,
      )
    : null,
)
</script>

<template>
  <RuleSelectionSummary :selection="run.selection" />
  <section class="analysis-summary" aria-label="Java 源码检测汇总">
    <div class="analysis-summary__identity">
      <CircleCheck
        v-if="run.status === 'succeeded'"
        :size="18"
        aria-hidden="true"
      />
      <AlertTriangle v-else :size="18" aria-hidden="true" />
      <span>
        <small>检测状态</small>
        <strong>{{ statusLabels[run.status] }}</strong>
      </span>
    </div>
    <div class="analysis-summary__metric analysis-summary__metric--total">
      <small>发现总数</small>
      <strong>{{ run.finding_count }}</strong>
    </div>
    <div
      v-for="metric in severityMetrics"
      :key="metric.id"
      class="analysis-summary__metric"
      :class="`analysis-summary__metric--${metric.id.toLowerCase()}`"
    >
      <small>{{ metric.label }}</small>
      <strong>{{ run.severity_counts[metric.id] }}</strong>
    </div>
    <div class="analysis-summary__coverage">
      <Cpu :size="15" aria-hidden="true" />
      <span>
        <small>文件覆盖</small>
        <strong v-if="coveragePercent !== null">{{ run.coverage.analyzed_files }}/{{ run.coverage.total_files }} · {{ coveragePercent }}%</strong>
        <strong v-else>覆盖统计未知 · {{ run.coverage.total_files }} 个源码文件</strong>
        <small>解析 {{ run.coverage.parsed_files ?? '未知' }} · 失败 {{ run.coverage.failed_files ?? '未知' }}</small>
      </span>
    </div>
  </section>

  <section class="analysis-meta" aria-label="Java 源码检测版本信息">
    <span><small>检测器</small><span>{{ analysisEngineLabel(run.analyzer_name) }}</span></span>
    <span><small>规则集</small><code>{{ run.ruleset_version || '等待引擎返回' }}</code></span>
    <span><small>源码</small><code>{{ formatBytes(run.source_size_bytes) }} · {{ run.source_file_count }} 文件</code></span>
    <span><small>解析诊断</small><code>{{ run.diagnostic_count ?? '未知' }}</code></span>
    <span><small>创建时间</small><time :datetime="run.created_at">{{ formatDateTime(run.created_at) }}</time></span>
  </section>

  <div
    v-if="run.status === 'partial' || run.findings_truncated || run.diagnostics_truncated"
    class="analysis-notice"
    role="status"
  >
    <FileWarning :size="16" aria-hidden="true" />
    <span>
      检测结果不完整<span v-if="(run.coverage.failed_files ?? 0) > 0">，{{ run.coverage.failed_files }} 个文件未成功解析</span><span v-if="run.findings_truncated">，发现数量达到上限</span><span v-if="run.diagnostics_truncated">，诊断数量达到上限</span>。
    </span>
  </div>

  <section class="analysis-diagnostics" aria-label="Java 分析覆盖与诊断">
    <template v-if="summary">
      <div class="analysis-engines">
        <span v-for="(engine, name) in summary.engines" :key="name">
          <strong>{{ name === 'source' ? '源码引擎' : '字节码引擎' }}</strong>：{{ engineLabels[engine.status] ?? engine.status }}
          <span v-if="engine.reason"> · {{ reasonLabels[engine.reason] ?? engine.reason }}</span>
        </span>
      </div>
      <p v-if="summary.coverage.totalMethods !== null">方法：{{ summary.coverage.analyzedMethods ?? '未知' }}/{{ summary.coverage.totalMethods }}；未解析调用：{{ summary.coverage.unresolvedCalls ?? '未知' }}</p>
      <p v-if="scopeCounts">选定业务模块 {{ scopeCounts.application }} 个，依赖模块 {{ scopeCounts.dependency }} 个。实际完成范围以执行统计和诊断为准。</p>
      <p v-if="summary.historical">历史证据已恢复；未保存的覆盖统计显示未知。</p>
      <details v-if="summary.diagnostics.length">
        <summary>查看 {{ run.diagnostic_count ?? summary.diagnostics.length }} 条诊断</summary>
        <ol>
          <li v-for="(item, index) in summary.diagnostics" :key="index">
            <code>{{ item.code }}</code> {{ item.message }}
            <button v-if="item.path && item.line" type="button" @click="openDiagnostic(item)">{{ item.path }}:{{ item.line }}</button>
            <span v-else-if="item.path"> · {{ item.path }}</span>
          </li>
        </ol>
      </details>
    </template>
    <p v-else>该运行尚未提供可验证的覆盖与诊断统计，无法据此确认全部源码已完成检测。</p>
  </section>

  <div v-if="run.error_message" class="analysis-error" role="alert">
    <AlertTriangle :size="16" aria-hidden="true" />
    <span><code>{{ run.error_code || 'java_analysis_failed' }}</code>{{ analysisMessage(run.error_message) }}</span>
  </div>
</template>

<style scoped>
.analysis-diagnostics { padding: 10px 14px; border-bottom: 1px solid var(--line); color: var(--ink-600); font-size: 12px; }
.analysis-diagnostics p { margin: 6px 0; }
.analysis-engines { display: flex; flex-wrap: wrap; gap: 8px 24px; }
.analysis-diagnostics summary { cursor: pointer; }
.analysis-diagnostics ol { max-height: 300px; overflow: auto; padding-left: 22px; }
.analysis-diagnostics li { margin: 8px 0; overflow-wrap: anywhere; }
.analysis-diagnostics button { border: 0; background: transparent; color: var(--primary); cursor: pointer; text-align: left; }

.analysis-summary {
  display: grid;
  grid-template-columns: minmax(128px, 1.25fr) repeat(5, minmax(74px, 0.65fr)) minmax(150px, 1.2fr);
  border-bottom: 1px solid var(--line);
  background: var(--surface);
}

.analysis-summary > div {
  display: flex;
  min-width: 0;
  min-height: 70px;
  align-items: center;
  gap: 9px;
  padding: 10px 14px;
  border-right: 1px solid var(--line);
}

.analysis-summary > div:last-child { border-right: 0; }
.analysis-summary span { display: grid; min-width: 0; gap: 2px; }
.analysis-summary small,
.analysis-meta small { color: var(--ink-400); font-size: 11px; font-weight: 700; }
.analysis-summary strong { color: var(--ink-800); font-size: 15px; font-variant-numeric: tabular-nums; }
.analysis-summary__identity { color: var(--primary-hover); }
.analysis-summary__metric--critical { border-top: 3px solid var(--danger); }
.analysis-summary__metric--high { border-top: 3px solid var(--orange); }
.analysis-summary__metric--medium { border-top: 3px solid var(--warning); }
.analysis-summary__metric--low { border-top: 3px solid var(--primary); }
.analysis-summary__metric--total { border-top: 3px solid var(--ink-600); }
.analysis-summary__coverage { color: var(--primary); }
.analysis-summary__coverage strong { font-size: 12px; }

.analysis-meta {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 1px;
  border-bottom: 1px solid var(--line);
  background: var(--line);
}

.analysis-meta > span {
  display: grid;
  min-width: 0;
  gap: 3px;
  padding: 8px 14px;
  background: var(--surface);
}

.analysis-meta code,
.analysis-meta time {
  overflow: hidden;
  color: var(--ink-600);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.analysis-notice,
.analysis-error {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 9px 14px;
  border-bottom: 1px solid var(--warning-border);
  color: var(--warning);
  background: var(--warning-soft);
  font-size: 12px;
}

.analysis-error {
  border-color: var(--danger-border);
  color: var(--danger);
  background: var(--danger-soft);
}

.analysis-error span { display: flex; gap: 8px; }

@container (max-width: 980px) {
  .analysis-summary { grid-template-columns: repeat(4, minmax(90px, 1fr)); }
  .analysis-summary > div { border-bottom: 1px solid var(--line); }
  .analysis-meta { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

@container (max-width: 560px) {
  .analysis-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .analysis-meta { grid-template-columns: minmax(0, 1fr); }
}
</style>
