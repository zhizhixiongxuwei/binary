<script setup lang="ts">
import { DatabaseZap, RefreshCw } from 'lucide-vue-next'
import { computed } from 'vue'

import type { SystemStatus } from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import AnalyzerTechnicalDetails from './AnalyzerTechnicalDetails.vue'
import { analysisEngineLabel, analysisMessage } from '@/utils/analysisPresentation'
import {
  analyzerProbeHealth,
  analyzerProbeDescription,
  databaseBundleHealth,
} from '@/components/system/maintenance/systemStatusPresentation'
import { formatBytes, formatDateTime } from '@/utils/formatters'

const props = defineProps<{
  status: SystemStatus | null
  loading: boolean
  errorMessage: string
}>()

defineEmits<{ retry: [] }>()

const analyzers = computed(() => props.status?.analyzers ?? [])
const bundle = computed(() => props.status?.trivy_database_bundle ?? null)
const databases = computed(() => bundle.value?.databases ?? [])
const bundleHealth = computed(() => bundle.value
  ? databaseBundleHealth(bundle.value.status, bundle.value.freshness)
  : { label: '未收到探测', tone: 'unknown' })

function databaseName(name: string): string {
  if (name === 'trivy-db') return '主漏洞库'
  if (name === 'trivy-java-db') return 'Java 漏洞库'
  return name
}
</script>

<template>
  <StatePanel v-if="loading" class="surface-panel" kind="loading" />
  <StatePanel
    v-else-if="errorMessage"
    class="surface-panel"
    kind="error"
    :description="errorMessage"
    retryable
    @retry="$emit('retry')"
  />
  <div v-else-if="status" class="analyzer-status">
    <section class="analyzer-section surface-panel" aria-labelledby="live-analyzer-title">
      <header class="section-heading">
        <div>
          <span class="section-kicker mono">LOCAL / TOOLCHAIN PROBE</span>
          <h2 id="live-analyzer-title">分析器可用性</h2>
          <p>可用状态表示环境就绪检查通过，实际处理结果以任务执行记录为准。</p>
        </div>
        <button type="button" title="刷新分析器状态" @click="$emit('retry')">
          <RefreshCw :size="15" aria-hidden="true" /><span>刷新</span>
        </button>
      </header>
      <StatePanel v-if="!analyzers.length" kind="empty" title="尚未收到分析器探测报告" />
      <div v-else class="analyzer-grid">
        <article v-for="analyzer in analyzers" :key="analyzer.name" class="analyzer-row">
          <span class="analyzer-icon" aria-hidden="true"><DatabaseZap :size="17" /></span>
          <div class="analyzer-identity">
            <strong>{{ analysisEngineLabel(analyzer.name) }}</strong>
            <span>{{ analysisMessage(analyzer.scope) || '本地执行器' }}</span>
          </div>
          <span class="state-label" :class="`state-label--${analyzerProbeHealth(analyzer.status, analyzer.freshness).tone}`">
            <i aria-hidden="true" />{{ analyzerProbeHealth(analyzer.status, analyzer.freshness).label }}
          </span>
          <dl class="analyzer-details">
            <div><dt>通过探测的 Worker</dt><dd class="mono">{{ analyzer.status === 'unknown' || analyzer.freshness === 'stale' || analyzer.freshness === 'missing' ? '未知' : analyzer.ready_workers }}</dd></div>
            <div><dt>最近探测</dt><dd class="mono">{{ formatDateTime(analyzer.last_checked_at ?? undefined) }}</dd></div>
          </dl>
          <p class="analyzer-detail">{{ analyzerProbeDescription(analyzer) }}</p>
          <AnalyzerTechnicalDetails class="analyzer-detail" :analyzer="analyzer" />
          <small v-if="analyzer.last_run_at" class="analyzer-last-run">最近运行 {{ formatDateTime(analyzer.last_run_at) }}</small>
        </article>
      </div>
    </section>

    <section class="database-section surface-panel" aria-labelledby="live-database-title">
      <header class="section-heading">
        <div>
          <span class="section-kicker mono">LOCAL / DATABASE PROBE</span>
          <h2 id="live-database-title">离线漏洞库</h2>
          <p>展示本地主漏洞库与 Java 漏洞库的检查结果，运行时不会联网更新。</p>
        </div>
        <span class="state-label" :class="`state-label--${bundleHealth.tone}`"><i aria-hidden="true" />{{ bundleHealth.label }}</span>
      </header>
      <StatePanel
        v-if="!bundle"
        kind="empty"
        title="尚未收到离线数据库探测报告"
        description="当前无法确认双库状态，请检查漏洞检测服务的就绪报告。"
      />
      <template v-else>
        <div class="database-summary">
          <span>最近探测 <code>{{ formatDateTime(bundle.last_checked_at ?? undefined) }}</code></span>
          <span>报告时间 <code>{{ formatDateTime(bundle.registered_at) }}</code></span>
          <span v-if="bundle.age_days !== null && bundle.age_days !== undefined">数据年龄 <code>{{ bundle.age_days }} 天</code></span>
          <span v-if="bundle.stale_after_days !== undefined">过旧阈值 <code>{{ bundle.stale_after_days }} 天</code></span>
        </div>
        <p v-if="bundle.freshness === 'stale'" class="database-notice" role="status">探测报告已过期，请检查漏洞检测服务心跳；下方信息保留最近一次探测记录。</p>
        <p v-else-if="bundle.status === 'stale'" class="database-notice" role="status">本地漏洞库数据已过旧，请通过部署流程更新离线漏洞库。</p>
        <StatePanel
          v-if="!databases.length"
          kind="empty"
          title="尚未收到双库探测详情"
          description="需要主漏洞库和 Java 漏洞库的本地元数据才能确认状态。"
        />
        <div v-else class="database-grid">
          <article v-for="database in databases" :key="database.name" class="database-card">
            <header>
              <div><h3>{{ databaseName(database.name) }}</h3></div>
              <span class="state-label" :class="`state-label--${analyzerProbeHealth(database.status, bundle.freshness).tone}`">
                <i aria-hidden="true" />{{ analyzerProbeHealth(database.status, bundle.freshness).label }}
              </span>
            </header>
            <dl class="database-details">
              <div><dt>数据库版本 / Schema</dt><dd class="mono">{{ database.schema_version === null ? '未知' : `Schema ${database.schema_version}` }}</dd></div>
              <div><dt>文件大小</dt><dd class="mono">{{ database.size_bytes > 0 ? formatBytes(database.size_bytes) : '未知' }}</dd></div>
              <div><dt>更新时间</dt><dd class="mono">{{ formatDateTime(database.updated_at ?? undefined) }}</dd></div>
              <div><dt>下次更新时间</dt><dd class="mono">{{ formatDateTime(database.next_update ?? undefined) }}</dd></div>
              <div><dt>下载时间</dt><dd class="mono">{{ formatDateTime(database.downloaded_at ?? undefined) }}</dd></div>
            </dl>
            <p v-if="database.error" class="database-error" role="status">离线漏洞库检查未通过，请查看技术诊断。</p>
            <details class="database-path"><summary>技术诊断（原始信息）</summary><dl class="database-details"><div><dt>数据库标识</dt><dd>{{ database.name }}</dd></div><div><dt>容器内路径</dt><dd><code>{{ database.path || '未提供' }}</code></dd></div></dl><p v-if="database.error">{{ database.error }}</p></details>
          </article>
        </div>
      </template>
    </section>
  </div>
</template>

<style scoped>
.analyzer-status { display: grid; min-width: 0; gap: 14px; container: analyzer-live / inline-size; }
.analyzer-section, .database-section { min-width: 0; overflow: hidden; }
.section-heading { display: flex; min-height: 74px; align-items: center; justify-content: space-between; gap: 16px; padding: 14px 17px; border-bottom: 1px solid var(--line); }
.section-heading > div { min-width: 0; }
.section-kicker { display: block; margin-bottom: 5px; color: var(--primary-hover); font-size: 11px; font-weight: 700; }
.section-heading h2, .section-heading p { margin: 0; }
.section-heading h2 { color: var(--ink-800); font-size: 14px; }
.section-heading p { margin-top: 5px; color: var(--ink-600); font-size: 12px; line-height: 1.6; }
.section-heading button { display: inline-flex; min-height: 32px; flex: 0 0 auto; align-items: center; gap: 6px; padding: 5px 9px; border: 1px solid var(--line-strong); border-radius: var(--radius-sm); color: var(--ink-600); background: var(--surface); cursor: pointer; font-size: 12px; }
.section-heading button:focus-visible { outline: 2px solid var(--primary); outline-offset: 3px; }
.analyzer-grid, .database-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); }
.analyzer-row { display: grid; min-width: 0; grid-template-columns: 34px minmax(0, 1fr) auto; align-items: center; gap: 10px; padding: 14px 16px; border-right: 1px solid var(--line); border-bottom: 1px solid var(--line); }
.analyzer-row:nth-child(2n), .database-card:nth-child(2n) { border-right: 0; }
.analyzer-icon { display: grid; width: 32px; height: 32px; place-items: center; border: 1px solid var(--primary-border); border-radius: var(--radius-sm); color: var(--primary); background: var(--primary-soft); }
.analyzer-identity { min-width: 0; }
.analyzer-identity strong, .analyzer-identity span { display: block; overflow-wrap: anywhere; }
.analyzer-identity strong { color: var(--ink-800); font-size: 12px; }
.analyzer-identity span { margin-top: 3px; color: var(--ink-500); font-size: 11px; }
.analyzer-details { grid-column: 2 / -1; }
.analyzer-details, .database-details { display: grid; min-width: 0; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 16px; padding: 0; margin: 3px 0 0; }
.analyzer-details div, .database-details div { min-width: 0; }
.analyzer-details dt, .database-details dt { color: var(--ink-500); font-size: 11px; }
.analyzer-details dd, .database-details dd { margin: 4px 0 0; color: var(--ink-700); font-size: 12px; overflow-wrap: anywhere; }
.analyzer-detail, .analyzer-last-run { grid-column: 2 / -1; margin: 0; color: var(--ink-600); font-size: 11px; line-height: 1.6; overflow-wrap: anywhere; }
.analyzer-last-run { color: var(--ink-500); }
.state-label { display: inline-flex; min-height: 22px; align-items: center; gap: 5px; padding: 2px 6px; border: 1px solid var(--line-strong); border-radius: 6px; color: var(--ink-600); background: var(--surface-raised); font-size: 11px; font-weight: 700; white-space: nowrap; }
.state-label i { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.state-label--available { border-color: var(--success-border); color: var(--success); background: var(--success-soft); }
.state-label--unavailable { border-color: var(--danger-border); color: var(--danger); background: var(--danger-soft); }
.state-label--stale { border-color: var(--warning-border); color: var(--warning); background: var(--warning-soft); }
.database-summary { display: flex; flex-wrap: wrap; gap: 8px 20px; padding: 12px 17px; border-bottom: 1px solid var(--line); color: var(--ink-500); font-size: 11px; line-height: 1.6; }
.database-summary code { margin-left: 5px; color: var(--ink-700); }
.database-notice { margin: 0; padding: 10px 17px; border-bottom: 1px solid var(--warning-border); color: var(--warning); background: var(--warning-soft); font-size: 12px; line-height: 1.6; }
.database-card { min-width: 0; padding: 15px 17px; border-right: 1px solid var(--line); }
.database-card header { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 18px; }
.database-card h3 { margin: 0 0 4px; color: var(--ink-800); font-size: 13px; }
.database-card header code { color: var(--ink-500); font-size: 11px; }
.database-path { grid-column: 1 / -1; }
.database-error { margin: 14px 0 0; padding: 8px 10px; border-radius: 5px; color: var(--danger); background: var(--danger-soft); font-size: 12px; line-height: 1.6; overflow-wrap: anywhere; }
@container analyzer-live (max-width: 800px) { .analyzer-grid, .database-grid { grid-template-columns: 1fr; } .analyzer-row, .database-card { border-right: 0; border-bottom: 1px solid var(--line); } .database-card:last-child { border-bottom: 0; } }
@container analyzer-live (max-width: 520px) { .section-heading { align-items: flex-start; flex-direction: column; } .analyzer-row { grid-template-columns: 32px minmax(0, 1fr); } .analyzer-row > .state-label { grid-column: 2; justify-self: start; } .analyzer-details, .analyzer-detail, .analyzer-last-run { grid-column: 1 / -1; } .analyzer-details, .database-details { grid-template-columns: 1fr; } }
</style>
