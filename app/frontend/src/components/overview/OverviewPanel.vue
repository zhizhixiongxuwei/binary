<script setup lang="ts">
import { Activity, AlertTriangle, ArrowRight, CheckCircle2, Clock3, Files, RefreshCw } from 'lucide-vue-next'
import { computed, onBeforeUnmount, shallowRef, watch } from 'vue'
import { useRouter } from 'vue-router'

import { api, ApiError } from '@/api/client'
import { normalizeOverviewStatus, overviewStatuses } from '@/api/overview'
import type { OverviewSummary, TaskStatus } from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import { formatDateTime } from '@/utils/formatters'

const router = useRouter()
const days = shallowRef<7 | 30>(7)
const summary = shallowRef<OverviewSummary | null>(null)
const loading = shallowRef(false)
const errorMessage = shallowRef('')
let sequence = 0
onBeforeUnmount(() => { sequence++ })

async function load(): Promise<void> {
  const request = ++sequence
  loading.value = true
  errorMessage.value = ''
  // Clear the previous window so its figures never appear under a new range.
  summary.value = null
  try {
    const result = await api.getOverview(days.value)
    if (request === sequence) summary.value = result
  } catch (error) {
    if (request === sequence) errorMessage.value = error instanceof ApiError ? error.message : '概览数据读取失败，请重试'
  } finally {
    if (request === sequence) loading.value = false
  }
}
watch(days, load, { immediate: true })

const metrics = computed(() => summary.value ? [
  { label: '期间新增任务', value: summary.value.total, note: `近 ${days.value} 天创建`, icon: Files, tone: 'blue', status: undefined, current: false },
  { label: '当前处理中', value: summary.value.active, note: '当前全部检测任务', icon: Activity, tone: 'teal', status: 'SCANNING' as TaskStatus, current: true },
  { label: '当前排队', value: summary.value.queued, note: '当前全部检测任务', icon: Clock3, tone: 'purple', status: 'QUEUED' as TaskStatus, current: true },
  { label: '期间失败任务', value: summary.value.failed, note: '期间创建、当前失败', icon: AlertTriangle, tone: 'red', status: 'FAILED' as TaskStatus, current: false },
] : [])
const statuses = computed(() => (summary.value?.statuses ?? []).map((bucket) => {
  const key = normalizeOverviewStatus(bucket.value)
  return { ...bucket, ...(overviewStatuses[key] ?? { label: bucket.value, color: 'var(--ink-400)' }) }
}))
const formats = computed(() => [...(summary.value?.formats ?? [])].sort((a, b) => b.count - a.count || a.value.localeCompare(b.value)))
const maxDaily = computed(() => Math.max(1, ...summary.value?.trend.map((day) => day.created) ?? []))
const donutBackground = computed(() => {
  let offset = 0
  const total = summary.value?.total ?? 0
  if (!total) return 'var(--surface-muted)'
  const stops = statuses.value.map((status) => {
    const start = offset
    offset += status.count / total * 100
    return `${status.color} ${start}% ${offset}%`
  })
  return `conic-gradient(${stops.join(',')})`
})
function percent(count: number): string {
  return `${((count / (summary.value?.total || 1)) * 100).toFixed(1)}%`
}
function openTasks(status?: TaskStatus, current = false, date?: string, format?: string): void {
  const query: Record<string, string> = {}
  if (status) query.status = status
  if (!current && summary.value) {
    query.created_from = date ?? summary.value.created_from
    query.created_to = date ?? summary.value.created_to
  }
  if (format) query.input_type = format
  void router.push({ name: 'tasks', query })
}
</script>

<template>
  <div class="overview">
    <div class="overview-toolbar">
      <div class="overview-toolbar__copy">
        <span class="section-kicker">检测态势</span>
        <p>统计实际检测任务（含归档子任务） · 近 {{ days }} 天 · UTC 自然日<span v-if="summary"> · 更新于 {{ formatDateTime(summary.collected_at) }}</span></p>
      </div>
      <div class="overview-toolbar__actions">
        <el-radio-group v-model="days" aria-label="统计时间范围">
          <el-radio-button :value="7">近 7 天</el-radio-button>
          <el-radio-button :value="30">近 30 天</el-radio-button>
        </el-radio-group>
        <el-button :icon="RefreshCw" :loading="loading" @click="load">刷新</el-button>
      </div>
    </div>

    <StatePanel v-if="loading" class="surface-panel" kind="loading" title="正在汇总检测数据" />
    <StatePanel v-else-if="errorMessage" class="surface-panel" kind="error" title="概览数据暂不可用" :description="errorMessage" retryable @retry="load" />
    <template v-else-if="summary">
      <div class="metrics" aria-label="检测摘要">
        <button v-for="metric in metrics" :key="metric.label" type="button" class="metric surface-panel" @click="openTasks(metric.status, metric.current)">
          <span class="metric__top"><span>{{ metric.label }}</span><component :is="metric.icon" :size="18" :class="`tone-${metric.tone}`" aria-hidden="true" /></span>
          <strong>{{ metric.value.toLocaleString() }}</strong>
          <span class="metric__bottom">{{ metric.note }}<ArrowRight :size="14" aria-hidden="true" /></span>
        </button>
      </div>

      <div class="overview-grid">
        <section class="surface-panel overview-card trend-card" aria-labelledby="trend-title">
          <header class="card-heading">
            <div><h2 id="trend-title">检测趋势</h2><p>按任务创建日统计；失败数为其中当前失败的任务</p></div>
            <div class="chart-legend"><span><i class="dot dot--created" />新增</span><span><i class="dot dot--failed" />失败</span></div>
          </header>
          <StatePanel v-if="summary.total === 0" kind="empty" title="期间暂无检测任务" description="可切换时间范围，或新建检测任务。" />
          <div v-else class="trend-chart">
            <div class="chart-scale" aria-hidden="true"><span>{{ maxDaily }}</span><span>{{ Math.round(maxDaily / 2) }}</span><span>0</span></div>
            <div class="chart-scroll">
              <div class="chart-bars" :class="{ 'chart-bars--month': days === 30 }" role="group" aria-label="每日新增及失败任务数，点击查看当日任务">
                <button v-for="day in summary.trend" :key="day.date" type="button" class="day-bar" :aria-label="`${day.date}：新增 ${day.created}，当前失败 ${day.failed}，查看当日任务`" :title="`${day.date} · 新增 ${day.created} · 失败 ${day.failed}`" @click="openTasks(undefined, false, day.date)">
                  <span class="day-bar__plot"><span class="bar bar--created" :style="{ height: `${day.created / maxDaily * 100}%` }" /><span class="bar bar--failed" :style="{ height: `${day.failed / maxDaily * 100}%` }" /></span>
                  <span class="day-bar__label">{{ day.date.slice(5).replace('-', '/') }}</span>
                </button>
              </div>
            </div>
          </div>
          <footer class="card-footer">{{ summary.created_from }} — {{ summary.created_to }} · UTC</footer>
        </section>

        <section class="surface-panel overview-card" aria-labelledby="status-title">
          <header class="card-heading"><div><h2 id="status-title">任务状态分布</h2><p>所选期间创建任务的当前状态</p></div></header>
          <StatePanel v-if="summary.total === 0" kind="empty" title="暂无状态数据" />
          <div v-else class="status-content">
            <div class="donut" :style="{ background: donutBackground }" role="img" :aria-label="statuses.map(item => `${item.label} ${item.count} 个`).join('，')"><div><strong>{{ summary.total.toLocaleString() }}</strong><span>期间任务</span></div></div>
            <div class="status-legend">
              <button v-for="status in statuses" :key="status.value" type="button" :disabled="!status.filter" @click="openTasks(status.filter)">
                <i class="dot" :style="{ background: status.color }" /><span>{{ status.label }}</span><strong>{{ status.count }}</strong><small>{{ percent(status.count) }}</small>
              </button>
            </div>
          </div>
        </section>

        <section class="surface-panel overview-card" aria-labelledby="format-title">
          <header class="card-heading"><div><h2 id="format-title">样本类型分布</h2><p>按任务样本的实际识别格式统计</p></div><span class="heading-tag">{{ formats.length }} 种格式</span></header>
          <StatePanel v-if="summary.total === 0" kind="empty" title="暂无样本数据" />
          <div v-else class="format-list">
            <button v-for="format in formats" :key="format.value" type="button" class="format-row" @click="openTasks(undefined, false, undefined, format.value)">
              <span class="format-row__heading"><strong>{{ format.value === 'unknown' ? '未识别' : format.value.toUpperCase() }}</strong><span>{{ format.count }} <small>个 · {{ percent(format.count) }}</small></span></span>
              <span class="format-track"><span :style="{ width: percent(format.count) }" /></span>
            </button>
          </div>
        </section>

        <section class="surface-panel overview-card" aria-labelledby="attention-title">
          <header class="card-heading"><div><h2 id="attention-title">需关注事项</h2><p>所选期间创建的失败任务</p></div><el-button text @click="openTasks('FAILED')">查看全部<ArrowRight :size="14" aria-hidden="true" /></el-button></header>
          <div v-if="summary.failed === 0" class="attention-empty"><CheckCircle2 :size="32" aria-hidden="true" /><strong>期间暂无失败任务</strong><span>新出现的执行异常将显示在这里</span></div>
          <div v-else class="attention-content">
            <div class="attention-summary"><AlertTriangle :size="18" aria-hidden="true" /><span><strong>{{ summary.failed }} 个任务执行失败</strong><small>可进入详情查看执行日志与失败原因</small></span></div>
            <button v-for="task in summary.failures" :key="task.id" type="button" class="failure-row" @click="router.push({ name: 'task-detail', params: { id: task.id } })"><span><strong>{{ task.name }}</strong><small>创建于 {{ formatDateTime(task.created_at) }}</small></span><ArrowRight :size="16" aria-hidden="true" /></button>
            <p class="attention-note">仅展示最近创建的 {{ summary.failures.length }} 条失败任务</p>
          </div>
        </section>
      </div>
    </template>
  </div>
</template>

<style scoped>
.overview { display: grid; gap: 22px; container: overview / inline-size; }
.overview-toolbar, .overview-toolbar__actions { display: flex; align-items: center; justify-content: space-between; gap: 14px; }
.section-kicker { font-size: 14px; font-weight: 600; color: var(--ink-800); }
.overview-toolbar p { margin: 7px 0 0; color: var(--ink-500); font-size: 12px; line-height: 1.7; }
.overview-toolbar__actions { flex-shrink: 0; }
.metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 18px; }
.metric { display: grid; gap: 16px; padding: 22px; text-align: left; cursor: pointer; color: var(--ink-800); }
.metric:hover { border-color: var(--primary-border); background: var(--primary-soft); }
.metric__top, .metric__bottom { display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 13px; }
.metric > strong { font-size: 32px; font-weight: 700; color: var(--ink-950); line-height: 1.1; font-variant-numeric: tabular-nums; }
.metric__bottom { font-size: 12px; color: var(--ink-500); }
.tone-blue { color: var(--primary); }.tone-teal { color: var(--success); }.tone-purple { color: #8b5cf6; }.tone-red { color: var(--danger); }
.overview-grid { display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(0, 1fr); gap: 22px; align-items: stretch; }
.overview-card { min-width: 0; overflow: hidden; }
.card-heading { display: flex; align-items: center; justify-content: space-between; min-height: 85px; padding: 20px 24px; gap: 16px; }
.card-heading h2 { margin: 0; color: var(--ink-950); font-size: 15px; font-weight: 600; }
.card-heading p { margin: 7px 0 0; font-size: 12px; color: var(--ink-500); line-height: 1.6; }
.card-heading :deep(.el-button > span) { display: flex; align-items: center; gap: 6px; }
.chart-legend { display: flex; gap: 12px; flex-shrink: 0; font-size: 11px; color: var(--ink-600); }
.chart-legend > span { display: flex; align-items: center; gap: 6px; }
.dot { display: inline-block; width: 8px; height: 8px; flex-shrink: 0; border-radius: 50%; }.dot--created { background: var(--primary); }.dot--failed { background: var(--danger); }
.trend-chart { display: flex; gap: 12px; padding: 10px 24px 0; }
.chart-scale { display: flex; flex-direction: column; justify-content: space-between; width: 28px; height: 180px; color: var(--ink-500); font-size: 11px; text-align: right; }
.chart-scroll { flex: 1; min-width: 0; overflow-x: auto; }
.chart-bars { display: flex; height: 210px; min-width: 320px; gap: 8px; background: repeating-linear-gradient(to top, transparent 0, transparent 89px, var(--line) 89px, var(--line) 90px) top / 100% 180px no-repeat; }
.chart-bars--month { min-width: 760px; gap: 4px; }
.day-bar { display: flex; flex: 1; min-width: 0; flex-direction: column; padding: 0 2px; border: 0; background: transparent; cursor: pointer; color: var(--ink-500); }
.day-bar:hover { background: var(--primary-soft); }
.day-bar__plot { display: flex; align-items: end; justify-content: center; gap: 3px; width: 100%; height: 180px; border-bottom: 1px solid var(--line-strong); }
.bar { display: block; width: 32%; max-width: 18px; border-radius: 3px 3px 0 0; }.bar--created { background: var(--primary); }.bar--failed { background: var(--danger); }
.day-bar__label { padding-top: 10px; font-size: 10px; white-space: nowrap; align-self: center; }
.card-footer { padding: 15px 24px 20px; color: var(--ink-500); font-size: 11px; }
.status-content { display: flex; align-items: center; justify-content: center; flex-wrap: wrap; gap: 26px; padding: 16px 24px 32px; min-height: 246px; }
.donut { display: grid; width: 156px; height: 156px; flex-shrink: 0; place-items: center; border-radius: 50%; }
.donut > div { display: grid; align-content: center; justify-items: center; gap: 5px; width: 122px; height: 122px; border-radius: 50%; background: var(--surface); }
.donut strong { font-size: 28px; color: var(--ink-950); }.donut span { font-size: 12px; color: var(--ink-500); }
.status-legend { display: grid; flex: 1; min-width: 165px; gap: 5px; }
.status-legend button { display: grid; grid-template-columns: 8px 1fr auto 48px; align-items: center; gap: 9px; padding: 7px 4px; border: 0; border-radius: 4px; color: var(--ink-600); background: transparent; cursor: pointer; text-align: left; font-size: 12px; }
.status-legend button:hover { background: var(--surface-muted); }.status-legend button:disabled { cursor: default; }
.status-legend strong { color: var(--ink-800); font-variant-numeric: tabular-nums; }.status-legend small { text-align: right; color: var(--ink-500); }
.heading-tag { padding: 5px 9px; border-radius: 6px; background: var(--surface-muted); font-size: 11px; color: var(--ink-600); white-space: nowrap; }
.format-list { display: grid; gap: 20px; max-height: 300px; overflow-y: auto; padding: 8px 24px 28px; }
.format-row { padding: 0; border: 0; background: transparent; cursor: pointer; text-align: left; }
.format-row__heading { display: flex; justify-content: space-between; gap: 10px; margin-bottom: 9px; font-size: 12px; color: var(--ink-800); }.format-row__heading strong { font-weight: 500; }.format-row__heading small { color: var(--ink-500); }
.format-track, .format-track > span { display: block; height: 7px; border-radius: 4px; }.format-track { background: var(--surface-muted); }.format-track > span { background: var(--primary); min-width: 2px; opacity: .75; }.format-row:hover .format-track > span { opacity: 1; }
.attention-empty { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px; min-height: 230px; padding: 24px; text-align: center; color: var(--success); }.attention-empty strong { font-size: 14px; color: var(--ink-700); }.attention-empty span { font-size: 12px; color: var(--ink-500); }
.attention-content { padding: 4px 24px 20px; }.attention-summary { display: flex; gap: 12px; align-items: center; padding: 14px; border-radius: var(--radius-sm); background: var(--danger-soft); color: var(--danger); }.attention-summary strong, .attention-summary small { display: block; }.attention-summary strong { font-size: 13px; font-weight: 600; }.attention-summary small { margin-top: 5px; font-size: 11px; color: var(--ink-600); }
.failure-row { display: flex; width: 100%; align-items: center; justify-content: space-between; gap: 12px; padding: 16px 0; border: 0; border-bottom: 1px solid var(--line); background: transparent; color: var(--ink-500); text-align: left; cursor: pointer; }.failure-row > span { min-width: 0; }.failure-row strong { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; font-weight: 500; color: var(--primary); }.failure-row small { display: block; margin-top: 6px; font-size: 11px; }.failure-row:hover strong { text-decoration: underline; }.failure-row svg { flex-shrink: 0; }
.attention-note { margin: 14px 0 0; color: var(--ink-500); font-size: 11px; }
@container overview (max-width: 1000px) { .status-content { gap: 18px; }.donut { width: 132px; height: 132px; }.donut > div { width: 102px; height: 102px; }.card-heading { padding: 18px; }.chart-legend { gap: 8px; } }
@container overview (max-width: 800px) { .overview-grid { grid-template-columns: 1fr; }.metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }.overview-toolbar { align-items: flex-start; flex-direction: column; }.status-content { flex-wrap: nowrap; }.status-legend { max-width: 320px; } }
@container overview (max-width: 440px) { .metric { padding: 16px; }.metrics { gap: 12px; }.metric__bottom { font-size: 11px; }.card-heading { flex-wrap: wrap; }.status-content { flex-wrap: wrap; }.overview-toolbar__actions { flex-wrap: wrap; }.trend-chart { padding-inline: 12px; } }
</style>
