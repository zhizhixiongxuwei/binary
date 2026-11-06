<script setup lang="ts">
import { Download, Filter, RefreshCw, ScrollText, Search } from 'lucide-vue-next'
import { reactive, shallowRef } from 'vue'

import type { AuditLog, AuditLogListQuery } from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import { auditFilterQuery } from '@/components/system/maintenance/auditFilters'
import { formatDateTime } from '@/utils/formatters'

defineProps<{
  logs: readonly AuditLog[]
  loading: boolean
  loadingMore: boolean
  loadMoreError?: string
  errorMessage: string
  hasMore: boolean
  exporting: boolean
  exportError: string
  exportFeedback: string
}>()

const emit = defineEmits<{
  search: [query: AuditLogListQuery]
  retry: []
  loadMore: []
  export: [query: AuditLogListQuery]
}>()

const filterError = shallowRef('')

const filters = reactive({
  action: '',
  outcome: '',
  actor: '',
  createdFrom: '',
  createdTo: '',
})

function filterQuery(): AuditLogListQuery | null {
  filterError.value = ''
  try {
    return auditFilterQuery(filters)
  } catch (error) {
    filterError.value = error instanceof Error ? error.message : '筛选条件无效'
    return null
  }
}

function submitFilters(): void {
  const query = filterQuery()
  if (query) emit('search', query)
}

function exportLogs(): void {
  const query = filterQuery()
  if (query) emit('export', query)
}

function clearFilters(): void {
  filterError.value = ''
  filters.action = ''
  filters.outcome = ''
  filters.actor = ''
  filters.createdFrom = ''
  filters.createdTo = ''
  emit('search', {})
}

function outcomeLabel(value: string): string {
  const labels: Readonly<Record<string, string>> = {
    success: '成功',
    denied: '拒绝',
    failure: '失败',
  }
  return labels[value] ?? value
}

function actorLabel(log: AuditLog): string {
  return log.actor?.display_name || log.actor?.username || '系统'
}
</script>

<template>
  <section
    class="audit-live surface-panel"
    aria-labelledby="audit-live-title"
  >
    <header class="section-heading">
      <div>
        <span class="section-kicker mono">LIVE / AUDIT EVENTS</span>
        <h2 id="audit-live-title">审计日志</h2>
        <p>记录账号登录、任务操作与管理变更，支持按条件查询和导出CSV。</p>
      </div>
      <div class="heading-actions">
        <button
          type="button"
          title="刷新审计日志"
          aria-label="刷新审计日志"
          :disabled="loading"
          @click="$emit('retry')"
        >
          <RefreshCw :size="15" aria-hidden="true" />
        </button>
        <button
          type="button"
          :disabled="exporting"
          class="audit-export"
          title="按当前填写的筛选条件导出全部匹配记录"
          @click="exportLogs"
        >
          <Download :size="15" aria-hidden="true" />
          <span>{{ exporting ? '正在导出…' : '导出CSV' }}</span>
        </button>
      </div>
    </header>

    <form class="audit-filters" @submit.prevent="submitFilters">
      <span class="filter-mark" aria-hidden="true">
        <Filter :size="15" />
      </span>
      <label>
        <span>操作</span>
        <input
          v-model="filters.action"
          placeholder="如 task.create"
          maxlength="100"
        >
      </label>
      <label>
        <span>结果</span>
        <select v-model="filters.outcome">
          <option value="">全部结果</option>
          <option value="success">成功</option>
          <option value="denied">拒绝</option>
          <option value="failure">失败</option>
        </select>
      </label>
      <label>
        <span>操作者</span>
        <input
          v-model="filters.actor"
          placeholder="用户名"
          maxlength="64"
        >
      </label>
      <label>
        <span>起始时间</span>
        <input v-model="filters.createdFrom" type="datetime-local">
      </label>
      <label>
        <span>结束时间</span>
        <input v-model="filters.createdTo" type="datetime-local">
      </label>
      <div class="filter-actions">
        <button type="button" :disabled="loading" @click="clearFilters">
          清除
        </button>
        <button class="search-command" type="submit" :disabled="loading">
          <Search :size="14" aria-hidden="true" />
          查询
        </button>
      </div>
    </form>

    <p v-if="filterError || exportError" class="audit-message audit-message--error" role="alert">{{ filterError || exportError }}</p>
    <p v-else-if="exportFeedback" class="audit-message" role="status">{{ exportFeedback }}</p>
    <p class="audit-scope">任务进度见任务详情的执行日志；服务启动与程序错误等运行日志由部署环境保存。</p>

    <StatePanel v-if="loading" kind="loading" />
    <StatePanel
      v-else-if="errorMessage"
      kind="error"
      :description="errorMessage"
      retryable
      @retry="$emit('retry')"
    />
    <StatePanel
      v-else-if="!logs.length"
      kind="empty"
      title="没有匹配的审计事件"
      description="可清除筛选条件后重新查询。"
    />
    <ol v-else class="audit-list" aria-label="审计事件列表">
      <li v-for="log in logs" :key="log.id" class="audit-row">
        <span class="audit-icon" aria-hidden="true">
          <ScrollText :size="16" />
        </span>
        <div class="event-time">
          <strong class="mono">{{ formatDateTime(log.created_at) }}</strong>
          <span class="mono">{{ log.id }}</span>
        </div>
        <div class="event-main">
          <div>
            <span class="action-label mono">{{ log.action }}</span>
            <strong>{{ actorLabel(log) }}</strong>
          </div>
          <span>
            <code>{{ log.actor?.username || 'system' }}</code>
            · {{ log.object_type }}
            <code v-if="log.object_id">{{ log.object_id }}</code>
          </span>
        </div>
        <div class="request-meta">
          <span>请求标识</span>
          <code>{{ log.request_id || '—' }}</code>
          <small v-if="log.client_ip">来源 {{ log.client_ip }}</small>
        </div>
        <span
          class="outcome-label"
          :class="`outcome-label--${log.outcome}`"
        >
          <i aria-hidden="true" />
          {{ outcomeLabel(log.outcome) }}
        </span>
      </li>
    </ol>

    <p v-if="loadMoreError" class="audit-message audit-message--error" role="alert">{{ loadMoreError }}</p>
    <footer v-if="!loading && !errorMessage" class="audit-footer">
      <span>
        当前已加载 <strong class="mono">{{ logs.length }}</strong> 条
      </span>
      <button
        v-if="hasMore"
        type="button"
        :disabled="loadingMore"
        @click="$emit('loadMore')"
      >
        {{ loadingMore ? '正在加载…' : loadMoreError ? '重试加载更早事件' : '加载更早事件' }}
      </button>
      <span v-else>已到达当前查询末尾</span>
    </footer>
  </section>
</template>

<style scoped>
.heading-actions .audit-export:not(:disabled) { border-color: var(--primary-border); color: var(--primary); background: var(--primary-soft); }
.audit-message, .audit-scope { margin: 0; padding: 10px 17px; color: var(--ink-600); font-size: 12px; line-height: 1.6; }
.audit-message--error { color: var(--danger); }
.audit-scope { border-bottom: 1px solid var(--line); background: var(--surface-raised); }
.audit-live {
  min-width: 0;
  overflow: hidden;
  container: audit-live / inline-size;
}

.section-heading {
  display: flex;
  min-height: 76px;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 14px 17px;
  border-bottom: 1px solid var(--line);
}

.section-heading > div {
  min-width: 0;
}

.section-kicker {
  display: block;
  margin-bottom: 5px;
  color: var(--primary-hover);
  font-size: 11px;
  font-weight: 700;
}

.section-heading h2,
.section-heading p {
  margin: 0;
}

.section-heading h2 {
  color: var(--ink-800);
  font-size: 14px;
}

.section-heading p {
  margin-top: 5px;
  color: var(--ink-600);
  font-size: 12px;
}

.heading-actions {
  display: flex;
  flex: 0 0 auto;
  gap: 7px;
}

.heading-actions button {
  display: inline-flex;
  min-height: 32px;
  align-items: center;
  gap: 6px;
  padding: 5px 9px;
  border: 1px solid var(--line-strong);
  border-radius: var(--radius-sm);
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
  font-size: 12px;
}

.heading-actions button:first-child {
  width: 32px;
  justify-content: center;
  padding: 0;
}

button:disabled {
  color: var(--ink-400);
  background: var(--surface-muted);
  cursor: not-allowed;
}

.audit-filters {
  display: grid;
  min-width: 0;
  grid-template-columns:
    28px minmax(120px, 0.8fr) minmax(100px, 0.55fr)
    minmax(110px, 0.65fr) minmax(168px, 0.9fr) minmax(168px, 0.9fr) auto;
  align-items: end;
  gap: 9px;
  padding: 11px 17px;
  border-bottom: 1px solid var(--line);
  background: var(--surface-raised);
}

.filter-mark {
  display: grid;
  width: 28px;
  height: 32px;
  place-items: center;
  color: var(--ink-400);
}

.audit-filters label {
  display: grid;
  min-width: 0;
  gap: 4px;
}

.audit-filters label > span {
  color: var(--ink-600);
  font-size: 11px;
  font-weight: 700;
}

.audit-filters input,
.audit-filters select {
  width: 100%;
  min-width: 0;
  min-height: 32px;
  padding: 5px 7px;
  border: 1px solid var(--line-strong);
  border-radius: var(--radius-sm);
  color: var(--ink-800);
  background: var(--surface);
  font-size: 11px;
}

.filter-actions {
  display: flex;
  gap: 6px;
}

.filter-actions button,
.audit-footer button {
  display: inline-flex;
  min-height: 32px;
  align-items: center;
  justify-content: center;
  gap: 5px;
  padding: 5px 9px;
  border: 1px solid var(--line-strong);
  border-radius: var(--radius-sm);
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
  font-size: 11px;
  white-space: nowrap;
}

.filter-actions .search-command {
  border-color: var(--primary);
  color: var(--surface);
  background: var(--primary);
}

.audit-list {
  padding: 0;
  margin: 0;
  list-style: none;
}

.audit-row {
  display: grid;
  min-width: 0;
  grid-template-columns:
    32px minmax(145px, 0.7fr) minmax(250px, 1.5fr)
    minmax(130px, 0.7fr) auto;
  align-items: center;
  gap: 12px;
  min-height: 68px;
  padding: 10px 17px;
  border-bottom: 1px solid var(--line);
}

.audit-icon {
  display: grid;
  width: 30px;
  height: 30px;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
  color: var(--ink-600);
  background: var(--surface-raised);
}

.event-time,
.event-main,
.request-meta {
  min-width: 0;
}

.event-time strong,
.event-time span,
.request-meta span,
.request-meta code {
  display: block;
  overflow-wrap: anywhere;
}

.event-time strong {
  color: var(--ink-800);
  font-size: 11px;
}

.event-time span,
.request-meta span {
  margin-top: 3px;
  color: var(--ink-400);
  font-size: 11px;
}

.event-main > div {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 7px;
}

.event-main strong {
  color: var(--ink-800);
  font-size: 12px;
  overflow-wrap: anywhere;
}

.event-main > span {
  display: block;
  margin-top: 4px;
  color: var(--ink-600);
  font-size: 11px;
  overflow-wrap: anywhere;
}

.action-label {
  flex: 0 0 auto;
  padding: 2px 5px;
  border: 1px solid var(--primary-border);
  border-radius: 6px;
  color: var(--primary);
  background: var(--primary-soft);
  font-size: 11px;
}

.event-main code,
.request-meta code {
  color: var(--ink-600);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 11px;
}

.outcome-label {
  display: inline-flex;
  min-height: 22px;
  align-items: center;
  gap: 5px;
  padding: 2px 6px;
  border: 1px solid var(--success-border);
  border-radius: 6px;
  color: var(--success);
  background: var(--success-soft);
  font-size: 11px;
  font-weight: 700;
  white-space: nowrap;
}

.outcome-label i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--success);
}

.outcome-label--denied,
.outcome-label--failure {
  border-color: var(--danger-border);
  color: var(--danger);
  background: var(--danger-soft);
}

.outcome-label--denied i,
.outcome-label--failure i {
  background: var(--danger);
}

.audit-footer {
  display: flex;
  min-height: 48px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 17px;
  color: var(--ink-400);
  background: var(--surface-raised);
  font-size: 11px;
}

@container audit-live (max-width: 1050px) {
  .audit-filters {
    grid-template-columns: 28px repeat(3, minmax(100px, 1fr)) auto;
  }

  .audit-filters label:nth-of-type(4),
  .audit-filters label:nth-of-type(5) {
    grid-row: 2;
  }

  .audit-filters label:nth-of-type(4) {
    grid-column: 2 / 4;
  }

  .audit-filters label:nth-of-type(5) {
    grid-column: 4 / 6;
  }
}

@container audit-live (max-width: 760px) {
  .audit-row {
    grid-template-columns: 30px minmax(0, 1fr) auto;
  }

  .event-main,
  .request-meta {
    grid-column: 2 / -1;
  }

  .outcome-label {
    grid-row: 1;
    grid-column: 3;
  }
}

@container audit-live (max-width: 620px) {
  .section-heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .audit-filters {
    grid-template-columns: 1fr;
    padding: 13px;
  }

  .filter-mark {
    display: none;
  }

  .audit-filters label:nth-of-type(4),
  .audit-filters label:nth-of-type(5) {
    grid-row: auto;
    grid-column: auto;
  }

  .filter-actions {
    justify-content: flex-end;
  }
}

@container audit-live (max-width: 440px) {
  .audit-row {
    grid-template-columns: 30px minmax(0, 1fr);
    padding: 12px 13px;
  }

  .outcome-label {
    grid-row: auto;
    grid-column: 2;
    justify-self: start;
  }

  .audit-footer {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
