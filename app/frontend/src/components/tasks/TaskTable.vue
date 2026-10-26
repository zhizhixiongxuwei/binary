<script setup lang="ts">
import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  FileCode2,
  Trash2,
} from 'lucide-vue-next'
import { computed } from 'vue'

import type { ScanTask, UserRole } from '@/api/types'
import StatusBadge from '@/components/common/StatusBadge.vue'
import { getTaskActionModel } from '@/components/tasks/taskActions'
import { useSampleRetentionClock } from '@/composables/useSampleRetentionClock'
import { formatDateTime } from '@/utils/formatters'
import {
  resolveSampleRetention,
  type SampleRetentionSnapshot,
} from '@/utils/sampleRetention'

const props = withDefaults(
  defineProps<{
    items: readonly ScanTask[]
    pageSize: number
    hasPrevious: boolean
    hasNext: boolean
    canReset: boolean
    loading?: boolean
    // Test and server-rendered callers can inject a deterministic clock.
    // eslint-disable-next-line vue/require-default-prop
    now?: Date
    userRole?: UserRole | null
    currentUserId?: string | null
    pendingTaskId?: string | null
  }>(),
  {
    loading: false,
    userRole: null,
    currentUserId: null,
    pendingTaskId: null,
  },
)

const emit = defineEmits<{
  open: [id: string]
  delete: [task: ScanTask]
  firstPage: []
  previousPage: []
  nextPage: []
  pageSizeChange: [pageSize: number]
}>()

const sampleClock = useSampleRetentionClock(
  () => props.items.map((item) => item.sample_expires_at),
  { now: () => props.now },
)
const sampleRetentionByTask = computed(() =>
  new Map(
    props.items.map((item) => [
      item.id,
      resolveSampleRetention({
        sampleExpiresAt: item.sample_expires_at,
        sampleDeletedAt: item.sample_deleted_at,
        now: sampleClock.now.value,
      }),
    ]),
  ),
)

function taskSampleRetention(task: ScanTask): SampleRetentionSnapshot {
  return (
    sampleRetentionByTask.value.get(task.id) ??
    resolveSampleRetention({
      sampleExpiresAt: task.sample_expires_at,
      sampleDeletedAt: task.sample_deleted_at,
      now: sampleClock.now.value,
    })
  )
}

function normalizeProgress(value: number): number {
  if (!Number.isFinite(value)) return 0
  return Math.max(0, Math.min(100, value))
}

function deleteAction(task: ScanTask) {
  return getTaskActionModel({
    task,
    mode: 'live',
    userRole: props.userRole,
    isCreator: props.currentUserId === task.creator_id,
    now: props.now,
  }).delete
}

function changePageSize(value: unknown): void {
  if (typeof value !== 'number' || ![10, 20, 50].includes(value)) return
  emit('pageSizeChange', value)
}
</script>

<template>
  <div class="task-table">
    <span class="sr-only">
      任务列表支持横向滚动；任务名称和每行末尾的详情按钮均可打开任务。
    </span>
    <div
      class="task-table__scroller"
      role="region"
      aria-label="任务列表，可横向滚动查看全部字段"
      tabindex="0"
    >
      <el-table
        class="task-table__data"
        :data="items"
        empty-text="当前批次暂无任务"
        row-key="id"
        @row-click="(row: ScanTask) => emit('open', row.id)"
      >
        <el-table-column label="任务" min-width="260">
          <template #default="{ row }: { row: ScanTask }">
            <div class="task-cell">
              <span class="task-cell__icon" aria-hidden="true">
                <FileCode2 :size="17" aria-hidden="true" />
              </span>
              <span class="task-cell__copy">
                <button
                  class="task-cell__open"
                  type="button"
                  :aria-label="`查看任务：${row.name}`"
                  :title="row.name"
                  @click.stop="emit('open', row.id)"
                >
                  {{ row.name }}
                </button>
                <small class="task-cell__id mono" :title="row.id">
                  {{ row.id }}
                </small>
                <small
                  v-if="taskSampleRetention(row).status !== 'available'"
                  class="task-cell__retention"
                  :class="`task-cell__retention--${taskSampleRetention(row).status}`"
                  :data-retention-status="taskSampleRetention(row).status"
                  :title="taskSampleRetention(row).actionReason"
                >
                  {{ taskSampleRetention(row).statusLabel }}
                </small>
              </span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="类型" min-width="105">
          <template #default="{ row }: { row: ScanTask }">
            <span class="table-token mono" :title="row.input_type">
              {{ row.input_type }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="分析模式" min-width="115">
          <template #default="{ row }: { row: ScanTask }">
            <span class="table-token">
              {{ row.analysis_mode === 'binary' ? '二进制' : row.analysis_mode === 'archive' ? '压缩包' : row.analysis_mode === 'container' ? '容器/映像' : '历史任务' }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="执行状态" min-width="136">
          <template #default="{ row }: { row: ScanTask }">
            <StatusBadge :value="row.status" kind="status" />
          </template>
        </el-table-column>
        <el-table-column label="风险等级" min-width="116">
          <template #default="{ row }: { row: ScanTask }">
            <StatusBadge :value="row.risk_level" kind="risk" />
          </template>
        </el-table-column>
        <el-table-column label="进度" min-width="150">
          <template #default="{ row }: { row: ScanTask }">
            <div class="progress-cell">
              <el-progress
                :percentage="normalizeProgress(row.progress)"
                :stroke-width="5"
                :show-text="false"
                :indeterminate="row.progress_indeterminate"
                :duration="2"
                :aria-label="row.progress_indeterminate
                  ? `${row.name} 检测进度计算中`
                  : `${row.name} 检测进度 ${normalizeProgress(row.progress)}%`"
              />
              <span class="mono">
                {{ row.progress_indeterminate ? '计算中' : `${normalizeProgress(row.progress)}%` }}
              </span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="创建者" min-width="105">
          <template #default="{ row }: { row: ScanTask }">
            <span class="table-token" :title="row.creator_name">
              {{ row.creator_name }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="创建时间" min-width="156">
          <template #default="{ row }: { row: ScanTask }">
            <span class="table-muted">{{ formatDateTime(row.created_at) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="92" align="center">
          <template #default="{ row }: { row: ScanTask }">
            <div class="row-commands" role="group" :aria-label="`${row.name} 任务操作`">
              <button
                class="row-command row-command--danger"
                type="button"
                :disabled="!deleteAction(row).enabled || pendingTaskId === row.id"
                :aria-label="`删除任务：${row.name}`"
                :title="deleteAction(row).reason"
                @click.stop="emit('delete', row)"
              >
                <Trash2 :size="16" aria-hidden="true" />
              </button>
              <button
                class="row-command"
                type="button"
                :aria-label="`查看任务详情：${row.name}`"
                title="查看任务详情"
                @click.stop="emit('open', row.id)"
              >
                <ChevronRight :size="18" aria-hidden="true" />
              </button>
            </div>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <footer class="task-table__footer">
      <span>本批 {{ items.length }} 个任务</span>
      <div class="task-table__cursor-controls" role="group" aria-label="任务列表游标分页">
        <el-select
          class="task-table__page-size"
          :model-value="pageSize"
          :disabled="loading"
          aria-label="每批任务数量"
          @update:model-value="changePageSize"
        >
          <el-option :value="10" label="每批 10" />
          <el-option :value="20" label="每批 20" />
          <el-option :value="50" label="每批 50" />
        </el-select>
        <button
          class="task-table__cursor-button"
          type="button"
          :disabled="loading || !canReset"
          aria-label="返回第一批任务"
          title="返回第一批"
          @click="emit('firstPage')"
        >
          <ChevronsLeft :size="17" aria-hidden="true" />
        </button>
        <button
          class="task-table__cursor-button"
          type="button"
          :disabled="loading || !hasPrevious"
          aria-label="查看上一批任务"
          title="上一批"
          @click="emit('previousPage')"
        >
          <ChevronLeft :size="17" aria-hidden="true" />
        </button>
        <button
          class="task-table__cursor-button"
          type="button"
          :disabled="loading || !hasNext"
          aria-label="查看下一批任务"
          title="下一批"
          @click="emit('nextPage')"
        >
          <ChevronRight :size="17" aria-hidden="true" />
        </button>
      </div>
    </footer>
  </div>
</template>

<style scoped>
.task-table {
  width: 100%;
  min-width: 0;
  max-width: 100%;
}

.task-table__scroller {
  width: 100%;
  max-width: 100%;
  overflow-x: auto;
  overscroll-behavior-inline: contain;
}

.task-table__scroller:focus-visible {
  outline: 2px solid var(--primary);
  outline-offset: -2px;
}

.task-table__data {
  min-width: 1080px;
}

.task-table :deep(.el-table__row) {
  cursor: pointer;
}

.task-table :deep(.el-table th.el-table__cell) {
  height: 48px;
  padding-block: 10px;
}

.task-table :deep(.el-table td.el-table__cell) {
  padding-block: 18px;
}

.task-table :deep(.el-table .cell) {
  padding-inline: 16px;
}

.task-table :deep(.el-table td:first-child .cell),
.task-table :deep(.el-table th:first-child .cell) {
  padding-left: 24px;
}

.task-table :deep(.el-table td:last-child .cell),
.task-table :deep(.el-table th:last-child .cell) {
  padding-inline: 10px;
}

.task-cell {
  display: flex;
  align-items: center;
  gap: 12px;
}

.task-cell__icon {
  display: grid;
  width: 38px;
  height: 38px;
  flex: 0 0 38px;
  place-items: center;
  border-radius: 10px;
  color: var(--primary);
  background: var(--primary-soft);
}

.task-cell__copy {
  display: block;
  min-width: 0;
  flex: 1;
}

.task-cell__open,
.task-cell__id {
  display: block;
  width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.task-cell__open {
  padding: 0;
  border: 0;
  color: var(--primary);
  background: transparent;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  text-align: left;
}

.task-cell__open:hover {
  color: var(--primary-hover);
  text-decoration: underline;
  text-underline-offset: 3px;
}

.task-cell__open:focus-visible {
  border-radius: 4px;
  outline: 2px solid var(--primary);
  outline-offset: 2px;
}

.task-cell__id {
  margin-top: 5px;
  color: var(--ink-500);
  font-size: 12px;
}

.task-cell__retention {
  display: inline-flex;
  width: fit-content;
  max-width: 100%;
  min-height: 24px;
  align-items: center;
  margin-top: 5px;
  padding: 2px 7px;
  border: 1px solid var(--warning-border);
  border-radius: 6px;
  color: var(--warning);
  background: var(--warning-soft);
  font-size: 12px;
  font-weight: 500;
}

.task-cell__retention--deleted {
  border-color: var(--danger-border);
  color: var(--danger);
  background: var(--danger-soft);
}

.task-cell__retention--unavailable {
  border-color: var(--line-strong);
  color: var(--ink-600);
  background: var(--surface-raised);
}

.progress-cell {
  display: grid;
  grid-template-columns: minmax(60px, 1fr) 40px;
  align-items: center;
  gap: 8px;
}

.progress-cell :deep(.el-progress-bar__inner) {
  background: var(--primary);
}

.progress-cell span {
  color: var(--ink-600);
  font-size: 12px;
  text-align: right;
}

.table-muted {
  color: var(--ink-600);
  font-size: 13px;
}

.table-token {
  display: block;
  overflow: hidden;
  color: var(--ink-600);
  font-size: 13px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.row-command {
  display: grid;
  width: 32px;
  height: 32px;
  place-items: center;
  border: 0;
  border-radius: var(--radius-sm);
  color: var(--primary);
  background: transparent;
  cursor: pointer;
}

.row-commands {
  display: grid;
  width: 68px;
  grid-template-columns: repeat(2, 32px);
  gap: 4px;
}

.row-command:hover {
  color: var(--primary-hover);
  background: var(--primary-soft);
}

.row-command--danger:hover:not(:disabled) {
  color: var(--danger);
  background: var(--danger-soft);
}

.row-command:disabled {
  color: var(--ink-300);
  background: transparent;
  cursor: not-allowed;
}

.row-command:focus-visible {
  outline: 2px solid var(--primary);
  outline-offset: 1px;
}

.task-table__footer {
  display: flex;
  min-height: 76px;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 16px 24px;
  border-top: 1px solid var(--line);
  color: var(--ink-600);
  font-size: 13px;
}

.task-table__cursor-controls {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
}

.task-table__page-size {
  width: 116px;
}

.task-table__cursor-button {
  display: grid;
  width: 38px;
  height: 38px;
  flex: 0 0 38px;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
  color: var(--ink-700);
  background: var(--surface);
  cursor: pointer;
}

.task-table__cursor-button:hover:not(:disabled) {
  border-color: var(--primary-border);
  color: var(--primary);
  background: var(--primary-soft);
}

.task-table__cursor-button:focus-visible {
  outline: 2px solid var(--primary);
  outline-offset: 1px;
}

.task-table__cursor-button:disabled {
  color: var(--ink-300);
  background: var(--surface-raised);
  cursor: not-allowed;
}

@media (max-width: 660px) {
  .task-table__footer {
    align-items: center;
    flex-direction: column;
    gap: 10px;
    padding-inline: 8px;
  }

  .task-table__cursor-controls {
    width: 100%;
    justify-content: center;
  }
}
</style>
