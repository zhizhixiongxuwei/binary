<script setup lang="ts">
import {
  Archive,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  FileCode2,
  Trash2,
} from 'lucide-vue-next'
import { computed } from 'vue'

import type { ScanTask, TaskListQuery, UserRole } from '@/api/types'
import TaskExecutionBadge from '@/components/tasks/TaskExecutionBadge.vue'
import { taskExecutionProgressLabel } from '@/components/tasks/taskExecutionPresentation'
import ArchiveTaskExpansion from '@/components/tasks/ArchiveTaskExpansion.vue'
import { archiveStatusLabels } from '@/components/tasks/archiveTaskPresentation'
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
    expandedId?: string
    filters?: TaskListQuery
    refreshVersion?: number
  }>(),
  {
    loading: false,
    userRole: null,
    currentUserId: null,
    pendingTaskId: null,
    expandedId: '',
    filters: () => ({ page_size: 20 }),
    refreshVersion: 0,
  },
)

const emit = defineEmits<{
  open: [id: string]
  delete: [task: ScanTask]
  toggleArchive: [id: string]
  archiveChanged: []
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

function openRow(task: ScanTask): void {
  if (task.archive) emit('toggleArchive', task.id)
  else emit('open', task.id)
}

function expandedChanged(task: ScanTask, expandedRows: ScanTask[]): void {
  if (!task.archive) return
  const expanded = expandedRows.some((row) => row.id === task.id)
  if (expanded !== (props.expandedId === task.id)) emit('toggleArchive', task.id)
}
</script>

<template>
  <div class="task-table">
    <span class="sr-only">
      点击归档导入行可展开子任务，点击其他任务可打开详情。
    </span>
    <div
      class="task-table__scroller"
      role="region"
      aria-label="任务列表"
    >
      <!-- Use small proportional column bases so fit can share the available
           width instead of imposing a desktop-sized horizontal scroll area. -->
      <el-table
        class="task-table__data"
        :data="items"
        empty-text="当前批次暂无任务"
        row-key="id"
        :expand-row-keys="expandedId ? [expandedId] : []"
        :row-class-name="({ row }: { row: ScanTask }) => row.archive ? 'task-row--archive' : 'task-row--standalone'"
        @row-click="openRow"
        @expand-change="expandedChanged"
      >
        <el-table-column type="expand" width="34">
          <template #default="{ row }: { row: ScanTask }">
            <ArchiveTaskExpansion
              v-if="row.archive && expandedId === row.id"
              :task="row"
              :filters="filters"
              :user-role="userRole"
              :current-user-id="currentUserId"
              :pending-task-id="pendingTaskId"
              :refresh-version="refreshVersion"
              @open="emit('open', $event)"
              @delete="emit('delete', $event)"
              @changed="emit('archiveChanged')"
            />
          </template>
        </el-table-column>
        <el-table-column label="任务" min-width="22">
          <template #default="{ row }: { row: ScanTask }">
            <div class="task-cell">
              <span class="task-cell__icon" aria-hidden="true">
                <Archive v-if="row.archive" :size="17" aria-hidden="true" />
                <FileCode2 v-else :size="17" aria-hidden="true" />
              </span>
              <span class="task-cell__copy">
                <button
                  class="task-cell__open"
                  type="button"
                  :aria-label="row.archive ? `${expandedId === row.id ? '收起' : '展开'}归档子任务：${row.name}` : `查看任务：${row.name}`"
                  v-bind="row.archive ? { 'aria-expanded': expandedId === row.id, 'aria-controls': `archive-task-${row.id}` } : {}"
                  :title="row.name"
                  @click.stop="openRow(row)"
                >
                  {{ row.name }}
                </button>
                <small class="task-cell__id mono" :title="row.id">
                  {{ row.id }}
                </small>
                <small
                  v-if="!row.archive && taskSampleRetention(row).status !== 'available'"
                  class="task-cell__retention"
                  :class="`task-cell__retention--${taskSampleRetention(row).status}`"
                  :data-retention-status="taskSampleRetention(row).status"
                  :title="taskSampleRetention(row).actionReason"
                >
                  {{ taskSampleRetention(row).statusLabel }}
                </small>
                <small v-if="row.archive && !row.archive.source_retained" class="task-cell__archive-note">原始归档已清理</small>
              </span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="类型" width="104" align="center">
          <template #default="{ row }: { row: ScanTask }">
            <span class="table-token table-token--type mono" :title="row.input_type">
              {{ row.input_type }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="分析模式" min-width="12" align="center">
          <template #default="{ row }: { row: ScanTask }">
            <span class="table-token">
              {{ row.analysis_mode === 'binary' ? '二进制' : row.analysis_mode === 'archive' ? '归档导入' : row.analysis_mode === 'container' ? '容器/映像' : '历史任务' }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="执行状态" min-width="12">
          <template #default="{ row }: { row: ScanTask }">
            <div v-if="row.archive" class="archive-state">
              <span :class="{ 'archive-state--failed': row.archive.status === 'failed' }">{{ archiveStatusLabels[row.archive.status] }}</span>
              <small>{{ row.archive.active_count }} 执行中 · {{ row.archive.failed_count }} 失败</small>
            </div>
            <TaskExecutionBadge v-else :task="row" />
          </template>
        </el-table-column>
        <el-table-column label="当前阶段" min-width="14">
          <template #default="{ row }: { row: ScanTask }">
            <div v-if="row.archive" class="archive-state">
              <span>{{ row.archive.completed_count }}/{{ row.archive.child_count }} 检测完成</span>
              <small>子任务检测结果</small>
            </div>
            <span v-else class="table-muted">{{ taskExecutionProgressLabel(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="创建者" min-width="10" align="center">
          <template #default="{ row }: { row: ScanTask }">
            <span class="table-token" :title="row.creator_name">
              {{ row.creator_name }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="创建时间" min-width="15">
          <template #default="{ row }: { row: ScanTask }">
            <span class="table-muted">{{ formatDateTime(row.created_at) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="64" align="center">
          <template #default="{ row }: { row: ScanTask }">
            <div v-if="!row.archive" class="row-commands" role="group" :aria-label="`${row.name} 任务操作`">
              <button
                class="row-command"
                type="button"
                :disabled="!deleteAction(row).enabled || pendingTaskId === row.id"
                :aria-label="`删除任务：${row.name}`"
                :title="deleteAction(row).reason"
                @click.stop="emit('delete', row)"
              >
                <Trash2 :size="16" aria-hidden="true" />
              </button>
            </div>
            <span v-else class="table-muted" title="展开归档行可管理成员和总报告">—</span>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <footer class="task-table__footer">
      <span>本批 {{ items.length }} 项 · 子任务单独分页</span>
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
  container-type: inline-size;
}

.task-table__scroller {
  width: 100%;
  max-width: 100%;
}

.task-table__data {
  width: 100%;
}

.task-table :deep(.el-table__row) {
  cursor: pointer;
}

.task-table :deep(.task-row--standalone > td .el-table__expand-icon) {
  visibility: hidden;
  pointer-events: none;
}

.task-table :deep(.el-table__expanded-cell) {
  padding: 0 !important;
}

.archive-state { display: grid; gap: 4px; color: var(--ink-700); font-size: 12px; line-height: 1.5; }
.archive-state small, .task-cell__archive-note { color: var(--ink-500); font-size: 11px; }
.archive-state--failed { color: var(--danger); }
.task-cell__archive-note { display: block; margin-top: 5px; }

.task-table :deep(.el-table th.el-table__cell) {
  height: 48px;
  padding-block: 10px;
}

.task-table :deep(.el-table td.el-table__cell) {
  padding-block: 18px;
}

.task-table :deep(.el-table .cell) {
  padding-inline: 8px;
  overflow-wrap: anywhere;
}

.task-table :deep(.el-table td:first-child .cell),
.task-table :deep(.el-table th:first-child .cell) {
  padding-left: 16px;
}

.task-table :deep(.el-table td:last-child .cell),
.task-table :deep(.el-table th:last-child .cell) {
  padding-inline: 8px;
}

.task-table :deep(.status-badge) {
  min-width: 0;
  max-width: 100%;
  white-space: normal;
}

.task-table :deep(.status-badge__dot) {
  flex-shrink: 0;
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

.table-muted {
  display: block;
  color: var(--ink-600);
  font-size: 13px;
  overflow-wrap: anywhere;
}

.table-token {
  display: block;
  overflow: hidden;
  color: var(--ink-600);
  font-size: 13px;
  overflow-wrap: anywhere;
}

.table-token--type {
  white-space: nowrap;
  text-overflow: ellipsis;
}

.row-command {
  display: inline-flex;
  width: 32px;
  height: 32px;
  align-items: center;
  justify-content: center;
  padding: 0;
  border: 0;
  border-radius: var(--radius-sm);
  color: var(--ink-500);
  background: transparent;
  cursor: pointer;
}

.row-commands {
  display: flex;
  justify-content: center;
}

.row-command:hover {
  color: var(--ink-800);
  background: var(--surface-muted);
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

@container (max-width: 850px) {
  .task-cell {
    gap: 0;
  }

  .task-cell__icon {
    display: none;
  }

  .task-table :deep(.status-badge) {
    gap: 4px;
    padding-inline: 5px;
  }
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
