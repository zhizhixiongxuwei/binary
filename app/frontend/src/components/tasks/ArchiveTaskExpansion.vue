<script setup lang="ts">
import { ChevronDown, ChevronLeft, ChevronRight, Trash2 } from 'lucide-vue-next'
import { computed, onScopeDispose, shallowRef, watch } from 'vue'

import { api, ApiError } from '@/api/client'
import type { ArchiveImport, ScanTask, TaskListQuery, UserRole } from '@/api/types'
import TaskExecutionBadge from '@/components/tasks/TaskExecutionBadge.vue'
import { canManageArchive } from '@/components/tasks/archiveTaskPresentation'
import { getTaskActionModel } from '@/components/tasks/taskActions'
import { taskExecutionProgressLabel } from '@/components/tasks/taskExecutionPresentation'
import ArchiveImportWorkspace from '@/components/uploads/ArchiveImportWorkspace.vue'
import { useArchiveTaskChildren } from '@/composables/useArchiveTaskChildren'
import { formatDateTime } from '@/utils/formatters'

const props = withDefaults(defineProps<{
  task: ScanTask
  filters: TaskListQuery
  userRole?: UserRole | null
  currentUserId?: string | null
  pendingTaskId?: string | null
  refreshVersion?: number
}>(), { userRole: null, currentUserId: null, pendingTaskId: null, refreshVersion: 0 })

const emit = defineEmits<{
  open: [id: string]
  delete: [task: ScanTask]
  changed: []
}>()

const children = useArchiveTaskChildren(() => props.task, () => props.filters)
const membersOpen = shallowRef(props.task.archive?.child_count === 0)
const imports = shallowRef<ArchiveImport[]>([])
const selectedImportId = shallowRef(props.task.archive?.import_id ?? '')
const importsCursor = shallowRef('')
const loadingImports = shallowRef(false)
const importError = shallowRef('')
let importsGeneration = 0
let disposed = false

const selectedImport = computed(() => imports.value.find((item) => item.id === selectedImportId.value))
const canManage = computed(() => canManageArchive(props.task, props.userRole, props.currentUserId))
const archive = computed(() => props.task.archive)

async function loadImports(append = false): Promise<void> {
  const generation = ++importsGeneration
  loadingImports.value = true
  importError.value = ''
  try {
    const page = await api.listArchiveImports({
      task_id: props.task.id,
      page_size: 50,
      ...(append && importsCursor.value ? { cursor: importsCursor.value } : {}),
    })
    if (disposed || generation !== importsGeneration) return
    const previousSelection = imports.value.find((item) => item.id === selectedImportId.value)
    const next = append ? [...imports.value, ...page.items] : [...page.items]
    // A refresh of the first page must not discard a selected older import.
    // Refresh that one known record so its member/report scope stays stable.
    if (!append && previousSelection && !next.some((item) => item.id === previousSelection.id)) {
      try {
        const selected = await api.getArchiveImport(previousSelection.id)
        if (disposed || generation !== importsGeneration) return
        next.push(selected)
      } catch (error) {
        if (disposed || generation !== importsGeneration) return
        if (!(error instanceof ApiError && error.status === 404)) throw error
      }
    }
    imports.value = [...new Map(next.map((item) => [item.id, item])).values()]
    importsCursor.value = page.next_cursor ?? ''
    if (!imports.value.some((item) => item.id === selectedImportId.value)) {
      selectedImportId.value = imports.value[0]?.id ?? ''
    }
  } catch (error) {
    if (disposed || generation !== importsGeneration) return
    importError.value = error instanceof ApiError ? error.message : '无法读取归档解析批次'
  } finally {
    if (!disposed && generation === importsGeneration) loadingImports.value = false
  }
}

function deleteAction(task: ScanTask) {
  return getTaskActionModel({
    task,
    mode: 'live',
    userRole: props.userRole,
    isCreator: task.creator_id === props.currentUserId,
  }).delete
}

async function refresh(): Promise<void> {
  await Promise.all([children.refresh(), ...(membersOpen.value ? [loadImports()] : [])])
}

async function changed(): Promise<void> {
  emit('changed')
  await refresh()
}

watch(membersOpen, (open) => {
  if (open && !imports.value.length) void loadImports()
}, { immediate: true })

watch(() => props.refreshVersion, () => void refresh())
watch(() => props.task.archive?.import_id, (importId, previous) => {
  if (importId === previous) return
  selectedImportId.value = importId ?? ''
  if (membersOpen.value) void loadImports()
})

onScopeDispose(() => {
  disposed = true
  importsGeneration += 1
})
</script>

<template>
  <section :id="`archive-task-${task.id}`" class="archive-task" :aria-label="`${task.name} 的归档子任务`" @click.stop>
    <header class="archive-task__header">
      <strong>子任务 <span class="mono">{{ archive?.child_count ?? 0 }}</span></strong>
    </header>

    <div v-if="children.hasFilters.value" class="archive-task__filter-note">
      <span>{{ children.matchingOnly.value ? '子任务已应用当前列表的匹配条件' : '正在显示全部子任务' }}</span>
      <button type="button" @click="children.matchingOnly.value = !children.matchingOnly.value">
        {{ children.matchingOnly.value ? '显示全部子任务' : '仅显示匹配子任务' }}
      </button>
    </div>
    <p v-if="children.error.value" class="archive-task__error" role="alert">
      {{ children.error.value }}
      <button type="button" @click="children.refresh">重试</button>
    </p>
    <p v-if="children.loading.value && !children.items.value.length" class="archive-task__empty" role="status">正在读取子任务</p>
    <template v-else>
      <el-table
        v-if="children.items.value.length"
        :data="children.items.value"
        row-key="id"
        class="archive-task__table"
        :aria-busy="children.loading.value"
        @row-click="(child: ScanTask) => emit('open', child.id)"
      >
        <el-table-column label="子任务 / 归档内路径" min-width="160">
          <template #default="{ row }: { row: ScanTask }">
            <button type="button" class="archive-task__open" :title="row.name" @click.stop="emit('open', row.id)">{{ row.name }}</button>
            <small class="archive-task__path mono" :title="row.archive_path ?? row.id">{{ row.archive_path ?? row.id }}</small>
          </template>
        </el-table-column>
        <el-table-column label="类型" width="100">
          <template #default="{ row }: { row: ScanTask }"><span class="mono">{{ row.input_type }}</span></template>
        </el-table-column>
        <el-table-column label="执行状态" min-width="110">
          <template #default="{ row }: { row: ScanTask }"><TaskExecutionBadge :task="row" /></template>
        </el-table-column>
        <el-table-column label="当前阶段" min-width="110">
          <template #default="{ row }: { row: ScanTask }">
            <small>{{ taskExecutionProgressLabel(row) }}</small>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="60" align="center">
          <template #default="{ row }: { row: ScanTask }">
            <button
              class="archive-task__delete"
              type="button"
              :aria-label="`删除子任务：${row.name}`"
              :title="deleteAction(row).reason"
              :disabled="!deleteAction(row).enabled || pendingTaskId === row.id"
              @click.stop="emit('delete', row)"
            ><Trash2 :size="15" aria-hidden="true" /></button>
          </template>
        </el-table-column>
      </el-table>
      <p v-else-if="!children.error.value" class="archive-task__empty">
        {{ archive?.child_count ? '没有符合当前条件的子任务。' : '尚未创建子任务，可在归档成员中选择文件创建检测任务。' }}
      </p>
      <footer v-if="children.pageIndex.value > 0 || children.nextCursor.value" class="archive-task__pagination">
        <span>子任务第 {{ children.pageIndex.value + 1 }} 批 · 本批 {{ children.items.value.length }} 个</span>
        <div>
          <el-button size="small" :icon="ChevronLeft" :disabled="!children.pageIndex.value || children.loading.value" aria-label="上一批子任务" @click="children.previousPage">上一批</el-button>
          <el-button size="small" :icon="ChevronRight" :disabled="!children.nextCursor.value || children.loading.value" aria-label="下一批子任务" @click="children.nextPage">下一批</el-button>
        </div>
      </footer>
    </template>

    <button class="archive-task__members-toggle" type="button" :aria-expanded="membersOpen" :aria-controls="`archive-members-${task.id}`" @click="membersOpen = !membersOpen">
      <span>归档成员与总报告</span>
      <small>{{ archive?.source_retained ? '选择成员创建任务、查看跳过原因、导出报告' : '原始归档已清理，子任务和报告关系保留' }}</small>
      <ChevronDown :size="16" aria-hidden="true" :class="{ 'archive-task__chevron--open': membersOpen }" />
    </button>
    <div v-if="membersOpen" :id="`archive-members-${task.id}`" class="archive-task__members">
      <div class="archive-task__history">
        <label :for="`archive-run-${task.id}`">解析批次</label>
        <el-select :id="`archive-run-${task.id}`" v-model="selectedImportId" :loading="loadingImports" aria-label="选择归档解析批次">
          <el-option v-for="item in imports" :key="item.id" :value="item.id" :label="`${formatDateTime(item.created_at)} · ${item.created_tasks} 个已建任务${item.id === archive?.import_id ? ' · 最新' : ''}`" />
        </el-select>
        <el-button v-if="importsCursor" size="small" :loading="loadingImports" @click="loadImports(true)">加载更早批次</el-button>
      </div>
      <p class="archive-task__scope">下方成员和总报告仅属于所选解析批次；上方子任务列表包含全部批次。</p>
      <p v-if="importError" class="archive-task__error" role="alert">{{ importError }} <button type="button" @click="loadImports()">重试</button></p>
      <p v-else-if="loadingImports && !selectedImport" class="archive-task__empty" role="status">正在读取归档成员</p>
      <ArchiveImportWorkspace
        v-if="selectedImport"
        :key="selectedImport.id"
        :task-id="task.id"
        :import-id="selectedImport.id"
        :upload-id="selectedImport.upload_id"
        :filename="selectedImport.filename"
        :apply-initial-selection="false"
        :can-manage="canManage"
        @open-task="emit('open', $event)"
        @changed="changed"
        @deleted="changed"
      />
    </div>
  </section>
</template>

<style scoped>
.archive-task { min-width: 0; padding: 18px 20px; border-block: 1px solid var(--primary-border); background: var(--surface-raised); }
.archive-task__header, .archive-task__pagination, .archive-task__filter-note, .archive-task__history { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.archive-task__header { margin-bottom: 12px; }
.archive-task__header strong { color: var(--ink-800); font-size: 14px; }
.archive-task small, .archive-task__scope, .archive-task__pagination, .archive-task__filter-note { color: var(--ink-500); font-size: 12px; line-height: 1.6; }
.archive-task__filter-note { justify-content: flex-start; flex-wrap: wrap; margin-bottom: 10px; }
.archive-task__filter-note button, .archive-task__error button, .archive-task__open { padding: 0; border: 0; color: var(--primary); background: transparent; text-align: left; cursor: pointer; }
.archive-task__open { max-width: 100%; font-size: 13px; font-weight: 500; overflow-wrap: anywhere; }
.archive-task__path { display: block; overflow-wrap: anywhere; }
.archive-task__table { border: 1px solid var(--line); border-radius: 6px; }
.archive-task__table :deep(.el-table__row) { cursor: pointer; }
.archive-task__empty { margin: 10px 0; padding: 16px 12px; color: var(--ink-600); background: var(--surface); font-size: 13px; line-height: 1.6; }
.archive-task__error { color: var(--danger); font-size: 13px; }
.archive-task__delete { display: inline-grid; width: 30px; height: 30px; place-items: center; border: 0; border-radius: 4px; color: var(--ink-500); background: transparent; cursor: pointer; }
.archive-task__delete:disabled { color: var(--ink-300); cursor: not-allowed; }
.archive-task__pagination { margin-top: 10px; flex-wrap: wrap; }
.archive-task__members-toggle { display: flex; width: 100%; align-items: center; gap: 12px; padding: 14px 0; margin-top: 12px; border: 0; border-top: 1px solid var(--line); color: var(--ink-700); background: transparent; text-align: left; cursor: pointer; }
.archive-task__members-toggle > span { flex-shrink: 0; font-size: 13px; font-weight: 500; }
.archive-task__members-toggle > small { flex: 1; }
.archive-task__chevron--open { transform: rotate(180deg); }
.archive-task__history { justify-content: flex-start; flex-wrap: wrap; font-size: 12px; color: var(--ink-600); }
.archive-task__history :deep(.el-select) { width: min(100%, 350px); }
.archive-task__scope { margin: 8px 0 12px; }
.archive-task button:focus-visible { outline: 2px solid var(--primary); outline-offset: 3px; }
@media (max-width: 660px) {
  .archive-task { padding: 12px 10px; }
  .archive-task__members-toggle { flex-wrap: wrap; gap: 6px; }
  .archive-task__members-toggle > small { flex-basis: calc(100% - 30px); order: 2; }
  .archive-task__members-toggle > svg { margin-left: auto; }
  .archive-task__table :deep(.el-table__body-wrapper) { overflow-x: auto; }
}
</style>
