<script setup lang="ts">
import {
  Archive,
  ChevronDown,
  CircleAlert,
  FileStack,
  RefreshCw,
} from 'lucide-vue-next'
import { computed, shallowRef } from 'vue'
import { useRouter } from 'vue-router'

import type { ArchiveImport } from '@/api/types'
import PageHeader from '@/components/common/PageHeader.vue'
import ArchiveImportWorkspace from '@/components/uploads/ArchiveImportWorkspace.vue'
import { useArchiveImportList } from '@/composables/useArchiveImportList'
import { formatDateTime } from '@/utils/formatters'

const router = useRouter()
const model = useArchiveImportList()
const expandedId = shallowRef('')

const expanded = computed<ArchiveImport | null>(
  () => model.items.value.find((item) => item.id === expandedId.value) ?? null,
)

const statusLabels = {
  queued: '等待解析',
  running: '正在解析',
  ready: '解析完成',
  failed: '解析失败',
  unsupported: '不适用/无结果',
  deleting: '正在删除',
  deleted: '已删除',
} as const

function toggle(item: ArchiveImport): void {
  expandedId.value = expandedId.value === item.id ? '' : item.id
}

function forget(item: ArchiveImport): void {
  if (expandedId.value === item.id) expandedId.value = ''
  model.remove(item.id)
}

function openTask(taskId: string): void {
  void router.push({ name: 'task-detail', params: { id: taskId } })
}
</script>

<template>
  <div class="page-view">
    <PageHeader
      title="归档批次"
      eyebrow="ARCHIVES / INDEX"
      description="持久查看归档成员、已创建二进制任务和归档总报告；新建任务页面不会恢复这些历史记录。"
    >
      <template #actions>
        <el-button
          :icon="RefreshCw"
          :loading="model.loading.value"
          @click="model.refresh"
        >
          刷新批次
        </el-button>
      </template>
    </PageHeader>

    <section class="archive-catalog surface-panel" aria-label="归档批次列表">
      <header class="archive-catalog__header">
        <div>
          <FileStack :size="18" aria-hidden="true" />
          <span>
            <strong>归档批次记录</strong>
            <small>原始归档清理后，只要仍有已创建子任务，批次关系和总报告入口就会保留。</small>
          </span>
        </div>
        <span class="mono">{{ model.items.value.length }} IMPORTS</span>
      </header>

      <p v-if="model.error.value" class="archive-catalog__error" role="alert">
        <CircleAlert :size="16" aria-hidden="true" />
        <span>{{ model.error.value }}</span>
      </p>
      <div
        v-if="model.loading.value && model.items.value.length === 0"
        class="archive-catalog__state"
      >
        正在读取归档批次
      </div>
      <div
        v-else-if="model.items.value.length === 0"
        class="archive-catalog__state"
      >
        当前没有可查看的归档批次。
      </div>

      <div v-else class="archive-catalog__list">
        <template v-for="item in model.items.value" :key="item.id">
          <button
            type="button"
            class="archive-catalog-row"
            :aria-expanded="expandedId === item.id"
            :aria-controls="`archive-batch-${item.id}`"
            @click="toggle(item)"
          >
            <span class="archive-catalog-row__icon" aria-hidden="true">
              <Archive :size="17" />
            </span>
            <span class="archive-catalog-row__identity">
              <strong :title="item.filename">{{ item.filename }}</strong>
              <small class="mono">{{ item.id }}</small>
            </span>
            <span class="archive-catalog-row__status">
              <strong>{{ statusLabels[item.status] }}</strong>
              <small>{{ item.source_retained ? '原始归档保留中' : '原始归档已清理' }}</small>
            </span>
            <span class="archive-catalog-row__metrics">
              <strong>{{ item.created_tasks }}</strong> 个子任务
              <small>{{ item.report_ready_tasks }} 个已有报告 · {{ item.ready_reports }} 份报告</small>
            </span>
            <time :datetime="item.updated_at">{{ formatDateTime(item.updated_at) }}</time>
            <ChevronDown
              :size="16"
              aria-hidden="true"
              :class="{ 'archive-catalog-row__chevron--open': expandedId === item.id }"
            />
          </button>
          <ArchiveImportWorkspace
            v-if="expandedId === item.id && expanded"
            :id="`archive-batch-${item.id}`"
            :key="`workspace-${item.id}`"
            class="archive-catalog__workspace"
            :import-id="item.id"
            :upload-id="item.upload_id"
            :filename="item.filename"
            :apply-initial-selection="false"
            @deleted="forget(item)"
            @open-task="openTask"
          />
        </template>
      </div>

      <div v-if="model.nextCursor.value" class="archive-catalog__more">
        <el-button
          :icon="ChevronDown"
          :loading="model.loadingMore.value"
          @click="model.loadMore"
        >
          加载更多批次
        </el-button>
      </div>
    </section>
  </div>
</template>

<style scoped>
.archive-catalog {
  overflow: hidden;
}

.archive-catalog__header,
.archive-catalog__header > div,
.archive-catalog__error,
.archive-catalog-row {
  display: flex;
  align-items: center;
}

.archive-catalog__header {
  min-height: 62px;
  justify-content: space-between;
  gap: 16px;
  padding: 11px 16px;
  border-bottom: 1px solid var(--line);
}

.archive-catalog__header > div {
  min-width: 0;
  gap: 9px;
  color: var(--primary-hover);
}

.archive-catalog__header span:not(.mono),
.archive-catalog-row__identity,
.archive-catalog-row__status,
.archive-catalog-row__metrics {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.archive-catalog__header strong {
  color: var(--ink-800);
  font-size: 13px;
}

.archive-catalog__header small,
.archive-catalog__header > .mono {
  color: var(--ink-500);
  font-size: 11px;
}

.archive-catalog__error,
.archive-catalog__state {
  gap: 8px;
  margin: 14px;
  padding: 12px;
  border-radius: var(--radius-sm);
  color: var(--ink-600);
  background: var(--surface-raised);
  font-size: 12px;
}

.archive-catalog__error {
  color: var(--danger);
  background: var(--danger-soft);
}

.archive-catalog__list {
  display: grid;
}

.archive-catalog-row {
  width: 100%;
  min-height: 70px;
  gap: 12px;
  padding: 10px 16px;
  border: 0;
  border-bottom: 1px solid var(--line);
  color: inherit;
  background: var(--surface);
  text-align: left;
  cursor: pointer;
}

.archive-catalog-row:hover,
.archive-catalog-row[aria-expanded="true"] {
  background: var(--primary-soft);
}

.archive-catalog-row__icon {
  display: grid;
  width: 32px;
  height: 32px;
  flex: 0 0 32px;
  place-items: center;
  border: 1px solid var(--primary-border);
  border-radius: var(--radius-sm);
  color: var(--primary-hover);
  background: var(--surface);
}

.archive-catalog-row__identity {
  flex: 1 1 280px;
}

.archive-catalog-row__identity strong,
.archive-catalog-row__status strong,
.archive-catalog-row__metrics strong {
  overflow: hidden;
  color: var(--ink-800);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.archive-catalog-row small,
.archive-catalog-row time {
  color: var(--ink-500);
  font-size: 11px;
}

.archive-catalog-row__status {
  flex: 0 0 110px;
}

.archive-catalog-row__metrics {
  flex: 0 0 170px;
}

.archive-catalog-row time {
  flex: 0 0 130px;
  text-align: right;
}

.archive-catalog-row svg:last-child {
  transition: transform 150ms ease;
}

.archive-catalog-row__chevron--open {
  transform: rotate(180deg);
}

.archive-catalog__workspace {
  margin: 14px;
}

.archive-catalog__more {
  display: flex;
  justify-content: center;
  padding: 14px;
}

@media (max-width: 900px) {
  .archive-catalog-row {
    align-items: flex-start;
    flex-wrap: wrap;
  }

  .archive-catalog-row__identity {
    flex-basis: calc(100% - 74px);
  }

  .archive-catalog-row__status,
  .archive-catalog-row__metrics,
  .archive-catalog-row time {
    flex: 1 1 140px;
    text-align: left;
  }
}
</style>
