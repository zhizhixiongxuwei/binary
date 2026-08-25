<script setup lang="ts">
import {
  AlertTriangle,
  ArrowUpRight,
  ChevronDown,
  RefreshCw,
  Trash2,
  Upload,
} from 'lucide-vue-next'
import { computed, onMounted, shallowRef } from 'vue'
import { useRouter } from 'vue-router'

import type { AnalysisMode, ArchiveImport, UploadAnalysisTask } from '@/api/types'
import ArchiveImportWorkspace from '@/components/uploads/ArchiveImportWorkspace.vue'
import FileDropzone from '@/components/uploads/FileDropzone.vue'
import SupportedUploadTypes from '@/components/uploads/SupportedUploadTypes.vue'
import { useArchiveImportList } from '@/composables/useArchiveImportList'
import {
  type UnifiedUploadItem,
  useUnifiedUpload,
} from '@/composables/useUnifiedUpload'
import { formatBytes } from '@/utils/formatters'

const router = useRouter()
const uploads = useUnifiedUpload()
const imports = useArchiveImportList()
const warningMessage = shallowRef('')
const expandedImportId = shallowRef<string | null>(null)

const modes: readonly {
  value: AnalysisMode
  label: string
  description: string
}[] = [
  {
    value: 'binary',
    label: '二进制分析',
    description: '创建任务后手动反编译并启动源码检测',
  },
  {
    value: 'archive',
    label: '压缩包分析',
    description: '自动解析一个逻辑层，再选择二进制成员',
  },
  {
    value: 'container',
    label: '容器/映像分析',
    description: 'Docker/OCI 可手动启动 Trivy，其他格式记录不适用',
  },
]

const expandedImport = computed(
  () =>
    imports.items.value.find((item) => item.id === expandedImportId.value) ??
    null,
)

function addFiles(files: File[]): void {
  warningMessage.value = uploads.addFiles(files).join('；')
}

function showRejected(messages: string[]): void {
  warningMessage.value = messages.join('；')
}

function option(item: UnifiedUploadItem, mode: AnalysisMode) {
  return item.analysisOptions.find((candidate) => candidate.mode === mode)
}

function task(item: UnifiedUploadItem, mode: AnalysisMode) {
  return item.tasks.find((candidate) => candidate.analysis_mode === mode)
}

async function chooseMode(
  item: UnifiedUploadItem,
  mode: AnalysisMode,
): Promise<void> {
  const created = await uploads.selectMode(item.localId, mode)
  if (!created) return
  if (created.analysis_mode === 'archive' && created.archive_import_id) {
    await imports.refresh()
    expandedImportId.value = created.archive_import_id
    uploads.forget(item.localId)
    return
  }
  uploads.forget(item.localId)
  openCreatedTask(created)
}

function openCreatedTask(created: UploadAnalysisTask): void {
  void router.push({ name: 'task-detail', params: { id: created.task_id } })
}

function toggleArchive(item: ArchiveImport): void {
  expandedImportId.value = expandedImportId.value === item.id ? null : item.id
}

function forgetArchive(item: ArchiveImport): void {
  imports.remove(item.id)
  if (expandedImportId.value === item.id) expandedImportId.value = null
}

onMounted(() => {
  void uploads.recover()
})
</script>

<template>
  <section class="unified-upload surface-panel">
    <header class="unified-upload__header">
      <div>
        <span class="mono">UNIFIED INTAKE</span>
        <h2>统一文件上传</h2>
        <p>先上传并识别真实格式，再为每个文件选择分析模式。</p>
      </div>
      <el-button
        type="primary"
        :icon="Upload"
        :loading="uploads.activeId.value !== null"
        :disabled="uploads.readyCount.value === 0"
        @click="uploads.startAll"
      >
        开始上传
      </el-button>
    </header>

    <div class="unified-upload__body">
      <SupportedUploadTypes />
      <div v-if="warningMessage" class="upload-warning" role="alert">
        <AlertTriangle :size="16" aria-hidden="true" />
        <span>{{ warningMessage }}</span>
      </div>
      <div v-if="uploads.recoveryError.value" class="upload-warning" role="alert">
        <AlertTriangle :size="16" aria-hidden="true" />
        <span>{{ uploads.recoveryError.value }}</span>
      </div>
      <FileDropzone
        :disabled="uploads.activeId.value !== null"
        @selected="addFiles"
        @rejected="showRejected"
      />

      <div v-if="uploads.queue.value.length" class="asset-list">
        <article
          v-for="item in uploads.queue.value"
          :key="item.localId"
          class="asset-card"
        >
          <header class="asset-card__header">
            <div>
              <strong :title="item.filename">{{ item.filename }}</strong>
              <span>{{ formatBytes(item.size) }}</span>
            </div>
            <el-button
              text
              :icon="Trash2"
              :loading="item.removing"
              :disabled="item.status === 'uploading'"
              @click="uploads.remove(item.localId)"
            >
              {{ item.tasks.length ? '从列表移除' : '删除' }}
            </el-button>
          </header>

          <el-progress
            :percentage="item.progress"
            :stroke-width="5"
            :status="item.status === 'failed' ? 'exception' : item.status === 'awaiting_mode' ? 'success' : undefined"
          />
          <div class="asset-card__state">
            <span v-if="item.status === 'ready'">等待上传</span>
            <span v-else-if="item.status === 'uploading'">正在上传并识别</span>
            <span v-else-if="item.status === 'awaiting_mode'">上传完成，等待选择分析模式</span>
            <span v-else>上传失败</span>
            <span v-if="item.detectedFormat" class="mono">
              识别格式：{{ item.detectedFormat }}
            </span>
          </div>
          <p v-if="item.errorMessage" class="asset-card__error">
            {{ item.errorMessage }}
          </p>
          <el-button
            v-if="item.status === 'failed' && item.canRetry"
            :icon="RefreshCw"
            :disabled="uploads.activeId.value !== null"
            @click="uploads.uploadItem(item.localId)"
          >
            重试上传
          </el-button>

          <div v-if="item.status === 'awaiting_mode'" class="mode-grid">
            <div v-for="mode in modes" :key="mode.value" class="mode-card">
              <div class="mode-card__copy">
                <strong>{{ mode.label }}</strong>
                <p>{{ mode.description }}</p>
                <small
                  v-if="option(item, mode.value)?.supported === false"
                  class="mode-card__unsupported"
                >
                  {{ option(item, mode.value)?.reason }}
                </small>
              </div>
              <el-button
                v-if="!task(item, mode.value)"
                :type="option(item, mode.value)?.supported === false ? 'warning' : 'primary'"
                plain
                :loading="item.creatingMode === mode.value"
                :disabled="Boolean(item.creatingMode)"
                @click="chooseMode(item, mode.value)"
              >
                {{ option(item, mode.value)?.supported === false ? '仍按此模式创建' : '选择此模式' }}
              </el-button>
              <el-button
                v-else-if="mode.value === 'archive' && task(item, mode.value)?.archive_import_id"
                :icon="ChevronDown"
                @click="expandedImportId = task(item, mode.value)?.archive_import_id ?? null"
              >
                查看归档解析
              </el-button>
              <el-button
                v-else
                :icon="ArrowUpRight"
                @click="openCreatedTask(task(item, mode.value)!)"
              >
                {{ task(item, mode.value)?.supported ? '查看任务' : '查看不适用记录' }}
              </el-button>
            </div>
          </div>
        </article>
      </div>
      <div v-else-if="uploads.recovering.value" class="empty-state">
        正在恢复待处理上传……
      </div>
    </div>
  </section>

  <section v-if="imports.items.value.length" class="archive-list surface-panel">
    <header class="archive-list__header">
      <div>
        <span class="mono">ARCHIVE IMPORTS</span>
        <h2>归档解析与二进制任务</h2>
      </div>
      <el-button :icon="RefreshCw" :loading="imports.loading.value" @click="imports.refresh">
        刷新
      </el-button>
    </header>
    <button
      v-for="item in imports.items.value"
      :key="item.id"
      class="archive-row"
      type="button"
      @click="toggleArchive(item)"
    >
      <span>
        <strong>{{ item.filename }}</strong>
        <small class="mono">{{ item.id }}</small>
      </span>
      <span>{{ item.status === 'unsupported' ? '不适用/无结果' : item.status }}</span>
      <span>{{ item.eligible_entries }} 个可创建</span>
      <ChevronDown :size="16" aria-hidden="true" />
    </button>
    <ArchiveImportWorkspace
      v-if="expandedImport"
      :key="expandedImport.id"
      :import-id="expandedImport.id"
      :upload-id="expandedImport.upload_id"
      :filename="expandedImport.filename"
      @deleted="forgetArchive(expandedImport)"
      @open-task="(taskId) => router.push({ name: 'task-detail', params: { id: taskId } })"
    />
  </section>
</template>

<style scoped>
.unified-upload,
.archive-list {
  overflow: hidden;
}

.unified-upload__header,
.archive-list__header,
.asset-card__header,
.asset-card__state {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.unified-upload__header,
.archive-list__header {
  padding: 20px 22px;
  border-bottom: 1px solid var(--line);
}

.unified-upload__header h2,
.archive-list__header h2,
.unified-upload__header p {
  margin: 0;
}

.unified-upload__header p {
  margin-top: 5px;
  color: var(--ink-600);
  font-size: 12px;
}

.unified-upload__body {
  padding: 20px 22px 24px;
}

.asset-list {
  display: grid;
  gap: 12px;
  margin-top: 16px;
}

.asset-card {
  padding: 16px;
  border: 1px solid var(--line);
  border-radius: 5px;
  background: #fff;
}

.asset-card__header > div,
.archive-row > span:first-child {
  display: grid;
  min-width: 0;
  gap: 3px;
}

.asset-card__header span,
.asset-card__state,
.archive-row small {
  color: var(--ink-600);
  font-size: 11px;
}

.asset-card__state {
  margin-top: 8px;
}

.asset-card__error,
.mode-card__unsupported {
  color: var(--red);
}

.mode-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
  margin-top: 16px;
}

.mode-card {
  display: flex;
  min-width: 0;
  min-height: 154px;
  flex-direction: column;
  justify-content: space-between;
  gap: 12px;
  padding: 13px;
  border: 1px solid var(--line);
  border-radius: 5px;
  background: #f8fafa;
}

.mode-card p,
.mode-card small {
  display: block;
  margin: 5px 0 0;
  font-size: 11px;
  line-height: 1.55;
}

.archive-list {
  margin-top: 18px;
}

.archive-row {
  display: grid;
  width: 100%;
  grid-template-columns: minmax(0, 1fr) auto auto auto;
  align-items: center;
  gap: 16px;
  padding: 13px 18px;
  border: 0;
  border-bottom: 1px solid var(--line);
  color: var(--ink-800);
  background: #fff;
  text-align: left;
  cursor: pointer;
}

.empty-state {
  padding: 24px;
  color: var(--ink-600);
  text-align: center;
}

@media (max-width: 860px) {
  .mode-grid {
    grid-template-columns: 1fr;
  }

  .mode-card {
    min-height: 0;
  }
}

@media (max-width: 620px) {
  .unified-upload__header,
  .archive-list__header,
  .asset-card__header,
  .asset-card__state {
    align-items: stretch;
    flex-direction: column;
  }

  .archive-row {
    grid-template-columns: 1fr auto;
  }
}
</style>
