<script setup lang="ts">
import {
  ArchiveRestore,
  Download,
  FileArchive,
  LoaderCircle,
  RefreshCw,
  ShieldAlert,
} from 'lucide-vue-next'
import { computed, shallowRef } from 'vue'

import type { ArchiveImport, ReportFormat } from '@/api/types'
import { useArchiveReportBundles } from '@/composables/useArchiveReportBundles'
import { useSessionStore } from '@/stores/session'
import { formatBytes, formatDateTime } from '@/utils/formatters'

const props = defineProps<{
  archiveImport: ArchiveImport
}>()

const session = useSessionStore()
const selectedFormats = shallowRef<ReportFormat[]>(['html', 'json'])
const includeSources = shallowRef(false)
const model = useArchiveReportBundles({
  importId: () => props.archiveImport.id,
})

const canGenerate = computed(
  () =>
    session.user?.role === 'administrator' ||
    session.user?.role === 'operator',
)
const selectedFormatSet = computed(() => new Set(selectedFormats.value))

const formatOptions: readonly { value: ReportFormat; label: string }[] = [
  { value: 'html', label: 'HTML' },
  { value: 'json', label: 'JSON' },
  { value: 'docx', label: 'Word' },
]

function toggleFormat(format: ReportFormat, checked: boolean): void {
  const next = new Set(selectedFormats.value)
  if (checked) next.add(format)
  else next.delete(format)
  selectedFormats.value = [...next]
}

async function generate(): Promise<void> {
  if (selectedFormats.value.length === 0) return
  const created = await model.generate({
    formats: selectedFormats.value,
    include_sources: includeSources.value,
  })
  if (created) await model.download(created)
}
</script>

<template>
  <section class="bundle-panel" aria-label="归档总报告">
    <header class="bundle-panel__header">
      <div>
        <span class="bundle-panel__icon" aria-hidden="true">
          <ArchiveRestore :size="17" />
        </span>
        <span>
          <strong>归档总报告</strong>
          <small>
            {{ archiveImport.report_ready_tasks }}/{{ archiveImport.created_tasks }} 个子任务已有报告，
            共 {{ archiveImport.ready_reports }} 份
          </small>
        </span>
      </div>
      <button
        type="button"
        title="刷新报告包列表"
        aria-label="刷新报告包列表"
        :disabled="model.loading.value || model.generating.value"
        @click="model.load"
      >
        <RefreshCw :size="15" aria-hidden="true" />
      </button>
    </header>

    <p class="bundle-panel__hint">
      仅收集各子任务已经生成成功的报告；未完成、未生成或缺少所选格式的任务会写入
      manifest.json，不会阻止其他任务导出。
    </p>

    <div class="bundle-panel__builder">
      <fieldset>
        <legend>报告格式</legend>
        <label v-for="option in formatOptions" :key="option.value">
          <input
            type="checkbox"
            :checked="selectedFormatSet.has(option.value)"
            @change="toggleFormat(option.value, ($event.target as HTMLInputElement).checked)"
          >
          <span>{{ option.label }}</span>
        </label>
      </fieldset>
      <label class="bundle-panel__sources">
        <input v-model="includeSources" type="checkbox">
        <span>
          包含反编译源码
          <small>源码按子任务和源码项目写入 ZIP，便于离线核对漏洞位置。</small>
        </span>
      </label>
      <el-button
        v-if="canGenerate"
        type="primary"
        :icon="FileArchive"
        :loading="model.generating.value"
        :disabled="selectedFormats.length === 0 || archiveImport.report_ready_tasks === 0 || Boolean(model.downloadingId.value)"
        @click="generate"
      >
        生成并下载总报告
      </el-button>
      <span v-else class="bundle-panel__readonly">当前角色只能下载已有总报告</span>
    </div>

    <p
      v-if="model.error.value || model.operationError.value"
      class="bundle-panel__error"
      role="alert"
    >
      <ShieldAlert :size="15" aria-hidden="true" />
      <span>{{ model.operationError.value || model.error.value }}</span>
    </p>

    <div v-if="model.loading.value && model.bundles.value.length === 0" class="bundle-panel__loading">
      <LoaderCircle class="spin" :size="15" aria-hidden="true" />
      正在读取归档总报告
    </div>
    <div v-else-if="model.bundles.value.length" class="bundle-list">
      <article v-for="bundle in model.bundles.value" :key="bundle.id" class="bundle-row">
        <span class="bundle-row__icon" aria-hidden="true">
          <FileArchive :size="17" />
        </span>
        <div class="bundle-row__identity">
          <strong>{{ bundle.formats.map((format) => format.toUpperCase()).join(' + ') }}</strong>
          <small>
            {{ bundle.included_tasks }} 个已包含 · {{ bundle.omitted_tasks }} 个省略 ·
            {{ bundle.report_files }} 份报告
            <template v-if="bundle.include_sources"> · {{ bundle.source_files }} 个源码文件</template>
          </small>
        </div>
        <div class="bundle-row__metadata">
          <span>{{ formatBytes(bundle.size_bytes) }}</span>
          <time :datetime="bundle.completed_at">{{ formatDateTime(bundle.completed_at) }}</time>
          <code :title="bundle.sha256">{{ bundle.sha256.slice(0, 16) }}…</code>
        </div>
        <el-button
          :icon="Download"
          :loading="model.downloadingId.value === bundle.id"
          :disabled="Boolean(model.downloadingId.value) || model.generating.value"
          @click="model.download(bundle)"
        >
          下载
        </el-button>
      </article>
    </div>
    <p v-else-if="!model.loading.value" class="bundle-panel__empty">
      尚未生成归档总报告。
    </p>
  </section>
</template>

<style scoped>
.bundle-panel {
  margin: 0 14px 14px;
  border: 1px solid var(--line);
  border-radius: 5px;
  background: #f8fbfa;
}

.bundle-panel__header,
.bundle-panel__header > div,
.bundle-panel__builder,
.bundle-row,
.bundle-panel__error,
.bundle-panel__loading {
  display: flex;
  align-items: center;
}

.bundle-panel__header {
  min-height: 54px;
  justify-content: space-between;
  gap: 12px;
  padding: 9px 12px;
  border-bottom: 1px solid var(--line);
}

.bundle-panel__header > div {
  min-width: 0;
  gap: 9px;
}

.bundle-panel__header span:not(.bundle-panel__icon),
.bundle-row__identity,
.bundle-row__metadata {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.bundle-panel__header strong,
.bundle-panel__header small {
  display: block;
}

.bundle-panel__header strong {
  color: var(--ink-800);
  font-size: 12px;
}

.bundle-panel__header small,
.bundle-row small,
.bundle-panel__hint,
.bundle-panel__empty,
.bundle-panel__readonly {
  color: var(--ink-600);
  font-size: 10px;
}

.bundle-panel__icon,
.bundle-row__icon {
  display: grid;
  place-items: center;
  color: var(--teal-strong);
}

.bundle-panel__header button {
  display: grid;
  width: 30px;
  height: 30px;
  place-items: center;
  padding: 0;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--ink-600);
  background: #fff;
  cursor: pointer;
}

.bundle-panel__hint {
  margin: 0;
  padding: 10px 12px 0;
  line-height: 1.6;
}

.bundle-panel__builder {
  flex-wrap: wrap;
  gap: 12px;
  padding: 10px 12px 12px;
}

.bundle-panel__builder fieldset {
  display: flex;
  align-items: center;
  gap: 9px;
  margin: 0;
  padding: 0;
  border: 0;
}

.bundle-panel__builder legend {
  float: left;
  margin-right: 3px;
  color: var(--ink-700);
  font-size: 10px;
  font-weight: 700;
}

.bundle-panel__builder label,
.bundle-panel__sources {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  color: var(--ink-700);
  font-size: 10px;
}

.bundle-panel__sources > span {
  display: grid;
}

.bundle-panel__sources small {
  color: var(--ink-500);
  font-size: 9px;
}

.bundle-panel__error,
.bundle-panel__loading,
.bundle-panel__empty {
  gap: 7px;
  margin: 0 12px 12px;
  padding: 9px 10px;
  border-radius: 4px;
}

.bundle-panel__error {
  color: var(--red);
  background: #fff3f1;
}

.bundle-panel__loading,
.bundle-panel__empty {
  color: var(--ink-600);
  background: #fff;
}

.bundle-list {
  display: grid;
  gap: 7px;
  padding: 0 12px 12px;
}

.bundle-row {
  gap: 10px;
  padding: 9px 10px;
  border: 1px solid var(--line);
  border-radius: 4px;
  background: #fff;
}

.bundle-row__identity {
  flex: 1 1 260px;
}

.bundle-row__identity strong {
  color: var(--ink-800);
  font-size: 11px;
}

.bundle-row__metadata {
  flex: 0 1 220px;
  color: var(--ink-500);
  font-size: 9px;
  text-align: right;
}

.bundle-row__metadata code {
  overflow: hidden;
  text-overflow: ellipsis;
}

@media (max-width: 760px) {
  .bundle-row {
    align-items: flex-start;
    flex-wrap: wrap;
  }

  .bundle-row__metadata {
    width: 100%;
    flex-basis: 100%;
    text-align: left;
  }
}
</style>
