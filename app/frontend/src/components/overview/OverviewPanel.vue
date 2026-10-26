<script setup lang="ts">
import {
  AlertTriangle,
  ArrowRight,
  Clock3,
  FileCheck2,
  LoaderCircle,
  ShieldAlert,
} from 'lucide-vue-next'
import { computed, onMounted, shallowRef } from 'vue'
import { useRouter } from 'vue-router'

import { api, ApiError } from '@/api/client'
import type { ScanTask } from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import { formatDateTime } from '@/utils/formatters'

const router = useRouter()
const tasks = shallowRef<ScanTask[]>([])
const loading = shallowRef(true)
const errorMessage = shallowRef('')

const activeStatuses = new Set([
  'UPLOADING',
  'QUEUED',
  'VALIDATING',
  'IDENTIFYING',
  'EXTRACTING',
  'INDEXING',
  'SCANNING',
  'REPORTING',
  'RUNNING',
  'CANCEL_REQUESTED',
])

const running = computed(
  () => tasks.value.filter((task) => activeStatuses.has(task.status.toUpperCase())).length,
)
const queued = computed(
  () => tasks.value.filter((task) => task.status.toUpperCase() === 'QUEUED').length,
)
const attention = computed(
  () => tasks.value.filter((task) => {
    const risk = task.risk_level.toUpperCase()
    return (
      task.status.toUpperCase() === 'FAILED' ||
      risk === 'HIGH' ||
      risk === 'CRITICAL'
    )
  }).length,
)

function activityTone(status: ScanTask['status']): string {
  const normalized = status.toUpperCase()
  if (activeStatuses.has(normalized)) return 'active'
  if (normalized === 'PARTIAL_SUCCEEDED' || normalized === 'PARTIAL') return 'partial'
  return normalized.toLowerCase()
}

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    const result = await api.listTasks({ page_size: 8 })
    tasks.value = result.items
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '任务状态读取失败'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <StatePanel v-if="loading" class="surface-panel" kind="loading" />
  <StatePanel
    v-else-if="errorMessage"
    class="surface-panel"
    kind="error"
    :description="errorMessage"
    retryable
    @retry="load"
  />
  <div v-else class="overview">
    <dl class="metrics" aria-label="任务摘要">
      <div class="metric">
        <span class="metric__icon metric__icon--blue">
          <FileCheck2 :size="19" aria-hidden="true" />
        </span>
        <div class="metric__copy"><dt>最近任务</dt><dd>{{ tasks.length }}</dd></div>
      </div>
      <div class="metric">
        <span class="metric__icon metric__icon--teal">
          <LoaderCircle :size="19" aria-hidden="true" />
        </span>
        <div class="metric__copy"><dt>最近活动</dt><dd>{{ running }}</dd></div>
      </div>
      <div class="metric">
        <span class="metric__icon metric__icon--red">
          <ShieldAlert :size="19" aria-hidden="true" />
        </span>
        <div class="metric__copy"><dt>最近待关注</dt><dd>{{ attention }}</dd></div>
      </div>
      <div class="metric">
        <span class="metric__icon"><Clock3 :size="19" aria-hidden="true" /></span>
        <div class="metric__copy"><dt>最近排队</dt><dd>{{ queued }}</dd></div>
      </div>
    </dl>

    <section class="activity surface-panel">
      <header class="section-heading">
        <h2>最近任务</h2>
        <el-button text @click="router.push({ name: 'tasks' })">
          <span>查看全部</span>
          <ArrowRight :size="15" aria-hidden="true" />
        </el-button>
      </header>
      <StatePanel v-if="tasks.length === 0" kind="empty" title="暂无检测任务" />
      <div v-else class="activity-list">
        <button
          v-for="task in tasks"
          :key="task.id"
          class="activity-row"
          type="button"
          @click="router.push({ name: 'task-detail', params: { id: task.id } })"
        >
          <span
            class="activity-row__marker"
            :class="`activity-row__marker--${activityTone(task.status)}`"
            aria-hidden="true"
          />
          <span class="activity-row__copy">
            <strong>{{ task.name }}</strong>
            <small class="mono">{{ task.input_type }} / {{ task.id }}</small>
          </span>
          <span class="activity-row__badges">
            <StatusBadge :value="task.status" kind="status" />
            <StatusBadge :value="task.risk_level" kind="risk" />
          </span>
          <time :datetime="task.created_at">{{ formatDateTime(task.created_at) }}</time>
        </button>
      </div>
    </section>

    <div v-if="attention > 0" class="attention-strip">
      <AlertTriangle :size="16" aria-hidden="true" />
      <span>{{ attention }} 个最近任务需要关注</span>
    </div>
  </div>
</template>

<style scoped>
.overview {
  display: grid;
  gap: 24px;
  container: overview / inline-size;
}

.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 20px;
  padding: 0;
  margin: 0;
}

.metric {
  display: flex;
  min-height: 122px;
  align-items: center;
  gap: 16px;
  padding: 24px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: var(--shadow-sm);
}

.metric__icon {
  display: grid;
  width: 48px;
  height: 48px;
  flex: 0 0 48px;
  place-items: center;
  border-radius: 12px;
  color: var(--warning);
  background: var(--warning-soft);
}

.metric__icon--teal {
  color: var(--success);
  background: var(--success-soft);
}

.metric__icon--blue {
  color: var(--primary);
  background: var(--primary-soft);
}

.metric__icon--red {
  color: var(--danger);
  background: var(--danger-soft);
}

.metric__copy {
  min-width: 0;
}

.metric__copy dt,
.metric__copy dd {
  display: block;
  margin: 0;
}

.metric__copy dt {
  color: var(--ink-600);
  font-size: 13px;
  overflow-wrap: anywhere;
}

.metric__copy dd {
  margin-top: 7px;
  color: var(--ink-950);
  font-size: 30px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  line-height: 1.2;
}

.activity {
  overflow: hidden;
}

.section-heading {
  display: flex;
  min-height: 68px;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 12px 22px;
  border-bottom: 1px solid var(--line);
}

.section-heading h2 {
  margin: 0;
  color: var(--ink-950);
  font-size: 16px;
  font-weight: 600;
}

.section-heading :deep(.el-button) {
  color: var(--primary);
}

.section-heading :deep(.el-button > span) {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}

.activity-list {
  display: grid;
}

.activity-row {
  display: grid;
  min-height: 82px;
  grid-template-columns: 6px minmax(220px, 1fr) auto 156px;
  align-items: center;
  gap: 18px;
  padding: 16px 24px;
  border: 0;
  border-bottom: 1px solid var(--line);
  color: inherit;
  background: var(--surface);
  text-align: left;
  cursor: pointer;
  transition: background 160ms ease;
}

.activity-row:last-child {
  border-bottom: 0;
}

.activity-row:hover {
  background: var(--primary-soft);
}

.activity-row:focus-visible {
  position: relative;
  z-index: 1;
  outline-offset: -3px;
}

.activity-row__marker {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--ink-400);
}

.activity-row__marker--active {
  background: var(--primary);
}

.activity-row__marker--succeeded {
  background: var(--success);
}

.activity-row__marker--failed {
  background: var(--danger);
}

.activity-row__marker--partial {
  background: var(--warning);
}

.activity-row__copy {
  min-width: 0;
}

.activity-row__badges {
  display: flex;
  min-width: 0;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
}

.activity-row__copy strong,
.activity-row__copy small {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.activity-row__copy strong {
  color: var(--primary);
  font-size: 14px;
  font-weight: 600;
}

.activity-row__copy small,
.activity-row time {
  margin-top: 6px;
  color: var(--ink-500);
  font-size: 12px;
}

.activity-row time {
  margin-top: 0;
  text-align: right;
}

.attention-strip {
  display: flex;
  min-height: 48px;
  align-items: center;
  gap: 9px;
  padding: 12px 16px;
  border: 1px solid var(--warning-border);
  border-radius: var(--radius-sm);
  color: var(--warning);
  background: var(--warning-soft);
  font-size: 13px;
}

@container overview (max-width: 780px) {
  .metrics {
    grid-template-columns: 1fr 1fr;
  }

  .activity-row {
    grid-template-columns: 6px minmax(180px, 1fr) auto;
  }

  .activity-row time {
    display: none;
  }
}

@container overview (max-width: 620px) {
  .metrics {
    gap: 12px;
  }

  .metric {
    min-height: 106px;
    gap: 10px;
    padding: 14px;
  }

  .metric__icon {
    width: 38px;
    height: 38px;
    flex-basis: 38px;
    border-radius: 10px;
  }

  .metric__copy dd {
    font-size: 26px;
  }

  .activity-row {
    grid-template-areas:
      "marker copy"
      "marker badges";
    grid-template-columns: 6px minmax(0, 1fr);
    gap: 10px 12px;
    padding: 16px;
  }

  .activity-row__marker {
    grid-area: marker;
    align-self: start;
    margin-top: 7px;
  }

  .activity-row__copy {
    grid-area: copy;
  }

  .activity-row__badges {
    grid-area: badges;
    justify-content: flex-start;
    flex-wrap: wrap;
  }

  .section-heading {
    padding-right: 12px;
    padding-left: 16px;
  }
}

@container overview (max-width: 360px) {
  .metric {
    align-items: flex-start;
    flex-direction: column;
  }
}

@media (prefers-reduced-motion: reduce) {
  .activity-row {
    transition: none;
  }
}
</style>
