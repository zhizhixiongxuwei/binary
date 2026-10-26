<script setup lang="ts">
import { computed } from 'vue'

import type { RiskLevel, TaskStatus } from '@/api/types'

const props = defineProps<{
  value: TaskStatus | RiskLevel
  kind: 'status' | 'risk'
}>()

const statusLabels: Record<string, string> = {
  pending: '待提交',
  uploading: '上传中',
  queued: '排队中',
  validating: '校验中',
  identifying: '识别中',
  extracting: '解包中',
  indexing: '索引中',
  scanning: '扫描中',
  reporting: '报告生成中',
  running: '执行中',
  succeeded: '已完成',
  partial_succeeded: '部分完成',
  partial: '部分完成',
  failed: '失败',
  cancel_requested: '取消中',
  cancelled: '已取消',
  deleting: '删除中',
  deleted: '已删除',
}

const riskLabels: Record<string, string> = {
  none: '无风险',
  low: '低危',
  medium: '中危',
  high: '高危',
  critical: '严重',
  unknown: '未评估',
}

const normalizedValue = computed(() => props.value.toLowerCase())
const label = computed(
  () =>
    (props.kind === 'status'
      ? statusLabels[normalizedValue.value]
      : riskLabels[normalizedValue.value]) ?? props.value,
)
const accessibleLabel = computed(
  () => `${props.kind === 'status' ? '执行状态' : '风险等级'}：${label.value}`,
)

const tone = computed(() => {
  const value = normalizedValue.value
  if (
    [
      'uploading',
      'validating',
      'identifying',
      'extracting',
      'indexing',
      'scanning',
      'reporting',
    ].includes(value)
  ) {
    return 'running'
  }
  if (value === 'partial_succeeded') return 'partial'
  if (value === 'cancel_requested' || value === 'deleting') return 'queued'
  return value
})
</script>

<template>
  <span
    class="status-badge"
    :class="[`status-badge--${kind}`, `status-badge--${tone}`]"
    :aria-label="accessibleLabel"
  >
    <span class="status-badge__dot" aria-hidden="true" />
    {{ label }}
  </span>
</template>

<style scoped>
.status-badge {
  display: inline-flex;
  min-width: 70px;
  min-height: 26px;
  align-items: center;
  justify-content: flex-start;
  gap: 6px;
  padding: 3px 9px;
  border: 1px solid var(--line);
  border-radius: 6px;
  color: var(--ink-600);
  background: var(--surface-raised);
  font-size: 12px;
  font-weight: 500;
  line-height: 18px;
  white-space: nowrap;
}

.status-badge__dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--ink-400);
}

.status-badge--running,
.status-badge--queued {
  border-color: var(--primary-border);
  color: var(--primary);
  background: var(--primary-soft);
}

.status-badge--running .status-badge__dot,
.status-badge--queued .status-badge__dot {
  background: var(--primary);
}

.status-badge--succeeded,
.status-badge--none,
.status-badge--low {
  border-color: var(--success-border);
  color: var(--success);
  background: var(--success-soft);
}

.status-badge--succeeded .status-badge__dot,
.status-badge--none .status-badge__dot,
.status-badge--low .status-badge__dot {
  background: var(--success);
}

.status-badge--failed,
.status-badge--high,
.status-badge--critical {
  border-color: var(--danger-border);
  color: var(--danger);
  background: var(--danger-soft);
}

.status-badge--failed .status-badge__dot,
.status-badge--high .status-badge__dot,
.status-badge--critical .status-badge__dot {
  background: var(--danger);
}

.status-badge--medium,
.status-badge--partial {
  border-color: var(--warning-border);
  color: var(--warning);
  background: var(--warning-soft);
}

.status-badge--medium .status-badge__dot,
.status-badge--partial .status-badge__dot {
  background: var(--warning);
}
</style>
