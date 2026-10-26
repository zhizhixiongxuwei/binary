<script setup lang="ts">
import { LockKeyhole } from 'lucide-vue-next'

import type { SampleRetentionSnapshot } from '@/utils/sampleRetention'

defineProps<{
  retention: SampleRetentionSnapshot
  historyLabel: string
}>()
</script>

<template>
  <div
    class="sample-retention-notice"
    :class="`sample-retention-notice--${retention.status}`"
    role="note"
    :title="retention.actionReason"
  >
    <LockKeyhole :size="15" aria-hidden="true" />
    <span>
      <strong>{{ retention.statusLabel }}</strong>
      {{ retention.actionReason }} 当前仍可查看已保存的{{ historyLabel }}。
    </span>
  </div>
</template>

<style scoped>
.sample-retention-notice {
  display: flex;
  min-width: 0;
  min-height: 38px;
  align-items: center;
  gap: 8px;
  padding: 8px 14px;
  border-bottom: 1px solid var(--warning-border);
  color: var(--warning);
  background: var(--warning-soft);
  font-size: 12px;
  line-height: 1.5;
}

.sample-retention-notice svg {
  flex: 0 0 auto;
}

.sample-retention-notice span {
  min-width: 0;
}

.sample-retention-notice strong {
  margin-right: 5px;
  color: var(--warning);
}

.sample-retention-notice--deleted {
  border-color: var(--danger-border);
  color: var(--danger);
  background: var(--danger-soft);
}

.sample-retention-notice--deleted strong {
  color: var(--danger);
}

.sample-retention-notice--unavailable {
  border-color: var(--line-strong);
  color: var(--ink-600);
  background: var(--surface-muted);
}

.sample-retention-notice--unavailable strong {
  color: var(--ink-800);
}
</style>
