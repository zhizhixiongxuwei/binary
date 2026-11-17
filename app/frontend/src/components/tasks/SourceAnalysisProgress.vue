<script setup lang="ts">
import { computed } from 'vue'
import type { TaskExecutionLogEntry } from './taskExecutionLog'
import TaskStageProgress from './TaskStageProgress.vue'

const props = defineProps<{
  runId: string
  status: string
  entries?: readonly TaskExecutionLogEntry[] | undefined
}>()
const runEntries = computed(() => (props.entries ?? []).filter((entry) =>
  entry.workflow === 'source-analysis' && entry.runId === props.runId,
))
const task = computed(() => ({
  status: props.status === 'cancelled' ? 'CANCELLED' as const : 'running' as const,
  current_stage: 'SCAN', progress: 0, progress_indeterminate: true, analysis_mode: 'source',
}))
</script>

<template>
  <TaskStageProgress
    v-if="['queued', 'running', 'cancel_requested'].includes(status)"
    :task="task"
    :entries="runEntries"
  />
</template>
