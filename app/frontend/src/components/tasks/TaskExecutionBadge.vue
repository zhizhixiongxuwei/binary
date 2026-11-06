<script setup lang="ts">
import type { ScanTask } from '@/api/types'
import StatusBadge from '@/components/common/StatusBadge.vue'
import { getTaskExecutionStatus } from '@/components/tasks/taskExecutionPresentation'

defineProps<{ task: ScanTask }>()
</script>

<template>
  <StatusBadge :value="getTaskExecutionStatus(task)" kind="status" />
</template>
