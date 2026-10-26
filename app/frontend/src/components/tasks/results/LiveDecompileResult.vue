<script setup lang="ts">
import { watch } from 'vue'

import type { SourceNavigationTarget } from '@/api/types'
import type { TaskResultState } from '@/components/tasks/taskResultTypes'
import StatePanel from '@/components/common/StatePanel.vue'
import DecompileResultWorkspace from '@/components/tasks/results/DecompileResultWorkspace.vue'
import { useDecompileResults } from '@/composables/useDecompileResults'

const props = defineProps<{
  taskId: string
}>()

const emit = defineEmits<{
  stateChange: [state: TaskResultState]
  navigationChange: [target: SourceNavigationTarget]
}>()

const results = useDecompileResults({
  taskId: () => props.taskId,
})

watch(
  results.state,
  (state) => emit('stateChange', state),
  { immediate: true },
)

watch(
  [
    results.selectedResultId,
    results.selectedSourceFileId,
    results.selectedSourceFile,
    results.targetRange,
  ],
  ([projectId, sourceFileId, sourceFile, target]) => {
    if (!projectId || !sourceFileId || !sourceFile) return
    const matchingTarget =
      target?.projectId === projectId &&
      (!target.sourceFileId || target.sourceFileId === sourceFileId)
        ? target
        : undefined
    emit('navigationChange', {
      projectId,
      sourceFileId,
      path: sourceFile.logicalPath,
      startLine: matchingTarget?.startLine ?? 1,
      startColumn: matchingTarget?.startColumn ?? 1,
      endLine: matchingTarget?.endLine ?? 1,
      endColumn: matchingTarget?.endColumn ?? 2,
      reveal: Boolean(matchingTarget) && matchingTarget?.reveal !== false,
    })
  },
)

defineExpose({
  refresh: results.refresh,
  openResult: results.openResult,
  openSource: results.openSource,
})
</script>

<template>
  <StatePanel
    v-if="results.state.value.status !== 'ready'"
    :kind="
      results.state.value.status === 'loading'
        ? 'loading'
        : results.state.value.status === 'error'
          ? 'error'
          : 'empty'
    "
    :title="results.state.value.title ?? ''"
    :description="results.state.value.description ?? ''"
    :retryable="results.state.value.status === 'error'"
    @retry="results.refresh"
  />
  <DecompileResultWorkspace
    v-else
    :task-id="taskId"
    :items="results.items.value"
    :selected-id="results.selectedResultId.value"
    :source-files="results.sourceFiles.value"
    :selected-source-file-id="results.selectedSourceFileId.value"
    :source-file="results.sourceFile.value"
    :source="results.source.value"
    :source-files-loading="results.sourceFilesLoading.value"
    :source-files-error="results.sourceFilesError.value"
    :source-loading="results.sourceLoading.value"
    :source-error="results.sourceError.value"
    :target-range="results.targetRange.value"
    :has-more-results="results.hasMoreResults.value"
    :loading-more-results="results.loadingMore.value"
    @select="results.selectResult"
    @select-source-file="results.selectSourceFile"
    @open-source="results.openSource"
    @load-more-results="results.loadMoreResults"
  />
</template>
