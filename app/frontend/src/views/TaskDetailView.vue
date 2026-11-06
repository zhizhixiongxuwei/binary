<script setup lang="ts">
import { ArrowLeft } from 'lucide-vue-next'
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import PageHeader from '@/components/common/PageHeader.vue'
import TaskDetailPanel from '@/components/tasks/TaskDetailPanel.vue'

const route = useRoute()
const router = useRouter()
const taskId = computed(() => String(route.params.id))
const returnPath = computed(() => {
  const value = route.query.return_to
  // Only return to this application's task list, including its filter/expand state.
  return typeof value === 'string' && value.length <= 4096 &&
    /^\/tasks(?:\?[^\r\n#]*)?$/.test(value) ? value : '/tasks'
})

function returnToList(): void {
  void router.push(returnPath.value)
}
</script>

<template>
  <div class="page-view">
    <PageHeader title="任务详情" :eyebrow="`TASKS / ${taskId}`">
      <template #actions>
        <el-button :icon="ArrowLeft" @click="returnToList">返回列表</el-button>
      </template>
    </PageHeader>
    <TaskDetailPanel
      :task-id="taskId"
      @return-list="returnToList"
    />
  </div>
</template>
