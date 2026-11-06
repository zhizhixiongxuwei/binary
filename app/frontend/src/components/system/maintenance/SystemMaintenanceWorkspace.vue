<script setup lang="ts">
import PreviewNotice from '@/components/common/PreviewNotice.vue'
import SystemMaintenanceLiveWorkspace from '@/components/system/maintenance/SystemMaintenanceLiveWorkspace.vue'
</script>

<template>
  <section class="maintenance-workspace" aria-label="系统维护工作台">
    <PreviewNotice />

    <SystemMaintenanceLiveWorkspace />
  </section>
</template>

<style scoped>
.maintenance-workspace {
  display: grid;
  min-width: 0;
  gap: 14px;
}

</style>
