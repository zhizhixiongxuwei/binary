<script setup lang="ts">
defineProps<{
  title: string
  description?: string
  eyebrow?: string
}>()
</script>

<template>
  <Teleport v-if="$slots.actions" defer to="#page-header-actions">
    <div class="page-header__actions" role="group" :aria-label="`${title}操作`">
      <slot name="actions" />
    </div>
  </Teleport>
  <p v-if="description" class="page-header__description">{{ description }}</p>
</template>

<style scoped>
.page-header__description {
  margin: 0 0 20px;
  color: var(--ink-600);
  font-size: 13px;
  line-height: 1.6;
}

.page-header__actions {
  display: flex;
  min-width: 0;
  align-items: center;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
}

.page-header__actions :deep(.el-button + .el-button) {
  margin-left: 0;
}

@media (max-width: 620px) {
  .page-header__actions :deep(.el-button) {
    min-height: 32px;
    padding: 6px 10px;
    font-size: 12px;
  }
}
</style>
