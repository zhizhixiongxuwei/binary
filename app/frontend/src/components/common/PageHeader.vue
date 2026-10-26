<script setup lang="ts">
defineProps<{
  title: string
  description?: string
  eyebrow?: string
}>()
</script>

<template>
  <header class="page-header">
    <div class="page-header__copy">
      <h1 class="page-header__title">{{ title }}</h1>
      <p v-if="description" class="page-header__description">{{ description }}</p>
    </div>
    <div v-if="$slots.actions" class="page-header__actions">
      <slot name="actions" />
    </div>
  </header>
</template>

<style scoped>
.page-header {
  display: flex;
  min-height: 64px;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 24px;
}

.page-header__copy {
  min-width: 0;
}

.page-header__title {
  margin: 0;
  color: var(--ink-950);
  font-size: 26px;
  font-weight: 700;
  line-height: 1.35;
  overflow-wrap: anywhere;
}

.page-header__description {
  margin: 7px 0 0;
  color: var(--ink-600);
  font-size: 14px;
  line-height: 1.6;
}

.page-header__actions {
  display: flex;
  min-width: 0;
  flex: 0 0 auto;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 10px;
}

@media (max-width: 620px) {
  .page-header {
    min-height: 0;
    align-items: stretch;
    flex-direction: column;
    gap: 14px;
    margin-bottom: 18px;
  }

  .page-header__title {
    font-size: 23px;
  }

  .page-header__actions {
    width: 100%;
  }

  .page-header__actions :deep(.el-button) {
    flex: 1;
    margin-left: 0;
  }
}
</style>
