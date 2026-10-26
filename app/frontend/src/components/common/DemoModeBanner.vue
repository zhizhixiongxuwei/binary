<script setup lang="ts">
import { MonitorDot } from 'lucide-vue-next'
</script>

<template>
  <div class="demo-mode-banner" role="status" aria-label="界面预览模式">
    <MonitorDot :size="15" aria-hidden="true" />
    <strong>界面预览</strong>
    <span>示例数据</span>
    <small>不连接后端，不执行真实检测</small>
  </div>
</template>

<style scoped>
.demo-mode-banner {
  position: fixed;
  inset: 0 0 auto;
  z-index: 100;
  display: flex;
  min-height: 34px;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 6px 14px;
  border-bottom: 1px solid var(--warning-border);
  color: var(--warning);
  background: var(--warning-soft);
  box-shadow: var(--shadow-sm);
  font-size: 12px;
}

.demo-mode-banner strong {
  font-size: 12px;
}

.demo-mode-banner span {
  padding-left: 8px;
  border-left: 1px solid var(--warning-border);
  font-weight: 600;
}

.demo-mode-banner small {
  color: var(--warning);
  font-size: 12px;
}

@media (max-width: 520px) {
  .demo-mode-banner {
    justify-content: flex-start;
  }

  .demo-mode-banner small {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
}
</style>
