<script setup lang="ts">
import { AlertTriangle, Inbox, LoaderCircle, RotateCw } from 'lucide-vue-next'
import { computed } from 'vue'

type StateKind = 'loading' | 'empty' | 'error'

const props = defineProps<{
  kind: StateKind
  title?: string
  description?: string
  retryable?: boolean
}>()

const emit = defineEmits<{
  retry: []
}>()

const icon = computed(() => {
  if (props.kind === 'loading') return LoaderCircle
  if (props.kind === 'error') return AlertTriangle
  return Inbox
})

const defaultTitle = computed(() => {
  if (props.kind === 'loading') return '正在读取数据'
  if (props.kind === 'error') return '数据读取失败'
  return '暂无数据'
})

const liveRole = computed(() => (props.kind === 'error' ? 'alert' : 'status'))
</script>

<template>
  <div
    class="state-panel"
    :class="`state-panel--${kind}`"
    :role="liveRole"
    aria-atomic="true"
    :aria-busy="kind === 'loading'"
  >
    <component
      :is="icon"
      class="state-panel__icon"
      :class="{ spin: kind === 'loading' }"
      :size="25"
      aria-hidden="true"
    />
    <strong class="state-panel__title">{{ title ?? defaultTitle }}</strong>
    <span v-if="description" class="state-panel__description">{{ description }}</span>
    <el-button
      v-if="kind === 'error' && retryable"
      plain
      size="small"
      :icon="RotateCw"
      @click="emit('retry')"
    >
      重试
    </el-button>
  </div>
</template>

<style scoped>
.state-panel {
  display: flex;
  min-height: 260px;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  gap: 12px;
  padding: 44px 24px;
  color: var(--ink-600);
  text-align: center;
}

.state-panel__icon {
  box-sizing: content-box;
  padding: 16px;
  border-radius: 16px;
  color: var(--primary);
  background: var(--primary-soft);
}

.state-panel--error .state-panel__icon {
  color: var(--danger);
  background: var(--danger-soft);
}

.state-panel__title {
  color: var(--ink-800);
  font-size: 15px;
  font-weight: 600;
  overflow-wrap: anywhere;
}

.state-panel__description {
  max-width: 480px;
  color: var(--ink-600);
  font-size: 13px;
  line-height: 1.7;
  overflow-wrap: anywhere;
}

.spin {
  animation: rotate 1s linear infinite;
}

@keyframes rotate {
  to {
    transform: rotate(360deg);
  }
}

@media (prefers-reduced-motion: reduce) {
  .spin {
    animation: none;
  }
}
</style>
