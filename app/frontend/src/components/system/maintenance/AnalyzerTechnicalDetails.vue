<script setup lang="ts">
import type { SystemStatus } from '@/api/types'
defineProps<{ analyzer: NonNullable<SystemStatus['analyzers']>[number] }>()
</script>

<template>
  <details class="technical-diagnostics">
    <summary>技术诊断（原始组件信息）</summary>
    <dl>
      <div><dt>组件标识</dt><dd>{{ analyzer.name }}</dd></div>
      <div><dt>探测版本</dt><dd>{{ analyzer.version || '未知' }}</dd></div>
      <div><dt>配置版本</dt><dd>{{ analyzer.expected_version || '未配置' }}</dd></div>
      <div><dt>运行环境</dt><dd>{{ analyzer.runtime_name || '未知' }} {{ analyzer.runtime_version }}</dd></div>
    </dl>
    <p>{{ analyzer.detail || '尚无原始探测详情。' }}</p>
  </details>
</template>

<style scoped>
.technical-diagnostics { min-width: 0; color: var(--ink-500); font-size: 11px; line-height: 1.7; }
summary { cursor: pointer; }
dl { display: grid; gap: 5px; margin: 8px 0; }
dt { font-weight: 600; }
dd { margin: 0; overflow-wrap: anywhere; }
p { margin: 6px 0; overflow-wrap: anywhere; }
</style>
