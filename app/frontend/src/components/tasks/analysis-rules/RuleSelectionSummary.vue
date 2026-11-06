<script setup lang="ts">
import type { AnalysisRuleSelection } from '@/api/types'
defineProps<{ selection: AnalysisRuleSelection | null | undefined }>()
</script>

<template>
  <section class="rule-selection-summary" aria-label="本次检测规则范围">
    <template v-if="selection">
      <strong>本次启用 {{ selection.enabled_count }}/{{ selection.total_rules }} 条规则</strong>
      <span v-if="selection.mode === 'custom'">其余 {{ selection.total_rules - selection.enabled_count }} 条规则本次未检测。</span>
      <span v-else>已选择当前规则目录的全部规则。</span>
      <details>
        <summary>查看规则与版本</summary>
        <p>规则版本 <code>{{ selection.catalog_version }}</code></p>
        <ul><li v-for="id in selection.enabled_rule_ids" :key="id"><code>{{ id }}</code></li></ul>
      </details>
    </template>
    <span v-else>历史检测未记录启用规则，无法确认当时的规则覆盖范围。</span>
  </section>
</template>

<style scoped>
.rule-selection-summary { display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px 14px; padding: 12px 16px; margin-bottom: 12px; border: 1px solid var(--line); border-radius: var(--radius-sm); color: var(--ink-600); background: var(--surface-raised); font-size: 12px; line-height: 1.7; }
.rule-selection-summary strong { color: var(--ink-800); }
.rule-selection-summary details { flex-basis: 100%; }
.rule-selection-summary summary { color: var(--primary); cursor: pointer; }
.rule-selection-summary code { overflow-wrap: anywhere; }
.rule-selection-summary ul { display: flex; flex-wrap: wrap; gap: 6px 22px; padding-left: 18px; margin: 8px 0 0; }
</style>
