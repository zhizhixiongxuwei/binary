import { createSSRApp, effectScope, h, nextTick, shallowRef, type Component } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { afterEach, describe, expect, it } from 'vitest'

import type { AnalysisRuleCatalog } from '@/api/types'
import RuleSelectionDialog from './RuleSelectionDialog.vue'
import { testRuleCatalog } from './ruleSelection.testFixtures'
import { useRuleSelectionState } from './useRuleSelectionState'

const scopes: ReturnType<typeof effectScope>[] = []
afterEach(() => scopes.splice(0).forEach((scope) => scope.stop()))

async function renderDialog(overrides: Record<string, unknown> = {}): Promise<string> {
  const app = createSSRApp({ render: () => h(RuleSelectionDialog, { open: true, catalog: testRuleCatalog, ...overrides }) })
  app.component('el-dialog', { props: ['modelValue'], setup: (props, { slots }) => () => props.modelValue ? h('section', [slots.header?.(), slots.default?.(), slots.footer?.()]) : null } as Component)
  app.component('el-button', { props: { disabled: Boolean, loading: Boolean }, setup: (props, { slots, attrs }) => () => h('button', { ...attrs, disabled: props.disabled }, slots.default?.()) } as Component)
  return renderToString(app)
}

describe('one-run rule selection dialog', () => {
  it('shows engine identity and Chinese rule details with all rules selected by default', async () => {
    const html = await renderDialog()
    expect(html).toContain('C/C++ 源码检测引擎')
    expect(html).toContain('未提供')
    expect(html).toContain('无效内存释放')
    expect(html).toContain('c-memory-release')
    expect(html).toContain('CWE-590')
    expect(html).toContain('高危 · HIGH')
    expect(html).toContain('中危 · MEDIUM')
    expect(html).toContain('仅依据当前函数中的指针来源判断。')
    expect(html).toContain('已选 2 / 2 条')
    expect(html.match(/type="checkbox"[^>]*checked/g)).toHaveLength(2)
    expect(html.match(/<button[^>]*data-confirm="analysis-rules"[^>]*>/)?.[0]).not.toContain('disabled')
  })

  it.each([
    { loading: true }, { pending: true }, { errorMessage: '目录加载失败' }, { stale: true },
    { catalog: { ...testRuleCatalog, freshness: 'stale' } },
    { catalog: { ...testRuleCatalog, available: false, freshness: 'missing' } },
  ])('blocks starting for an unavailable or unverified directory (%j)', async (props) => {
    const html = await renderDialog(props)
    expect(html.match(/<button[^>]*data-confirm="analysis-rules"[^>]*>/)?.[0]).toContain('disabled')
  })

  it('keeps selection independent of filters, blocks an empty selection and resets the next opening', async () => {
    const scope = effectScope()
    scopes.push(scope)
    const open = shallowRef(true)
    const catalog = shallowRef<AnalysisRuleCatalog | null>(testRuleCatalog)
    const state = scope.run(() => useRuleSelectionState({ open: () => open.value, catalog: () => catalog.value, blocked: () => false }))!
    state.keyword.value = '释放 CWE-590'
    expect(state.filteredRules.value.map((rule) => rule.id)).toEqual(['c-memory-release'])
    expect(state.selectedCount.value).toBe(2)
    state.clearSelection()
    expect(state.confirmation()).toBeNull()
    state.toggle('c-memory-release')
    expect(state.confirmation()).toEqual({ catalog_version: 'catalog-1', rule_ids: ['c-memory-release'] })
    open.value = false
    await nextTick()
    open.value = true
    await nextTick()
    expect(state.selectedCount.value).toBe(2)
    expect(state.keyword.value).toBe('')
    catalog.value = { ...testRuleCatalog, catalogVersion: 'catalog-2', rules: [testRuleCatalog.rules[1]!] }
    await nextTick()
    expect(state.confirmation()).toEqual({ catalog_version: 'catalog-2', rule_ids: ['c-bounds'] })
  })
})
