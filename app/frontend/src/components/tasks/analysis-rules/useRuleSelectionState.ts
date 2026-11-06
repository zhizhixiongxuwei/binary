import { computed, readonly, shallowRef, watch } from 'vue'

import type { AnalysisRuleCatalog, AnalysisRuleSelectionInput } from '@/api/types'
import { ruleMatches, validateRuleSelection } from './ruleSelection'

export function useRuleSelectionState(options: {
  open: () => boolean
  catalog: () => AnalysisRuleCatalog | null
  blocked: () => boolean
}) {
  const keyword = shallowRef('')
  const cwe = shallowRef('')
  const selectedIds = shallowRef<ReadonlySet<string>>(new Set())
  const rules = computed(() => options.catalog()?.rules ?? [])
  const categories = computed(() => [...new Set(rules.value.flatMap((rule) => rule.cwes))].sort())
  const filteredRules = computed(() => rules.value.filter((rule) => ruleMatches(rule, keyword.value, cwe.value)))
  const selectedCount = computed(() => rules.value.filter((rule) => selectedIds.value.has(rule.id)).length)

  function clearFilters(): void { keyword.value = ''; cwe.value = '' }
  function selectAll(): void { if (!options.blocked()) selectedIds.value = new Set(rules.value.map((rule) => rule.id)) }
  function clearSelection(): void { if (!options.blocked()) selectedIds.value = new Set() }
  function toggle(id: string): void {
    if (options.blocked() || !rules.value.some((rule) => rule.id === id)) return
    const next = new Set(selectedIds.value)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    selectedIds.value = next
  }
  function confirmation(): AnalysisRuleSelectionInput | null {
    if (!options.open() || options.blocked()) return null
    return validateRuleSelection(options.catalog(), {
      catalog_version: options.catalog()?.catalogVersion ?? '',
      rule_ids: [...selectedIds.value],
    })
  }
  const canConfirm = computed(() => confirmation() !== null)

  watch([
    options.open,
    () => JSON.stringify([options.catalog()?.language, options.catalog()?.catalogVersion, rules.value.map((rule) => rule.id)]),
  ], () => {
    clearFilters()
    selectedIds.value = new Set(options.open() ? rules.value.map((rule) => rule.id) : [])
  }, { immediate: true })

  return { keyword, cwe, selectedIds: readonly(selectedIds), rules, categories, filteredRules,
    selectedCount, canConfirm, clearFilters, selectAll, clearSelection, toggle, confirmation }
}
