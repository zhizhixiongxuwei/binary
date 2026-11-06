import type { AnalysisRuleCatalog, AnalysisRuleDefinition, AnalysisRuleSelectionInput } from '@/api/types'

export function normalizeRuleSelection(input: AnalysisRuleSelectionInput): AnalysisRuleSelectionInput | null {
  const catalog_version = input.catalog_version.trim()
  const rule_ids = [...new Set(input.rule_ids.map((id) => id.trim()).filter(Boolean))].sort()
  return catalog_version && rule_ids.length ? { catalog_version, rule_ids } : null
}

export function validateRuleSelection(catalog: AnalysisRuleCatalog | null, input: AnalysisRuleSelectionInput): AnalysisRuleSelectionInput | null {
  const selection = normalizeRuleSelection(input)
  if (!catalog || !catalog.available || catalog.freshness !== 'fresh' || !selection
    || selection.catalog_version !== catalog.catalogVersion) return null
  const known = new Set(catalog.rules.map((rule) => rule.id))
  return selection.rule_ids.every((id) => known.has(id)) ? selection : null
}

export function ruleMatches(rule: AnalysisRuleDefinition, keyword: string, cwe: string): boolean {
  if (cwe && !rule.cwes.includes(cwe)) return false
  const terms = keyword.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean)
  const content = [rule.id, rule.name, rule.description, ...rule.cwes, rule.severity, ...rule.limitations].join(' ').toLocaleLowerCase()
  return terms.every((term) => content.includes(term))
}

export function ruleSeverityLabel(severity: string): string {
  const labels: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' }
  return `${labels[severity.toLowerCase()] ?? '未分类'} · ${severity.toUpperCase()}`
}
