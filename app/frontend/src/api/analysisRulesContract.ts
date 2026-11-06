import type { AnalysisRuleCatalog, AnalysisRuleDefinition, AnalysisRuleSelection, AnalysisRuleSelectionInput } from '@/api/types'

export class AnalysisRulesContractError extends Error {
  constructor(field: string) { super(`检测规则响应不符合接口契约：${field}`); this.name = 'AnalysisRulesContractError' }
}

function object(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new AnalysisRulesContractError(field)
  return value as Record<string, unknown>
}
function text(value: unknown, field: string, empty = false): string {
  if (typeof value !== 'string' || (!empty && !value.trim()) || value.length > 4096) throw new AnalysisRulesContractError(field)
  return value
}
function texts(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length > 10000) throw new AnalysisRulesContractError(field)
  return value.map((item) => text(item, field))
}
function language(value: unknown): AnalysisRuleCatalog['language'] {
  if (value !== 'c' && value !== 'java' && value !== 'python') throw new AnalysisRulesContractError('language')
  return value
}
function catalogVersion(value: unknown): string {
  const result = text(value, 'catalog_version')
  if (!/^sha256:[0-9a-f]{64}$/.test(result)) throw new AnalysisRulesContractError('catalog_version')
  return result
}
function ruleIDs(value: unknown): string[] {
  const ids = texts(value, 'rule_ids')
  if (!ids.length || ids.some((id) => !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id)) || new Set(ids).size !== ids.length) throw new AnalysisRulesContractError('rule_ids')
  return ids
}

export function parseAnalysisRuleCatalog(value: unknown): AnalysisRuleCatalog {
  const catalog = object(value, 'catalog')
  const lang = language(catalog.language)
  const engine = object(catalog.engine, 'engine')
  if (engine.name !== `${lang}-checker`) throw new AnalysisRulesContractError('engine.name')
  if (typeof catalog.available !== 'boolean' || !['fresh', 'stale', 'missing', 'conflict'].includes(String(catalog.freshness))) throw new AnalysisRulesContractError('availability')
  if (!Array.isArray(catalog.rules) || catalog.rules.length > 10000) throw new AnalysisRulesContractError('rules')
  const rules = catalog.rules.map((value): AnalysisRuleDefinition => {
    const rule = object(value, 'rule')
    const severity = text(rule.severity, 'severity').toUpperCase()
    if (!['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(severity) || typeof rule.default_enabled !== 'boolean' || rule.language !== lang) throw new AnalysisRulesContractError('rule metadata')
    return { id: ruleIDs([rule.id])[0]!, name: text(rule.name, 'name'), description: text(rule.description, 'description'),
      cwes: texts(rule.cwes, 'cwes'), severity, language: lang, default_enabled: rule.default_enabled,
      limitations: texts(rule.limitations, 'limitations') }
  })
  if (new Set(rules.map((rule) => rule.id)).size !== rules.length) throw new AnalysisRulesContractError('duplicate rule IDs')
  const version = text(catalog.catalogVersion, 'catalogVersion', !catalog.available)
  if (catalog.available && (catalog.freshness !== 'fresh' || !rules.length)) throw new AnalysisRulesContractError('availability')
  if (catalog.available) catalogVersion(version)
  const checked = catalog.last_checked_at === null ? null : text(catalog.last_checked_at, 'last_checked_at')
  if (checked !== null && !Number.isFinite(Date.parse(checked))) throw new AnalysisRulesContractError('last_checked_at')
  return { language: lang, engine: { name: String(engine.name), version: text(engine.version, 'engine.version', true) }, catalogVersion: version,
    rules, freshness: catalog.freshness as AnalysisRuleCatalog['freshness'], available: catalog.available,
    last_checked_at: checked, detail: text(catalog.detail, 'detail', true) }
}

export function parseAnalysisRuleSelection(value: unknown): AnalysisRuleSelection | null {
  if (value === null) return null
  const selection = object(value, 'selection')
  const ids = ruleIDs(selection.enabled_rule_ids)
  const count = selection.enabled_count
  const total = selection.total_rules
  if (!Number.isSafeInteger(total) || (total as number) < ids.length || (total as number) > 10000 || count !== ids.length) throw new AnalysisRulesContractError('selection counts')
  if ((selection.mode !== 'all' && selection.mode !== 'custom') || (selection.mode === 'all') !== (count === total)) throw new AnalysisRulesContractError('selection.mode')
  const lang = language(selection.language)
  if (selection.engine !== `${lang}-checker`) throw new AnalysisRulesContractError('selection.engine')
  return { catalog_version: catalogVersion(selection.catalog_version), enabled_rule_ids: ids, total_rules: total as number,
    enabled_count: ids.length, mode: selection.mode, engine: String(selection.engine), language: lang }
}

export function analysisRuleRequest(input?: AnalysisRuleSelectionInput): Record<string, unknown> {
  if (!input) return {}
  const ids = [...new Set(input.rule_ids)].sort()
  return { ruleIds: ruleIDs(ids), catalogVersion: catalogVersion(input.catalog_version) }
}
