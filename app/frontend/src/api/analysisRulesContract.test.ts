import { describe, expect, it } from 'vitest'
import { analysisRuleRequest, parseAnalysisRuleCatalog, parseAnalysisRuleSelection } from './analysisRulesContract'

const version = `sha256:${'a'.repeat(64)}`
const rule = { id: 'cwe-590-invalid-free', name: '释放非堆内存', description: '检查栈内存等无效释放。', cwes: ['CWE-590'], severity: 'high', language: 'c', default_enabled: true, limitations: ['面向反编译伪 C。'] }
const catalog = { language: 'c', engine: { name: 'c-checker', version: '1.0' }, catalogVersion: version, rules: [rule], freshness: 'fresh', available: true, last_checked_at: '2026-11-04T01:00:00Z', detail: '' }
const selection = { catalog_version: version, enabled_rule_ids: [rule.id], total_rules: 2, enabled_count: 1, mode: 'custom', engine: 'c-checker', language: 'c' }

describe('analysis rule contracts', () => {
  it('keeps readable rule metadata and allows a missing catalog without pretending it is ready', () => {
    expect(parseAnalysisRuleCatalog(catalog).rules[0]).toMatchObject({ name: '释放非堆内存', severity: 'HIGH', cwes: ['CWE-590'] })
    expect(parseAnalysisRuleCatalog({ ...catalog, available: false, freshness: 'missing', rules: [], catalogVersion: '', last_checked_at: null })).toMatchObject({ available: false, rules: [] })
  })
  it('rejects duplicate rules, cross-language data and inconsistent availability', () => {
    expect(() => parseAnalysisRuleCatalog({ ...catalog, rules: [rule, rule] })).toThrow('duplicate')
    expect(() => parseAnalysisRuleCatalog({ ...catalog, rules: [{ ...rule, language: 'java' }] })).toThrow('metadata')
    expect(() => parseAnalysisRuleCatalog({ ...catalog, freshness: 'stale' })).toThrow('availability')
    expect(() => parseAnalysisRuleCatalog({ ...catalog, catalogVersion: 'checker-v1' })).toThrow('catalog_version')
  })
  it('distinguishes historical unknown coverage from a frozen custom selection', () => {
    expect(parseAnalysisRuleSelection(null)).toBeNull()
    expect(parseAnalysisRuleSelection(selection)).toEqual(selection)
    expect(() => parseAnalysisRuleSelection({ ...selection, enabled_count: 2 })).toThrow('counts')
    expect(() => parseAnalysisRuleSelection({ ...selection, mode: 'all' })).toThrow('mode')
    expect(() => parseAnalysisRuleSelection({ ...selection, enabled_rule_ids: [] })).toThrow('rule_ids')
  })
  it('normalizes requests without turning an empty selection into all rules', () => {
    expect(analysisRuleRequest()).toEqual({})
    expect(analysisRuleRequest({ rule_ids: ['rule-b', 'rule-a', 'rule-b'], catalog_version: version })).toEqual({ ruleIds: ['rule-a', 'rule-b'], catalogVersion: version })
    expect(() => analysisRuleRequest({ rule_ids: [], catalog_version: version })).toThrow('rule_ids')
  })
})
