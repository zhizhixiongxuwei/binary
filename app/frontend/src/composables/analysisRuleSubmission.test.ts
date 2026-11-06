import { effectScope } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { DecompileProject } from '@/api/types'
import { testRuleCatalog } from '@/components/tasks/analysis-rules/ruleSelection.testFixtures'

const requests = vi.hoisted(() => ({
  projects: vi.fn(), catalog: vi.fn(),
  cRuns: vi.fn(), javaRuns: vi.fn(), pythonRuns: vi.fn(),
  createC: vi.fn(), createJava: vi.fn(), createPython: vi.fn(),
}))
vi.mock('@/api/client', () => ({
  api: {
    listDecompileProjects: requests.projects, getAnalysisRuleCatalog: requests.catalog,
    listCAnalysisRuns: requests.cRuns, listJavaAnalysisRuns: requests.javaRuns, listPythonAnalysisRuns: requests.pythonRuns,
    createCAnalysisRun: requests.createC, createJavaAnalysisRun: requests.createJava, createPythonAnalysisRun: requests.createPython,
  },
  ApiError: class ApiError extends Error {},
}))

import { useCAnalysis } from './useCAnalysis'
import { useJavaAnalysis } from './useJavaAnalysis'
import { usePythonAnalysis } from './usePythonAnalysis'
import { useAnalysisRuleSelection } from './useAnalysisRuleSelection'

const scopes: ReturnType<typeof effectScope>[] = []
afterEach(() => { scopes.splice(0).forEach((scope) => scope.stop()); vi.resetAllMocks() })

const languages = [
  { language: 'c', source_kind: 'ghidra-pseudoc', factory: useCAnalysis, create: requests.createC },
  { language: 'java', source_kind: 'java', factory: useJavaAnalysis, create: requests.createJava },
  { language: 'python', source_kind: 'python', factory: usePythonAnalysis, create: requests.createPython },
] as const

async function setup(config: typeof languages[number]) {
  const project = { id: 'project-a', task_id: 'task-a', language: config.language,
    source_kind: config.source_kind, layout_version: 'project-v1', status: 'complete',
    manifest_available: true } as DecompileProject
  requests.projects.mockResolvedValue({ items: [project] })
  for (const request of [requests.cRuns, requests.javaRuns, requests.pythonRuns]) request.mockResolvedValue({ items: [] })
  requests.catalog.mockResolvedValue({ ...testRuleCatalog, language: config.language,
    engine: { name: `${config.language}-checker`, version: '1' } })
  const scope = effectScope()
  scopes.push(scope)
  const analysis = scope.run(() => config.factory({ taskId: 'task-a', userRole: 'operator' }))!
  await vi.waitFor(() => expect(analysis.state.value.status).toBe('ready'))
  const selection = scope.run(() => useAnalysisRuleSelection({
    taskId: 'task-a', projectId: () => analysis.selectedProjectId.value, language: config.language,
    canCreate: () => analysis.canCreate.value, createRun: analysis.createRun,
    operationError: () => analysis.operationError.value, clearOperationError: analysis.clearOperationError,
  }))!
  return { analysis, selection }
}

describe.each(languages)('$language analysis rule submission', (config) => {
  it('creates only after explicit non-empty rule confirmation and forwards the selected rule snapshot', async () => {
    const { selection } = await setup(config)
    config.create.mockResolvedValue({ id: 'run-1', task_id: 'task-a', source_project_id: 'project-a', status: 'queued' })
    await selection.openDialog()
    selection.close()
    expect(config.create).not.toHaveBeenCalled()
    await selection.openDialog()
    await selection.confirm({ catalog_version: 'catalog-1', rule_ids: [] })
    expect(config.create).not.toHaveBeenCalled()
    await selection.retry()
    await selection.confirm({ catalog_version: 'catalog-1', rule_ids: ['c-memory-release'] })
    expect(config.create).toHaveBeenCalledWith('task-a', 'project-a', expect.any(String), {
      catalog_version: 'catalog-1', rule_ids: ['c-memory-release'],
    })
    expect(selection.open.value).toBe(false)
  })

  it('reuses the key for an equivalent failed selection and changes it for different rules or catalog versions', async () => {
    const { analysis } = await setup(config)
    config.create.mockRejectedValue(new Error('connection interrupted'))
    await analysis.createRun({ catalog_version: 'catalog-1', rule_ids: [] })
    expect(config.create).not.toHaveBeenCalled()
    await analysis.createRun({ catalog_version: ' catalog-1 ', rule_ids: ['rule-b', 'rule-a', 'rule-b'] })
    const firstKey = config.create.mock.calls[0]?.[2]
    await analysis.createRun({ catalog_version: 'catalog-1', rule_ids: ['rule-a', 'rule-b'] })
    expect(config.create.mock.calls[1]?.[2]).toBe(firstKey)
    expect(config.create.mock.calls[1]?.[3]).toEqual({ catalog_version: 'catalog-1', rule_ids: ['rule-a', 'rule-b'] })
    await analysis.createRun({ catalog_version: 'catalog-1', rule_ids: ['rule-b'] })
    const changedRulesKey = config.create.mock.calls[2]?.[2]
    expect(changedRulesKey).not.toBe(firstKey)
    await analysis.createRun({ catalog_version: 'catalog-2', rule_ids: ['rule-b'] })
    expect(config.create.mock.calls[3]?.[2]).not.toBe(changedRulesKey)
  })
})
