import { effectScope, shallowRef } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { AnalysisRuleCatalog } from '@/api/types'
import { testRuleCatalog } from '@/components/tasks/analysis-rules/ruleSelection.testFixtures'

const catalogRequest = vi.hoisted(() => vi.fn())
vi.mock('@/api/client', () => ({ api: { getAnalysisRuleCatalog: catalogRequest }, ApiError: class ApiError extends Error {} }))

import { useAnalysisRuleSelection } from './useAnalysisRuleSelection'

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}
const scopes: ReturnType<typeof effectScope>[] = []
afterEach(() => { scopes.splice(0).forEach((scope) => scope.stop()); vi.resetAllMocks() })

function setup() {
  const scope = effectScope()
  scopes.push(scope)
  const taskId = shallowRef('task-a')
  const projectId = shallowRef('project-a')
  const operationError = shallowRef('')
  const createRun = vi.fn(async () => {})
  const selection = scope.run(() => useAnalysisRuleSelection({
    taskId, projectId, language: 'c', canCreate: true, createRun, operationError,
    clearOperationError: () => { operationError.value = '' },
  }))!
  return { scope, taskId, projectId, createRun, operationError, selection }
}

describe('analysis rule confirmation lifecycle', () => {
  it('loads configuration without creating a run and closes safely before a late response arrives', async () => {
    const { selection, createRun } = setup()
    const response = deferred<AnalysisRuleCatalog>()
    catalogRequest.mockReturnValueOnce(response.promise)
    const opening = selection.openDialog()
    selection.close()
    response.resolve(testRuleCatalog)
    await opening
    expect(selection.open.value).toBe(false)
    expect(selection.catalog.value).toBeNull()
    expect(createRun).not.toHaveBeenCalled()
  })

  it('rejects an empty selection and requires explicit confirmation before creating', async () => {
    const { selection, createRun } = setup()
    catalogRequest.mockResolvedValue(testRuleCatalog)
    await selection.openDialog()
    expect(createRun).not.toHaveBeenCalled()
    await selection.confirm({ catalog_version: 'catalog-1', rule_ids: [] })
    expect(createRun).not.toHaveBeenCalled()
    expect(selection.errorMessage.value).toContain('至少选择一条')
    await selection.retry()
    await selection.confirm({ catalog_version: 'catalog-1', rule_ids: ['c-memory-release', 'c-memory-release'] })
    expect(createRun).toHaveBeenCalledWith({ catalog_version: 'catalog-1', rule_ids: ['c-memory-release'] })
    expect(selection.open.value).toBe(false)
  })

  it('discards a directory response from the previous project and never submits its selection to the new project', async () => {
    const { selection, projectId, createRun } = setup()
    const response = deferred<AnalysisRuleCatalog>()
    catalogRequest.mockReturnValueOnce(response.promise)
    const opening = selection.openDialog()
    projectId.value = 'project-b'
    response.resolve(testRuleCatalog)
    await opening
    await selection.confirm({ catalog_version: 'catalog-1', rule_ids: ['c-memory-release'] })
    expect(selection.open.value).toBe(false)
    expect(selection.catalog.value).toBeNull()
    expect(createRun).not.toHaveBeenCalled()
  })

  it('rechecks the directory before submitting and blocks expired or changed catalogs', async () => {
    const { selection, createRun } = setup()
    catalogRequest.mockResolvedValueOnce(testRuleCatalog)
    await selection.openDialog()
    catalogRequest.mockResolvedValueOnce({ ...testRuleCatalog, freshness: 'stale', available: false })
    await selection.confirm({ catalog_version: 'catalog-1', rule_ids: ['c-memory-release'] })
    expect(createRun).not.toHaveBeenCalled()
    expect(selection.errorMessage.value).toContain('过期')
    catalogRequest.mockResolvedValueOnce(testRuleCatalog)
    await selection.retry()
    catalogRequest.mockResolvedValueOnce({ ...testRuleCatalog, catalogVersion: 'catalog-2' })
    await selection.confirm({ catalog_version: 'catalog-1', rule_ids: ['c-memory-release'] })
    expect(createRun).not.toHaveBeenCalled()
    expect(selection.errorMessage.value).toContain('已更新')
    expect(selection.open.value).toBe(true)
  })

  it('blocks creation if the task changes while confirmation is rechecking the directory', async () => {
    const { selection, taskId, createRun } = setup()
    catalogRequest.mockResolvedValueOnce(testRuleCatalog)
    await selection.openDialog()
    const response = deferred<AnalysisRuleCatalog>()
    catalogRequest.mockReturnValueOnce(response.promise)
    const confirm = selection.confirm({ catalog_version: 'catalog-1', rule_ids: ['c-memory-release'] })
    taskId.value = 'task-b'
    response.resolve(testRuleCatalog)
    await confirm
    expect(createRun).not.toHaveBeenCalled()
    expect(selection.open.value).toBe(false)
  })

  it('preserves failed creation feedback without reporting success and permits an explicit retry', async () => {
    const { selection, operationError, createRun } = setup()
    catalogRequest.mockResolvedValue(testRuleCatalog)
    await selection.openDialog()
    createRun.mockImplementationOnce(async () => { operationError.value = '创建失败：连接中断' })
    const input = { catalog_version: 'catalog-1', rule_ids: ['c-memory-release'] }
    await selection.confirm(input)
    expect(selection.open.value).toBe(true)
    expect(selection.errorMessage.value).toContain('连接中断')
    expect(selection.submitting.value).toBe(false)
    await selection.retry()
    await selection.confirm(input)
    expect(createRun).toHaveBeenCalledTimes(2)
    expect(selection.open.value).toBe(false)
  })
})
