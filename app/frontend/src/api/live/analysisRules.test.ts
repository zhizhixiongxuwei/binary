import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, configureApiClient, resetApiClient } from '@/api/client'
import { createLiveApiClient } from './client'

const version = `sha256:${'a'.repeat(64)}`
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
afterEach(() => { resetApiClient(); vi.unstubAllGlobals() })

describe('live analysis rule transport', () => {
  it('reads the current project rule catalog and preserves unavailable evidence', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ language: 'java', engine: { name: 'java-checker', version: '' }, catalogVersion: '', rules: [], freshness: 'missing', available: false, last_checked_at: null, detail: '等待上报' }))
    vi.stubGlobal('fetch', fetchMock)
    configureApiClient(createLiveApiClient())
    expect(await api.getAnalysisRuleCatalog('task', 'project')).toMatchObject({ available: false, detail: '等待上报' })
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/tasks/task/projects/project/check-rules', expect.objectContaining({ credentials: 'include' }))
  })

  it.each(['c', 'java', 'python'] as const)('sends the selected %s rules through the API facade and maps the created run rather than an older run', async (language) => {
    const selection = { catalog_version: version, enabled_rule_ids: ['selected-rule'], enabled_count: 1, total_rules: 2, mode: 'custom', engine: `${language}-checker`, language }
    const run = { id: 'created-run', kind: `${language}_check`, status: 'queued', subjectType: 'source_project', subjectId: 'project', resultQuality: null,
      toolName: `${language}-checker`, toolVersion: 'engine-1', rulesetVersion: version, selection, errorCode: null, errorMessage: null,
      createdAt: '2026-11-04T01:00:00Z', startedAt: null, completedAt: null }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({ run: { id: 'created-run' } }))
      .mockResolvedValueOnce(json({
        task: { id: 'task', displayName: 'input', status: 'ready', createdAt: '2026-11-04T01:00:00Z', updatedAt: '2026-11-04T01:00:00Z' }, files: [],
        runs: [{ ...run, id: 'older-run', selection: null }, run],
        projects: [{ id: 'project', fileId: 'file', runId: 'decompile', sourceKind: language === 'c' ? 'native' : language === 'java' ? 'jvm' : 'pyc', language, resultQuality: 'source', fileCount: 1, sizeBytes: 100, createdAt: run.createdAt }],
      }))
      .mockResolvedValueOnce(json({ findings: [] }))
    vi.stubGlobal('fetch', fetchMock)
    configureApiClient(createLiveApiClient())
    const create = language === 'c' ? api.createCAnalysisRun : language === 'java' ? api.createJavaAnalysisRun : api.createPythonAnalysisRun
    const created = await create('task', 'project', 'intent-key', { rule_ids: ['selected-rule'], catalog_version: version })
    expect(created).toMatchObject({ id: 'created-run', selection })
    const [path, init] = fetchMock.mock.calls[0]!
    expect(path).toBe('/api/v1/tasks/task/projects/project/check')
    expect(new Headers(init.headers).get('Idempotency-Key')).toBe('intent-key')
    expect(JSON.parse(init.body)).toEqual({ ruleIds: ['selected-rule'], catalogVersion: version })
  })

  it('does not create a run for an explicit empty selection', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    await expect(createLiveApiClient().createCAnalysisRun('task', 'project', 'intent', { rule_ids: [], catalog_version: version })).rejects.toThrow('rule_ids')
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
