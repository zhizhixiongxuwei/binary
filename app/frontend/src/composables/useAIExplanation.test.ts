import { effectScope, nextTick, shallowRef, type EffectScope } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '@/api/client'
import * as llm from '@/api/llm'
import type { ExplanationInput, ExplanationRecord, ExplanationStreamEvent, SourceIdentity } from '@/api/llmTypes'
import type { UserRole } from '@/api/types'
import { explanationRange, useAIExplanation, type ExplanationSource } from '@/composables/useAIExplanation'

const sourceFixture: ExplanationSource = {
  taskId: 'task', projectId: 'project', fileId: 'file-a', sourceSha256: 'sha-a',
  source: 'int first() {\n  return 1;\n}', filename: 'first.c', lineCount: 3, loading: false, selection: null,
}
const status = { enabled: true, configured: true, provider: 'fixture', baseUrl: 'http://fixture', model: 'fixture', maxInputChars: 1000, timeoutSeconds: 10 }
const scopes: EffectScope[] = []
function record(identity: SourceIdentity, override: Partial<ExplanationRecord> = {}): ExplanationRecord {
  return { ...identity, id: 'explanation', scope: 'file', startLine: 1, endLine: 3, sourceSha256: 'sha-a', provider: 'fixture', model: 'fixture', status: 'generating', text: '', createdAt: '2026-10-26T01:00:00Z', ...override }
}
function setup(roleValue: UserRole = 'operator') {
  const source = shallowRef({ ...sourceFixture })
  const open = shallowRef(true)
  const role = shallowRef<UserRole | null>(roleValue)
  const scope = effectScope()
  scopes.push(scope)
  const model = scope.run(() => useAIExplanation({ source, open, role }))!
  return { source, open, role, model }
}
async function settled() { await Promise.resolve(); await Promise.resolve(); await nextTick() }

beforeEach(() => {
  vi.spyOn(llm, 'getLLMStatus').mockResolvedValue({ ...status })
  vi.spyOn(llm, 'listExplanations').mockResolvedValue([])
})
afterEach(() => { scopes.splice(0).forEach((scope) => scope.stop()); vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('AI explanation file binding', () => {
  it('defaults a new file to its whole source even before the old editor selection clears', async () => {
    const { source, model } = setup()
    source.value = { ...sourceFixture, fileId: 'file-b', source: Array.from({ length: 130 }, (_, index) => `line ${index + 1}`).join('\n'), lineCount: 130, selection: { startLine: 120, endLine: 120, text: 'line 120' } }
    model.scope.value = 'selection'
    await settled()
    expect(model.range.value.startLine).toBe(120)

    source.value = { ...sourceFixture, selection: source.value.selection }
    expect(model.scope.value).toBe('file')
    expect(model.range.value).toMatchObject({ startLine: 1, endLine: 3, valid: true })
    source.value = { ...source.value, selection: null }
    await settled()
    expect(model.scope.value).toBe('file')
    expect(model.blockedReason.value).toBe('')
  })

  it('returns to the whole file when an idle selection is cleared', async () => {
    const { source, model } = setup()
    source.value = { ...source.value, selection: { startLine: 2, endLine: 2, text: 'return' } }
    model.scope.value = 'selection'
    await settled()
    source.value = { ...source.value, selection: null }
    expect(model.scope.value).toBe('file')
    expect(model.range.value).toMatchObject({ startLine: 1, endLine: 3, valid: true })
  })

  it('cancels the previous file, ignores late events, and restores that file when navigating back', async () => {
    const requests: { identity: SourceIdentity; event: (event: ExplanationStreamEvent) => void; signal?: AbortSignal | undefined; resolve: () => void }[] = []
    vi.spyOn(llm, 'streamExplanation').mockImplementation((identity, _input, event, signal) => new Promise<void>((resolve, reject) => {
      requests.push({ identity, event, signal, resolve })
      signal?.addEventListener('abort', () => reject(new DOMException('stopped', 'AbortError')), { once: true })
    }))
    const { source, model } = setup()
    await settled()
    const first = model.generate()
    const a = requests[0]!
    a.event({ type: 'meta', data: record(a.identity) })
    a.event({ type: 'delta', data: { text: 'file A explanation' } })
    source.value = { ...sourceFixture, fileId: 'file-b', filename: 'second.c', sourceSha256: 'sha-b' }
    await first
    await settled()
    expect(a.signal?.aborted).toBe(true)
    expect(model.current.value.selected).toBeNull()
    const second = model.generate()
    const b = requests[1]!
    b.event({ type: 'meta', data: record(b.identity, { id: 'second', sourceSha256: 'sha-b' }) })
    a.event({ type: 'delta', data: { text: 'late A must not leak' } })
    b.event({ type: 'done', data: record(b.identity, { id: 'second', text: 'file B explanation', status: 'completed', sourceSha256: 'sha-b' }) })
    b.resolve()
    await second
    expect(model.current.value.selected?.text).toBe('file B explanation')
    source.value = { ...sourceFixture }
    await settled()
    expect(model.current.value.selected?.text).toBe('file A explanation')
    expect(model.current.value.selected?.status).toBe('cancelled')
  })

  it('keeps the full submitted line range frozen while selection changes', async () => {
    let complete: (() => void) | undefined
    let sent: ExplanationInput | undefined
    const stream = vi.spyOn(llm, 'streamExplanation').mockImplementation((_identity, input) => {
      sent = input
      return new Promise<void>((resolve) => { complete = resolve })
    })
    const { source, model } = setup()
    source.value = { ...source.value, selection: { startLine: 1, endLine: 2, text: 'partial selection' } }
    model.scope.value = 'selection'
    await settled()
    const pending = model.generate()
    expect(sent).toMatchObject({ scope: 'selection', startLine: 1, endLine: 2, sourceSha256: 'sha-a' })
    expect(model.range.value.text).toBe('int first() {\n  return 1;')
    source.value = { ...source.value, selection: { startLine: 3, endLine: 3, text: '}' } }
    expect(model.generating.value).toBe(true)
    expect(model.range.value.endLine).toBe(2)
    expect(stream).toHaveBeenCalledOnce()
    source.value = { ...source.value, selection: null }
    expect(model.scope.value).toBe('selection')
    expect(model.range.value.endLine).toBe(2)
    model.stop()
    expect(model.scope.value).toBe('file')
    complete!()
    await pending
  })

  it('keeps asynchronous history responses bound to their file', async () => {
    let completeA: ((records: ExplanationRecord[]) => void) | undefined
    vi.mocked(llm.listExplanations).mockImplementation((identity) => identity.fileId === 'file-a'
      ? new Promise((resolve) => { completeA = resolve })
      : Promise.resolve([record(identity, { id: 'b', status: 'completed', text: 'B' })]))
    const { source, model } = setup()
    source.value = { ...sourceFixture, fileId: 'file-b' }
    await settled()
    completeA!([record(sourceFixture, { status: 'completed', text: 'A' })])
    await settled()
    expect(model.current.value.selected?.text).toBe('B')
  })
})

describe('AI generation constraints', () => {
  it('generates a UUID on HTTP intranet browsers without crypto.randomUUID', async () => {
    vi.stubGlobal('crypto', { getRandomValues: (bytes: Uint8Array) => { bytes.fill(7); return bytes } })
    let sent: ExplanationInput | undefined
    vi.spyOn(llm, 'streamExplanation').mockImplementation(async (identity, input, event) => {
      sent = input
      event({ type: 'done', data: record(identity, { status: 'completed' }) })
    })
    const { model } = setup()
    await settled()
    await model.generate()
    expect(sent?.requestId).toMatch(/^[\da-f]{8}-[\da-f]{4}-4[\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/)
    expect(model.generating.value).toBe(false)
  })

  it('shows an actionable error without getting stuck when secure randomness is unavailable', async () => {
    vi.stubGlobal('crypto', {})
    const stream = vi.spyOn(llm, 'streamExplanation')
    const { model } = setup()
    await settled()
    await model.generate()
    expect(model.current.value.error).toContain('安全随机数')
    expect(model.generating.value).toBe(false)
    expect(stream).not.toHaveBeenCalled()
  })

  it('allows readers to load history but prevents generation', async () => {
    vi.mocked(llm.listExplanations).mockResolvedValue([record(sourceFixture, { text: 'existing', status: 'completed' })])
    const stream = vi.spyOn(llm, 'streamExplanation')
    const { model } = setup('reader')
    await settled()
    expect(model.current.value.selected?.text).toBe('existing')
    await model.generate()
    expect(model.blockedReason.value).toContain('只读账号')
    expect(stream).not.toHaveBeenCalled()
  })

  it.each(['administrator', 'operator'] as const)('allows %s to explicitly confirm generation', async (role) => {
    const stream = vi.spyOn(llm, 'streamExplanation').mockImplementation(async (identity, _input, event) => {
      event({ type: 'done', data: record(identity, { status: 'completed', text: 'result', cacheHit: true }) })
    })
    const { model } = setup(role)
    await settled()
    expect(stream).not.toHaveBeenCalled()
    await model.generate()
    expect(stream).toHaveBeenCalledOnce()
    expect(model.current.value.selected?.cacheHit).toBe(true)
  })

  it('blocks unconfigured services and oversized input before any provider request', async () => {
    const stream = vi.spyOn(llm, 'streamExplanation')
    vi.mocked(llm.getLLMStatus).mockResolvedValue({ ...status, configured: false })
    const { model } = setup()
    await settled()
    await model.generate()
    expect(model.blockedReason.value).toContain('尚未启用或配置')
    vi.mocked(llm.getLLMStatus).mockResolvedValue({ ...status, maxInputChars: 1 })
    await model.refreshStatus()
    await model.generate()
    expect(model.current.value.error).toContain('字符上限')
    expect(stream).not.toHaveBeenCalled()
  })

  it('shows source changes and streamed errors while retaining received text', async () => {
    const stream = vi.spyOn(llm, 'streamExplanation').mockRejectedValue(new ApiError('changed', 409, { code: 'llm_source_changed' }))
    const { model } = setup()
    await settled()
    await model.generate()
    expect(model.current.value.error).toContain('源码已更新')
    stream.mockImplementation(async (identity, _input, event) => {
      event({ type: 'meta', data: record(identity) })
      event({ type: 'delta', data: { text: 'partial result' } })
      event({ type: 'error', data: { code: 'llm_timeout', message: 'timeout' } })
    })
    await model.generate(true)
    expect(model.current.value.selected?.text).toBe('partial result')
    expect(model.current.value.error).toContain('超时')
    expect(model.current.value.phase).toBe('failed')
  })

  it('counts Unicode characters and sends whole selected lines rather than partial text', () => {
    const selected = explanationRange({ ...sourceFixture, source: 'a😀\n中\nz', selection: { startLine: 1, endLine: 2, text: '😀' } }, 'selection')
    expect(selected.text).toBe('a😀\n中')
    expect(selected.chars).toBe(4)
  })

  it.each(['file', 'selection'] as const)('normalizes CRLF preview and character count like the server for %s', (scope) => {
    const selected = explanationRange({ ...sourceFixture, source: 'alpha\r\n中😀\r\nlast\r\n', selection: { startLine: 2, endLine: 3, text: '😀' } }, scope)
    const expected = scope === 'file' ? 'alpha\n中😀\nlast\n' : '中😀\nlast'
    expect(selected.text).toBe(expected)
    expect(selected.chars).toBe(Array.from(expected).length)
    expect(selected.text).not.toContain('\r')
  })
})
