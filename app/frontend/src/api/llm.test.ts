import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '@/api/client'
import { consumeExplanationStream, llmErrorMessage } from '@/api/llm'
import type { ExplanationRecord, ExplanationStreamEvent } from '@/api/llmTypes'

const record: ExplanationRecord = {
  id: 'record', taskId: 'task', projectId: 'project', fileId: 'file', sourceSha256: 'sha',
  scope: 'file', startLine: 1, endLine: 3, provider: 'fixture', model: 'fixture',
  text: '中文解释', status: 'completed', createdAt: '2026-10-26T01:00:00Z',
}
function frame(type: string, data: unknown): string { return `event: ${type}\r\ndata: ${JSON.stringify(data)}\r\n\r\n` }
function response(text: string, chunkSize = 1): Response {
  const bytes = new TextEncoder().encode(text)
  return new Response(new ReadableStream<Uint8Array>({ start(controller) {
    for (let i = 0; i < bytes.length; i += chunkSize) controller.enqueue(bytes.slice(i, i + chunkSize))
    controller.close()
  } }))
}

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); vi.doUnmock('@/api/runtime'); vi.resetModules() })

describe('explanation SSE parser', () => {
  it('decodes split UTF-8 and CRLF without losing text, including multi-line JSON data', async () => {
    const events: ExplanationStreamEvent[] = []
    await consumeExplanationStream(response(
      ': heartbeat\r\n\r\n' + frame('meta', { ...record, status: 'generating', text: '' }) +
      'event: delta\r\ndata: {\r\ndata: "text":"中文😀"\r\ndata: }\r\n\r\n' + frame('done', record),
    ), (event) => events.push(event))
    expect(events.map((event) => event.type)).toEqual(['meta', 'delta', 'done'])
    expect(events[1]?.data).toEqual({ text: '中文😀' })
  })

  it('rejects a connection that ends before done or error', async () => {
    await expect(consumeExplanationStream(response(frame('delta', { text: 'partial' })), vi.fn())).rejects.toThrow('提前断开')
  })

  it.each(['done', 'error'] as const)('stops at %s without waiting for the server to close the stream', async (type) => {
    const cancelled = vi.fn()
    const events: ExplanationStreamEvent[] = []
    const data = type === 'done' ? record : { code: 'llm_timeout', message: 'timeout' }
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new TextEncoder().encode(frame(type, data) + frame('delta', { text: 'must be ignored' }))) },
      cancel: cancelled,
    })
    await consumeExplanationStream(new Response(stream), (event) => events.push(event))
    expect(events).toEqual([{ type, data }])
    expect(cancelled).toHaveBeenCalledOnce()
  })

  it('cancels a pending read immediately when stopped', async () => {
    const abort = new AbortController()
    const cancelled = vi.fn()
    const pending = consumeExplanationStream(new Response(new ReadableStream({ cancel: cancelled })), vi.fn(), abort.signal)
    abort.abort()
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    expect(cancelled).toHaveBeenCalledOnce()
  })

  it.each([
    'event: delta\ndata: not-json\n\n',
    frame('delta', { text: 4 }),
    frame('done', { id: 'incomplete' }),
    frame('error', { message: 'missing code' }),
  ])('rejects malformed protocol payloads', async (text) => {
    await expect(consumeExplanationStream(response(text), vi.fn())).rejects.toThrow()
  })

  it('maps source revision and size failures into actionable text', () => {
    expect(llmErrorMessage(new ApiError('failure', 409, { code: 'llm_source_changed' }))).toContain('源码已更新')
    expect(llmErrorMessage(new ApiError('failure', 413, { code: 'llm_input_too_large' }))).toContain('较小的代码片段')
    expect(llmErrorMessage(new ApiError('failure', 502, { code: 'llm_output_limit' }))).toContain('模型输出达到上限')
  })
})

describe('offline preview model settings', () => {
  it('preserves a key on blank updates, clears it explicitly and never contacts a provider', async () => {
    vi.doMock('@/api/runtime', () => ({ isDemoMode: true }))
    const demo = await import('@/api/llm')
    const fetchMock = vi.fn().mockRejectedValue(new Error('Preview must stay offline'))
    vi.stubGlobal('fetch', fetchMock)
    const settings = { enabled: true, provider: 'fixture', baseUrl: 'http://localhost:9999', model: 'fixture', maxInputChars: 2000, timeoutSeconds: 10, maxConcurrent: 1 }
    const configured = await demo.saveLLMSettings({ ...settings, apiKey: 'test-only-secret' })
    expect(configured.configured).toBe(true)
    expect(JSON.stringify(configured)).not.toContain('test-only-secret')
    expect((await demo.saveLLMSettings({ ...settings, apiKey: '' })).configured).toBe(true)
    expect((await demo.saveLLMSettings(settings)).configured).toBe(true)
    expect(await demo.testLLMConnection()).toMatchObject({ ok: true })

    vi.useFakeTimers()
    const events: ExplanationStreamEvent[] = []
    const generated = demo.streamExplanation(record, { scope: 'file', requestId: 'preview-request', sourceSha256: 'sha' }, (event) => events.push(event), undefined, { source: 'line1\nline2', filename: 'test.c' })
    await vi.runAllTimersAsync()
    await generated
    expect(events[events.length - 1]?.type).toBe('done')
    expect((await demo.listExplanations(record))[0]?.text).toContain('未向任何外部服务发送代码')
    expect((await demo.saveLLMSettings({ ...settings, apiKey: '', clearApiKey: true })).configured).toBe(false)
    await expect(demo.streamExplanation(record, { scope: 'file', requestId: 'no-key' }, vi.fn())).rejects.toMatchObject({ code: 'llm_not_configured' })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
