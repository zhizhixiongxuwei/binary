import { ApiError, parseApiErrorBody } from '@/api/client'
import { fetchLiveResponse, requestLiveJSON } from '@/api/live/client'
import { isDemoMode } from '@/api/runtime'
import type {
  ExplanationInput, ExplanationRecord, ExplanationStreamEvent, LLMSettings,
  LLMStatus, SourceIdentity, UpdateLLMSettings,
} from '@/api/llmTypes'

const defaults: LLMSettings = {
  enabled: false, configured: false, provider: 'deepseek',
  baseUrl: 'https://api.deepseek.com', model: 'deepseek-flash',
  apiKeyMasked: '', maxInputChars: 60000, timeoutSeconds: 120, maxConcurrent: 2, maxOutputTokens: 4096,
}
let demoSettings = { ...defaults }
const demoHistory = new Map<string, ExplanationRecord[]>()

function path(identity: SourceIdentity): string {
  return `/tasks/${encodeURIComponent(identity.taskId)}/projects/${encodeURIComponent(identity.projectId)}` +
    `/files/${encodeURIComponent(identity.fileId)}/explanations`
}

export function llmErrorMessage(error: unknown): string {
  if (!(error instanceof Error)) return '模型服务暂不可用，请稍后重试'
  if (error.name === 'AbortError') return '已停止生成'
  if (error instanceof ApiError) {
    const code = error.code ?? ''
    if (code.includes('disabled')) return '大模型服务尚未启用，请联系管理员'
    if (code.includes('not_configured') || code.includes('missing_key')) return '请先在系统维护中配置模型接口和 API Key'
    if (code.includes('source_changed')) return '源码已更新，请重新加载文件后再解释'
    if (code === 'llm_invalid_settings') return '模型设置无效，请检查接口地址、模型名称和数值范围'
    if (code === 'llm_busy') return '模型请求较多，请稍后重试'
    if (code === 'llm_invalid_range') return '请选择源码中的有效行范围'
    if (code === 'llm_request_conflict') return '该解释请求已处理，请重新生成'
    if (code === 'llm_cancelled') return '已停止生成'
    if (code === 'llm_output_too_large' || code === 'llm_output_limit') return '模型输出达到上限，请缩小源码范围后重试'
    if (code.includes('too_large') || code.includes('input_limit') || error.status === 413) return '代码超过发送上限，请选择较小的代码片段'
    if (code.includes('timeout') || error.status === 504) return '模型响应超时，可以重试或缩小代码范围'
    if (code.includes('rate') || error.status === 429) return '模型服务限流或并发已满，请稍后重试'
    if (error.status === 401) return '登录或模型认证失败，请重新登录或检查 API Key'
    if (error.status === 403) return '当前账号无权执行该操作，或登录状态已更新'
    if (error.status === 404) return '源码文件或解释记录已不存在，请刷新后重试'
  }
  return error.message || '模型服务暂不可用，请稍后重试'
}

export async function getLLMStatus(): Promise<LLMStatus> {
  return isDemoMode ? { ...demoSettings } : requestLiveJSON<LLMStatus>('/llm/status')
}

export async function getLLMSettings(): Promise<LLMSettings> {
  return isDemoMode ? { ...demoSettings } : requestLiveJSON<LLMSettings>('/admin/llm/settings')
}

export async function saveLLMSettings(input: UpdateLLMSettings): Promise<LLMSettings> {
  if (isDemoMode) {
    const { apiKey, clearApiKey, ...publicValues } = input
    const configured = clearApiKey ? false : Boolean(apiKey) || demoSettings.configured
    demoSettings = { ...demoSettings, ...publicValues, configured, apiKeyMasked: configured ? '••••••••（预览）' : '' }
    return { ...demoSettings }
  }
  return requestLiveJSON<LLMSettings>('/admin/llm/settings', { method: 'PUT', body: JSON.stringify(input) })
}

export async function testLLMConnection(): Promise<{ message?: string; ok?: boolean }> {
  if (isDemoMode) return { ok: true, message: '界面预览：未连接外部模型服务' }
  return requestLiveJSON('/admin/llm/test', { method: 'POST' })
}

export async function listExplanations(identity: SourceIdentity): Promise<ExplanationRecord[]> {
  if (isDemoMode) return [...(demoHistory.get(path(identity)) ?? [])]
  return (await requestLiveJSON<{ items: ExplanationRecord[] }>(path(identity))).items
}

/** Parse SSE incrementally, including CRLF, split UTF-8 and multi-line data fields. */
export async function consumeExplanationStream(
  response: Response,
  onEvent: (event: ExplanationStreamEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  if (!response.body) throw new Error('模型服务没有返回流式内容')
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let terminal = false
  const abort = () => { void reader.cancel().catch(() => undefined) }
  const dispatch = (frame: string) => {
    if (terminal) return
    let type = 'message'
    const data: string[] = []
    for (const line of frame.split('\n')) {
      if (line.startsWith('event:')) type = line.slice(6).trim()
      else if (line.startsWith('data:')) data.push(line.slice(5).replace(/^ /, ''))
    }
    if (!data.length || !['meta', 'delta', 'done', 'error'].includes(type)) return
    let parsed: unknown
    try { parsed = JSON.parse(data.join('\n')) } catch { throw new Error('模型返回了无法解析的流式响应') }
    if (parsed === null || typeof parsed !== 'object') throw new Error('模型响应格式不正确')
    if (type === 'delta' && typeof (parsed as { text?: unknown }).text !== 'string') throw new Error('模型增量响应格式不正确')
    if (type === 'error' && (typeof (parsed as { code?: unknown }).code !== 'string' || typeof (parsed as { message?: unknown }).message !== 'string')) throw new Error('模型错误响应格式不正确')
    if ((type === 'meta' || type === 'done') && !isExplanationRecord(parsed)) throw new Error('模型解释记录格式不正确')
    onEvent({ type, data: parsed } as ExplanationStreamEvent)
    if (type === 'done' || type === 'error') terminal = true
  }
  signal?.addEventListener('abort', abort, { once: true })
  try {
    if (signal?.aborted) throw new DOMException('已停止生成', 'AbortError')
    while (true) {
      const { done, value } = await reader.read()
      if (signal?.aborted) throw new DOMException('已停止生成', 'AbortError')
      buffer += decoder.decode(value, { stream: !done })
      buffer = buffer.replace(/\r\n/g, '\n')
      let boundary: number
      while (!terminal && (boundary = buffer.indexOf('\n\n')) >= 0) {
        dispatch(buffer.slice(0, boundary))
        buffer = buffer.slice(boundary + 2)
      }
      if (done || terminal) break
      if (buffer.length > 2_000_000) throw new Error('模型单次响应过大')
    }
    if (!terminal && buffer.trim()) dispatch(buffer)
    if (!terminal) throw new Error('模型连接提前断开，请重试')
  } finally {
    signal?.removeEventListener('abort', abort)
    await reader.cancel().catch(() => undefined)
    reader.releaseLock()
  }
}

function isExplanationRecord(value: object): value is ExplanationRecord {
  const record = value as Partial<ExplanationRecord>
  return ['id', 'taskId', 'projectId', 'fileId', 'sourceSha256', 'provider', 'model', 'text', 'createdAt']
    .every((key) => typeof record[key as keyof ExplanationRecord] === 'string') &&
    (record.scope === 'file' || record.scope === 'selection') &&
    Number.isSafeInteger(record.startLine) && Number.isSafeInteger(record.endLine) &&
    (record.startLine ?? 0) >= 1 && (record.endLine ?? 0) >= (record.startLine ?? 1) &&
    ['completed', 'cancelled', 'failed', 'generating'].includes(record.status ?? '')
}

export async function streamExplanation(
  identity: SourceIdentity,
  input: ExplanationInput,
  onEvent: (event: ExplanationStreamEvent) => void,
  signal?: AbortSignal,
  preview?: { source: string; filename: string },
): Promise<void> {
  if (isDemoMode) {
    if (signal?.aborted) throw new DOMException('已停止生成', 'AbortError')
    if (!demoSettings.enabled || !demoSettings.configured) throw new ApiError('预览模型未配置', 409, { code: 'llm_not_configured' })
    const key = path(identity)
    const previous = (demoHistory.get(key) ?? []).find((item) => item.sourceSha256 === input.sourceSha256 && item.scope === input.scope && item.startLine === (input.startLine ?? 1) && item.endLine === (input.endLine ?? preview?.source.split('\n').length ?? 1) && item.status === 'completed')
    if (previous && !input.regenerate) { onEvent({ type: 'done', data: { ...previous, cacheHit: true } }); return }
    const record: ExplanationRecord = { ...identity, id: input.requestId, sourceSha256: input.sourceSha256 ?? '', scope: input.scope, startLine: input.startLine ?? 1, endLine: input.endLine ?? preview?.source.split('\n').length ?? 1, provider: 'demo', model: demoSettings.model, text: '', status: 'generating', createdAt: new Date().toISOString() }
    onEvent({ type: 'meta', data: { ...record } })
    const text = `功能概述\n这是界面预览的示例解释，未向任何外部服务发送代码。\n\n关键函数与参数\n阅读 ${preview?.filename ?? '当前文件'} 的 L${record.startLine}–L${record.endLine}，可结合函数签名确认输入与返回值。\n\n执行流程\n正式模式会由所配置的模型解释选中源码。\n\n推断说明\n反编译输出可能丢失原始命名、类型或注释，推断需要结合实际行为验证。`
    try {
      for (const part of text.match(/.{1,18}/gs) ?? []) {
        if (signal?.aborted) throw new DOMException('已停止生成', 'AbortError')
        await new Promise((resolve) => setTimeout(resolve, 35))
        if (signal?.aborted) throw new DOMException('已停止生成', 'AbortError')
        record.text += part
        onEvent({ type: 'delta', data: { text: part } })
      }
      record.status = 'completed'
      demoHistory.set(key, [record, ...(demoHistory.get(key) ?? [])].slice(0, 30))
      onEvent({ type: 'done', data: { ...record } })
    } catch (error) {
      record.status = 'cancelled'
      demoHistory.set(key, [record, ...(demoHistory.get(key) ?? [])].slice(0, 30))
      throw error
    }
    return
  }
  const response = await fetchLiveResponse(path(identity), {
    method: 'POST', headers: { Accept: 'text/event-stream' }, body: JSON.stringify(input), ...(signal ? { signal } : {}),
  })
  if (!response.ok) {
    let code = 'llm_request_failed'
    let message = '模型服务请求失败'
    try {
      const error = parseApiErrorBody(await response.json())
      code = error?.code ?? code
      message = error?.message ?? message
    } catch { /* A proxy may return a non-JSON response. */ }
    throw new ApiError(message, response.status, { code })
  }
  await consumeExplanationStream(response, onEvent, signal)
}
