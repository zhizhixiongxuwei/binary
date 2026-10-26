export interface LLMStatus {
  enabled: boolean
  configured: boolean
  provider: string
  baseUrl: string
  model: string
  maxInputChars: number
  timeoutSeconds: number
}

export interface LLMSettings extends LLMStatus {
  apiKeyMasked: string
  maxConcurrent: number
  maxOutputTokens?: number
}

export interface UpdateLLMSettings {
  enabled: boolean
  provider: string
  baseUrl: string
  model: string
  maxInputChars: number
  timeoutSeconds: number
  maxConcurrent: number
  maxOutputTokens?: number
  apiKey?: string
  clearApiKey?: boolean
}

export interface SourceIdentity {
  taskId: string
  projectId: string
  fileId: string
}

export interface SourceSelection {
  startLine: number
  endLine: number
  text: string
}

export interface ExplanationInput {
  scope: 'file' | 'selection'
  startLine?: number
  endLine?: number
  requestId: string
  regenerate?: boolean
  sourceSha256?: string
}

export interface ExplanationRecord extends SourceIdentity {
  id: string
  sourceSha256: string
  scope: 'file' | 'selection'
  startLine: number
  endLine: number
  provider: string
  model: string
  text: string
  status: 'completed' | 'cancelled' | 'failed' | 'generating'
  createdAt: string
  stale?: boolean
  cacheHit?: boolean
}

export type ExplanationStreamEvent =
  | { type: 'meta'; data: ExplanationRecord }
  | { type: 'delta'; data: { text: string } }
  | { type: 'done'; data: ExplanationRecord }
  | { type: 'error'; data: { code: string; message: string } }
