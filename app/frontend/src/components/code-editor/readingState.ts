import type { editor } from 'monaco-editor'

export interface CodeSelection {
  startLine: number
  endLine: number
  text: string
}

/** Only viewport metadata is cached; source text and live Monaco models are not. */
export class ViewStateCache<T> {
  private readonly states = new Map<string, T>()
  constructor(private readonly capacity = 80) {
    if (!Number.isInteger(capacity) || capacity < 1) throw new RangeError('Cache capacity must be positive')
  }
  get size() { return this.states.size }
  get(key: string): T | undefined {
    const value = this.states.get(key)
    if (value !== undefined) {
      this.states.delete(key)
      this.states.set(key, value)
    }
    return value
  }
  set(key: string, value: T): void {
    this.states.delete(key)
    this.states.set(key, value)
    while (this.states.size > this.capacity) {
      const oldest = this.states.keys().next().value
      if (oldest !== undefined) this.states.delete(oldest)
    }
  }
}

export interface SourceViewState {
  monaco?: editor.ICodeEditorViewState
  fallbackTop?: number
  fallbackLeft?: number
}
export const sourceViewStates = new ViewStateCache<SourceViewState>()

/** Deduplicate content refreshes within one navigation request, not later clicks. */
export function createTargetRevealGuard() {
  let appliedKey = ''
  return {
    reset() { appliedKey = '' },
    accept(key: string): boolean {
      if (key === appliedKey) return false
      appliedKey = key
      return true
    },
  }
}

export function clampDirectoryWidth(value: number, availableWidth: number): number {
  const maximum = Math.max(180, Math.min(520, availableWidth - 368))
  return Math.round(Math.min(maximum, Math.max(180, Number.isFinite(value) ? value : 280)))
}

export function formatCodeCopy(
  source: string,
  options: { filename?: string; includeFilename: boolean; includeLineNumbers: boolean; startLine?: number },
): string {
  const body = options.includeLineNumbers
    ? source.split('\n').map((line, index) => `${(options.startLine ?? 1) + index} | ${line}`).join('\n')
    : source
  return options.includeFilename && options.filename ? `${options.filename}\n${body}` : body
}
