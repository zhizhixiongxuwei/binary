import { describe, expect, it } from 'vitest'
import type { TaskEventMessage } from '@/api/types'
import { toTaskExecutionLogEntry } from './taskExecutionLog'

function event(analyzer: string, phase: string, type = 'decompile.progress'): TaskEventMessage {
  return { id: '1', event: type, data: { sequence: 1, type, stage: 'SCAN', progress: null,
    progress_indeterminate: true, severity: 'info', message: `${analyzer} original diagnostic`,
    created_at: '2026-11-05T01:00:00Z', payload: { analyzer, phase, current: 2, total: 3, elapsed_seconds: 5 } } }
}

describe('task log business presentation', () => {
  it.each(['ghidra', 'vineflower', 'cfr', 'jadx', 'pycdc', 'python-bytecode'])('relabels historical %s events without changing the record', (analyzer) => {
    for (const [phase, type] of [['starting', 'decompile.progress'], ['running', 'decompile.progress'],
      ['completed', 'decompile.completed'], ['failed', 'decompile.failed']]) {
      const source = event(analyzer, phase!, type)
      const original = JSON.stringify(source)
      const entry = toTaskExecutionLogEntry(source)
      expect(entry).not.toBeNull()
      expect(entry?.title).not.toMatch(/ghidra|vineflower|cfr|jadx|pycdc/i)
      expect(entry?.phase).toBe(phase)
      expect(JSON.stringify(source)).toBe(original)
    }
  })

  it('preserves partial completion and progress counters', () => {
    const message = event('ghidra', 'completed', 'decompile.completed')
    message.data.payload = { analyzer: 'ghidra', phase: 'completed', completeness: 'partial', current: 2, total: 3 }
    const entry = toTaskExecutionLogEntry(message)
    expect(entry?.title).toContain('部分完成')
    expect(entry?.title).toBe('原生二进制反编译部分完成')
    expect(entry?.detailLabel).toBe('函数 2 / 3')
  })

  it('reads the original image event IDs while displaying neutral labels', () => {
    for (const [phase, type] of [['scanning', 'trivy.progress'], ['completed', 'trivy.completed'], ['failed', 'trivy.failed']]) {
      const message = event('trivy', phase!, type)
      const entry = toTaskExecutionLogEntry(message)
      expect(entry?.title).toContain('镜像')
      expect(entry?.title).not.toMatch(/trivy/i)
      expect(entry?.workflow).toBe('image-scan')
      expect(message.data.type).toBe(type)
    }
  })
})
