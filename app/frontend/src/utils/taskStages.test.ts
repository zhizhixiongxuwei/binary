import { describe, expect, it } from 'vitest'
import type { TaskEventMessage } from '@/api/types'
import { toTaskExecutionLogEntry, type TaskExecutionLogEntry } from '@/components/tasks/taskExecutionLog'
import { deriveTaskStageProgress } from './taskStages'

const task = { status: 'running' as const, current_stage: 'SCAN', progress: 0, progress_indeterminate: true, input_type: 'jar', analysis_mode: 'binary' }
function entry(type: string, phase: string, current: number, total: number, run = 'run-1', sequence = 1): TaskExecutionLogEntry {
  const message: TaskEventMessage = {
    id: String(sequence), event: type,
    data: { sequence, type, stage: 'SCAN', progress: null, progress_indeterminate: total === 0,
      severity: 'info', message: 'Internal diagnostic must not be displayed', created_at: '2026-11-16T01:00:00Z',
      payload: { analyzer: type.startsWith('decompile') ? 'vineflower' : 'java-checker', phase, current, total, unit: 'files', elapsed_seconds: 15, run_id: run } },
  }
  return toTaskExecutionLogEntry(message)!
}

describe('analyzer stage progress', () => {
  it('uses source file counters and follows a source run after decompilation', () => {
    const model = deriveTaskStageProgress(task, [entry('decompile.completed', 'completed', 100, 100), entry('analysis.progress', 'analyzing', 50, 100, 'run-2', 2)])
    expect(model.workflow).toBe('source-analysis')
    expect(model.progress).toBe(65)
    expect(model.indeterminate).toBe(false)
    expect(model.summary).toContain('文件 50 / 100')
    expect(model.summary).toContain('已运行 15 秒')
  })

  it('shows a stable stage estimate and heartbeat time when work cannot be counted', () => {
    const entries = [entry('decompile.progress', 'decompiling', 0, 0)]
    const model = deriveTaskStageProgress(task, entries)
    expect(model.progress).toBe(30)
    expect(model.indeterminate).toBe(true)
    expect(model.updatedAt).toBe('2026-11-16T01:00:00Z')
    expect(model.stages.find((item) => item.id === 'running')?.state).toBe('current')
  })

  it('isolates retries and preserves a failed analysis outcome', () => {
    const model = deriveTaskStageProgress(task, [entry('analysis.progress', 'analyzing', 50, 100), entry('analysis.progress', 'parsing', 5, 10, 'run-2', 2), entry('analysis.failed', 'failed', 0, 0, 'run-2', 3)])
    expect(model.outcome).toBe('failed')
    expect(model.stages.find((item) => item.id === 'parsing')?.state).toBe('failed')
    expect(model.stages.find((item) => item.id === 'analyzing')?.state).toBe('pending')
  })

  it('aggregates per-module class counters without falling back during module preparation', () => {
    const first = { ...entry('decompile.progress', 'decompiling', 10, 10), moduleCurrent: 0, moduleTotal: 2 }
    const collected = { ...entry('decompile.progress', 'collecting', 10, 10), moduleCurrent: 0, moduleTotal: 2 }
    const second = { ...entry('decompile.progress', 'decompiling', 2, 10, 'run-1', 2), moduleCurrent: 1, moduleTotal: 2 }
    const prepare = entry('decompile.progress', 'preparing', 0, 0, 'run-1', 3)
    expect(deriveTaskStageProgress(task, [first, second]).progress).toBe(60)
    expect(deriveTaskStageProgress(task, [first, collected, second]).progress).toBe(60)
    expect(deriveTaskStageProgress(task, [first, second, prepare]).progress).toBe(60)
  })

  it('keeps source uploads before parsing and does not regress across indexing and parsing', () => {
    const upload = entry('analysis.progress', 'uploading', 10, 10)
    const indexing = entry('analysis.progress', 'indexing', 5, 10, 'run-1', 2)
    const parsing = entry('analysis.progress', 'parsing', 2, 10, 'run-1', 3)
    const uploaded = deriveTaskStageProgress(task, [upload])
    expect(uploaded.progress).toBe(10)
    expect(uploaded.stages.find((item) => item.id === 'uploading')?.state).toBe('current')
    expect(deriveTaskStageProgress(task, [upload, indexing, parsing]).progress).toBe(35)
  })

  it('keeps authoritative failed and cancelled execution statuses visible', () => {
    const done = entry('analysis.completed', 'completed', 1, 1)
    expect(deriveTaskStageProgress({ ...task, execution_status: 'SCAN_FAILED' }, [done]).outcome).toBe('failed')
    expect(deriveTaskStageProgress({ ...task, execution_status: 'CANCELLED' }, [done]).outcome).toBe('cancelled')
  })

  it('measures archive preparation before starting the decompiler', () => {
    expect(deriveTaskStageProgress(task, [entry('decompile.progress', 'preparing', 0, 100)]).progress).toBe(5)
    expect(deriveTaskStageProgress(task, [entry('decompile.progress', 'preparing', 50, 100)]).progress).toBe(15)
    expect(deriveTaskStageProgress(task, [entry('decompile.progress', 'preparing', 100, 100)]).progress).toBe(25)
    expect(deriveTaskStageProgress(task, [entry('decompile.progress', 'starting', 0, 0)]).progress).toBe(25)
  })

  it('treats omitted zero module_current as the first module instead of the entire archive', () => {
    const first = { ...entry('decompile.progress', 'decompiling', 212, 212), moduleTotal: 21 }
    const seventh = { ...entry('decompile.progress', 'decompiling', 0, 212, 'run-1', 2), moduleCurrent: 6, moduleTotal: 21 }
    expect(deriveTaskStageProgress(task, [first]).progress).toBe(32)
    expect(deriveTaskStageProgress(task, [first, seventh]).progress).toBe(44)
  })

  it('isolates retries of the same run by elapsed time reset without resetting on heartbeats', () => {
    const old = { ...entry('decompile.progress', 'publishing', 1, 1), elapsedSeconds: 180 }
    const legacy = { ...entry('decompile.completed', 'completed', 1, 1, 'run-1', 2), elapsedSeconds: null }
    const retried = { ...entry('decompile.progress', 'preparing', 0, 214, 'run-1', 3), elapsedSeconds: 0 }
    const current = { ...entry('decompile.progress', 'preparing', 67, 214, 'run-1', 4), elapsedSeconds: 20 }
    expect(deriveTaskStageProgress(task, [old, legacy, retried, current]).progress).toBe(11)

    const published = { ...entry('analysis.progress', 'publishing', 1, 1), elapsedSeconds: 180 }
    const newUpload = { ...entry('analysis.progress', 'uploading', 1, 2, 'run-1', 2), elapsedSeconds: 0 }
    expect(deriveTaskStageProgress(task, [published, newUpload]).progress).toBe(8)

    const high = { ...entry('analysis.progress', 'analyzing', 80, 100), elapsedSeconds: 20 }
    const heartbeat = { ...entry('analysis.progress', 'analyzing', 10, 100, 'run-1', 2), elapsedSeconds: 20 }
    expect(deriveTaskStageProgress(task, [high, heartbeat]).progress).toBe(80)
  })
})
