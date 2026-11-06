import { describe, expect, it } from 'vitest'
import type { ScanTask, TaskExecutionStatus } from '@/api/types'
import {
  getTaskExecutionStatus,
  taskExecutionIsActive,
  taskExecutionProgressLabel,
} from './taskExecutionPresentation'

const ready = { status: 'SUCCEEDED', progress: 100, analysis_mode: 'binary' } as ScanTask

describe('task execution milestones', () => {
  it('does not treat file readiness or partial intake as completed analysis', () => {
    expect(getTaskExecutionStatus(ready)).toBe('UPLOADED')
    expect(getTaskExecutionStatus({ ...ready, status: 'PARTIAL_SUCCEEDED' })).toBe('UPLOADED')
    expect(taskExecutionProgressLabel(ready)).toBe('待反编译')
    expect(taskExecutionProgressLabel({ ...ready, analysis_mode: 'container' })).toBe('待检测')
    const { analysis_mode: _mode, ...historicalTask } = ready
    expect(taskExecutionProgressLabel({ ...historicalTask, input_type: 'oci-tar' })).toBe('待检测')
    expect(taskExecutionIsActive(ready)).toBe(false)
  })

  it('distinguishes successful decompilation from completed scanning', () => {
    const decompiled = { ...ready, execution_status: 'DECOMPILED' as const }
    expect(getTaskExecutionStatus(decompiled)).toBe('DECOMPILED')
    expect(taskExecutionProgressLabel(decompiled)).toBe('待检测')
    expect(taskExecutionIsActive(decompiled)).toBe(false)
    expect(taskExecutionProgressLabel({ ...ready, execution_status: 'SCAN_COMPLETED' })).toBe('检测已结束')
  })

  it('keeps polling analyzer runs even when the underlying task is ready', () => {
    for (const status of ['PREPARING', 'DECOMPILE_QUEUED', 'DECOMPILING', 'SCAN_QUEUED', 'SCANNING'] as const) {
      expect(taskExecutionIsActive({ ...ready, execution_status: status })).toBe(true)
    }
    expect(taskExecutionIsActive({ ...ready, status: 'QUEUED', execution_status: 'UPLOADED' })).toBe(true)
    for (const status of ['UPLOADED', 'DECOMPILED', 'SCAN_COMPLETED', 'SCAN_PARTIAL', 'DECOMPILE_FAILED', 'CANCELLED'] as const) {
      expect(taskExecutionIsActive({ ...ready, execution_status: status })).toBe(false)
    }
  })

  it('preserves partial, failed and unsupported outcomes without a completion label', () => {
    for (const status of ['DECOMPILE_PARTIAL', 'SCAN_PARTIAL', 'DECOMPILE_FAILED', 'SCAN_FAILED', 'UNSUPPORTED'] as TaskExecutionStatus[]) {
      expect(getTaskExecutionStatus({ ...ready, execution_status: status })).toBe(status)
      expect(taskExecutionProgressLabel({ ...ready, execution_status: status })).not.toBe('检测已结束')
    }
  })
})
