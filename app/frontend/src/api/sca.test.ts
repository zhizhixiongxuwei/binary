import { describe, it, expect } from 'vitest'
import { parseOccurrence } from './sca'
import { deriveTaskStageProgress } from '@/utils/taskStages'

describe('SCA result trust boundaries', () => {
  it('preserves unknown and refuses an invalid disposition from the server', () => {
    const item = {
      id: 'a'.repeat(64),
      taskId: 'task',
      status: 'open',
      vulnerability: {
        id: 'CVE-test',
        componentId: 'component',
        severity: 'high',
        title: 'test',
        description: '',
        fixedVersion: '',
        primaryUrl: '',
        component: {
          id: 'component',
          sourceRef: 'ref',
          name: 'unresolved',
          version: '',
          path: 'app.jar',
          quality: 'unresolved',
        },
      },
      assessments: [],
      dispositions: [],
    }
    expect(parseOccurrence(item).status).toBe('open')
    expect(parseOccurrence(item).assessments).toEqual([])
    expect(() => parseOccurrence({ ...item, status: 'fixed' })).toThrow()
  })
  it('shows a finished Java component task without suggesting decompilation', () => {
    const view = deriveTaskStageProgress({
      status: 'SUCCEEDED',
      current_stage: 'completed',
      progress: 100,
      progress_indeterminate: false,
      execution_status: 'SCAN_PARTIAL',
      analysis_mode: 'java_sca',
      input_type: 'jar',
    })
    expect(view.progress).toBe(100)
    expect(view.workflowLabel).toContain('组件漏洞')
    expect(view.summary).toContain('覆盖受限')
    expect(view.stages.some((stage) => stage.label.includes('反编译'))).toBe(
      false,
    )
  })
})
