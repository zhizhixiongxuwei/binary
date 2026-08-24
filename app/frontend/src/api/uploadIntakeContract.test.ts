import { describe, expect, it } from 'vitest'

import {
  parseCompletedUpload,
  parseUploadAnalysisTask,
} from '@/api/uploadIntakeContract'

const uploadId = '11111111-1111-4111-8111-111111111111'
const taskId = '22222222-2222-4222-8222-222222222222'

describe('unified upload contract', () => {
  it('accepts a completed asset before any analysis mode is selected', () => {
    const parsed = parseCompletedUpload({
      id: uploadId,
      filename: 'rootfs.ext4',
      content_type: 'application/octet-stream',
      part_size: 8 * 1024 * 1024,
      sha256: 'a'.repeat(64),
      size_bytes: 2048,
      status: 'completed',
      uploaded_parts: [1],
      expires_at: '2026-08-25T12:00:00Z',
      validation_status: 'valid',
      detected_category: 'container',
      detected_format: 'ext4',
      analysis_options: [
        {
          mode: 'container',
          supported: false,
          reason: 'Trivy 镜像扫描器不支持 ext4 格式',
        },
      ],
    })

    expect(parsed.detected_format).toBe('ext4')
    expect(parsed.tasks).toBeUndefined()
    expect(parsed.analysis_options?.[0]?.supported).toBe(false)
  })

  it('accepts an explicit not-applicable mode task', () => {
    expect(
      parseUploadAnalysisTask({
        task_id: taskId,
        analysis_mode: 'container',
        status: 'partial',
        supported: false,
      }),
    ).toEqual({
      task_id: taskId,
      analysis_mode: 'container',
      status: 'partial',
      supported: false,
    })
  })
})
