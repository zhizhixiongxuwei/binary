import { describe, expect, it } from 'vitest'

import type { UploadSession } from '@/api/types'
import { isPendingAnalysisUpload } from '@/composables/useUnifiedUpload'

function upload(overrides: Partial<UploadSession> = {}): UploadSession {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    filename: 'fixture.bin',
    part_size: 8 * 1024 * 1024,
    status: 'completed',
    uploaded_parts: [1],
    expires_at: '2026-08-26T00:00:00Z',
    validation_status: 'valid',
    tasks: [],
    ...overrides,
  }
}

describe('isPendingAnalysisUpload', () => {
  it('recovers a valid completed upload until a mode is selected', () => {
    expect(isPendingAnalysisUpload(upload())).toBe(true)
  })

  it('does not restore uploads that already created an analysis task', () => {
    expect(
      isPendingAnalysisUpload(
        upload({
          tasks: [
            {
              task_id: '22222222-2222-4222-8222-222222222222',
              analysis_mode: 'binary',
              status: 'ready',
              supported: true,
            },
          ],
        }),
      ),
    ).toBe(false)
  })

  it.each([
    { status: 'uploading' as const },
    { validation_status: 'unsupported' as const },
    { task_id: '22222222-2222-4222-8222-222222222222' },
    { archive_import_id: '33333333-3333-4333-8333-333333333333' },
  ])('rejects non-pending recovery state %#', (overrides) => {
    expect(isPendingAnalysisUpload(upload(overrides))).toBe(false)
  })
})
