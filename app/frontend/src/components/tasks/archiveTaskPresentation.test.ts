import { describe, expect, it } from 'vitest'

import type { ScanTask } from '@/api/types'
import { archiveChildFilters, canManageArchive } from './archiveTaskPresentation'

const parent: ScanTask = {
  id: 'archive-parent', name: 'release.zip', input_type: 'zip', creator_id: 'owner', tags: ['ZIP'],
  status: 'SUCCEEDED', risk_level: 'UNKNOWN', progress: 100, progress_indeterminate: false,
  creator_name: '归档创建者', created_at: '2026-07-30T00:00:00Z',
  sample_expires_at: '2026-08-30T00:00:00Z', sample_deleted_at: null,
}

describe('archive child filters', () => {
  it('does not carry the parent cursor, archive mode or parent location query into binary children', () => {
    expect(archiveChildFilters(parent, {
      page_size: 20, cursor: 'parent-cursor', analysis_mode: 'archive',
      keyword: 'archive-parent', input_type: 'zip', status: 'FAILED',
    })).toEqual({ page_size: 10, status: 'FAILED' })
  })

  it('keeps member search and execution filters, independently of the parent mode', () => {
    expect(archiveChildFilters(parent, {
      page_size: 20, analysis_mode: 'binary', keyword: 'libcrypto',
      input_type: 'elf64', status: 'FAILED', creator: 'owner',
    })).toEqual({ page_size: 10, keyword: 'libcrypto', input_type: 'elf64', status: 'FAILED' })
  })

  it('keeps parent creator and creation windows out of child queries', () => {
    expect(archiveChildFilters(parent, {
      page_size: 20, creator: 'batch-owner', created_from: '2026-07-30', created_to: '2026-07-30',
    })).toEqual({ page_size: 10 })
  })

  it('shows children when the root was located by a partial parent ID or archive format tag', () => {
    expect(archiveChildFilters(parent, {
      page_size: 20, keyword: 'PARENT', tag: 'zip',
    })).toEqual({ page_size: 10 })
    expect(archiveChildFilters({ ...parent, tags: ['RELEASE'] }, {
      page_size: 20, tag: 'release',
    })).toEqual({ page_size: 10 })
  })

  it('continues applying a tag that matches only a member format', () => {
    expect(archiveChildFilters(parent, {
      page_size: 20, keyword: 'libcrypto', tag: 'elf64',
    })).toEqual({ page_size: 10, keyword: 'libcrypto', tag: 'elf64' })
  })
})

describe('archive management permission', () => {
  it('allows administrators and the operator who owns the parent', () => {
    expect(canManageArchive(parent, 'administrator', 'another-user')).toBe(true)
    expect(canManageArchive(parent, 'operator', 'owner')).toBe(true)
    expect(canManageArchive(parent, 'operator', 'another-user')).toBe(false)
    expect(canManageArchive(parent, 'reader', 'owner')).toBe(false)
  })
})
