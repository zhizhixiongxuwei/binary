import { describe, expect, it } from 'vitest'

import {
  ArchiveReportBundleContractError,
  parseArchiveReportBundle,
  parseArchiveReportBundleList,
} from '@/api/archiveReportBundleContract'

function bundle() {
  return {
    id: 'bundle-1',
    archive_import_id: 'import-1',
    status: 'ready',
    schema_version: 'binaryscan-archive-report-bundle-v1',
    formats: ['html', 'json'],
    include_sources: true,
    included_tasks: 2,
    omitted_tasks: 1,
    report_files: 4,
    source_files: 12,
    sha256: 'a'.repeat(64),
    size_bytes: 1024 * 1024,
    created_at: '2026-08-25T12:00:00Z',
    completed_at: '2026-08-25T12:00:00Z',
  }
}

describe('archive report bundle contract', () => {
  it('accepts a complete immutable bundle response', () => {
    const parsed = parseArchiveReportBundle({ bundle: bundle() })
    expect(parsed.formats).toEqual(['html', 'json'])
    expect(parsed.include_sources).toBe(true)
    expect(parsed.included_tasks).toBe(2)
  })

  it('accepts a unique bundle list', () => {
    const parsed = parseArchiveReportBundleList({ bundles: [bundle()] })
    expect(parsed.items).toHaveLength(1)
  })

  it('rejects duplicate formats and invalid hashes', () => {
    expect(() =>
      parseArchiveReportBundle({
        bundle: { ...bundle(), formats: ['html', 'html'] },
      }),
    ).toThrow(ArchiveReportBundleContractError)
    expect(() =>
      parseArchiveReportBundle({
        bundle: { ...bundle(), sha256: 'not-a-digest' },
      }),
    ).toThrow(ArchiveReportBundleContractError)
  })

  it('rejects unknown response fields', () => {
    expect(() =>
      parseArchiveReportBundle({
        bundle: { ...bundle(), unexpected: true },
      }),
    ).toThrow(ArchiveReportBundleContractError)
  })
})
