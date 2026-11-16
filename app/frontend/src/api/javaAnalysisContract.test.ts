import { describe, expect, it } from 'vitest'
import { parseJavaAnalysisRun } from './javaAnalysisContract'

function run() {
  const id = '11111111-1111-4111-8111-111111111111'
  const time = '2026-11-16T01:00:00Z'
  return {
    id, task_id: id, source_project_id: id, job_id: id,
    source_project: { id, target_path: 'app.jar', status: 'complete', engine_name: 'vineflower', engine_version: '1' },
    status: 'partial', analyzer_name: 'java-checker', analyzer_version: '2', ruleset_version: '2',
    source_manifest_sha256: 'a'.repeat(64), input_sha256: 'b'.repeat(64), bundle_sha256: '',
    source_size_bytes: 100, source_file_count: 20_000, finding_count: 0, diagnostic_count: null as number | null,
    coverage: { total_files: 20_000, analyzed_files: null as number | null, parsed_files: null as number | null, recovered_files: null, failed_files: null as number | null },
    severity_counts: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }, findings_truncated: false, diagnostics_truncated: false,
    error_code: null, error_message: null, started_at: null, completed_at: time, created_at: time, updated_at: time,
  }
}

describe('Java run coverage contract', () => {
  it('allows the JVM project limit and preserves unknown historical coverage', () => {
    const value = parseJavaAnalysisRun(run())
    expect(value.source_file_count).toBe(20_000)
    expect(value.coverage.parsed_files).toBeNull()
    expect(value.diagnostic_count).toBeNull()
  })

  it('allows explicitly partial processing without inventing the remaining coverage', () => {
    const value = run()
    value.coverage.parsed_files = 100
    value.coverage.analyzed_files = 80
    value.coverage.failed_files = 2
    value.diagnostic_count = 1200
    expect(parseJavaAnalysisRun(value).coverage.analyzed_files).toBe(80)
    value.status = 'succeeded'
    expect(() => parseJavaAnalysisRun(value)).toThrow('coverage')
  })
})
