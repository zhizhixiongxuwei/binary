import { afterEach, describe, expect, it, vi } from 'vitest'
import { createLiveApiClient } from './client'
import { javaSummaryIsPartial, parseJavaAnalysisSummary, parseJavaNullnessTrace } from '@/api/javaAnalysisSummary'

const summary = {
  version: 'java-analysis-summary-v1',
  coverage: { totalFiles: 276, parsedFiles: 204, failedFiles: 72, analyzedFiles: 204, totalMethods: 500, analyzedMethods: 400, unresolvedCalls: 8 },
  diagnosticCount: 73, diagnostics: [{ code: 'PARSE_ERROR', path: 'Foo.java', line: 99, column: 20, message: 'Unsupported syntax' }],
  findingsTruncated: false, diagnosticsTruncated: false,
  engines: { source: { status: 'partial' }, bytecode: { status: 'skipped', reason: 'input_too_large' } },
}

afterEach(() => vi.unstubAllGlobals())

function detail(analysisSummary?: unknown) {
  return {
    task: { id: 'task', displayName: 'input.jar', status: 'ready' }, files: [],
    projects: [{ id: 'project', fileId: 'file', runId: 'decompile', sourceKind: 'jvm', language: 'java', resultQuality: 'source', fileCount: 276, sizeBytes: 100, createdAt: '2026-11-16T01:00:00Z' }],
    runs: [{ id: 'run', kind: 'java_check', status: 'complete', subjectId: 'project', resultQuality: 'source', toolName: 'java-checker', analysisSummary }],
  }
}

describe('Java analysis evidence mapping', () => {
  it('shows real incomplete coverage and diagnostics even when the job completed', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(Response.json(detail(summary))).mockResolvedValueOnce(Response.json({ findings: [] })))
    const run = await createLiveApiClient().getJavaAnalysisRun('task', 'run')
    expect(run).toMatchObject({ status: 'partial', diagnostic_count: 73, coverage: { total_files: 276, parsed_files: 204, analyzed_files: 204, failed_files: 72 } })
    expect(run.analysis_summary?.engines.bytecode).toMatchObject({ status: 'skipped', reason: 'input_too_large' })
  })

  it('keeps missing historical coverage and diagnostic count unknown', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(Response.json(detail())).mockResolvedValueOnce(Response.json({ findings: [] })))
    const run = await createLiveApiClient().getJavaAnalysisRun('task', 'run')
    expect(run.diagnostic_count).toBeNull()
    expect(run.coverage.analyzed_files).toBeNull()
    expect(run.coverage.parsed_files).toBeNull()
    expect(run.coverage.failed_files).toBeNull()
  })

  it('does not downgrade an explicitly unrequested bytecode engine', () => {
    const parsed = parseJavaAnalysisSummary({ ...summary, engines: { source: { status: 'complete' }, bytecode: { status: 'not_requested' } } })
    expect(javaSummaryIsPartial(parsed)).toBe(false)
    expect(parseJavaAnalysisSummary({ ...summary, coverage: { ...summary.coverage, failedFiles: 200 } })).toBeUndefined()
  })

  it('preserves unknown historical counters and rejects unsafe trace navigation', () => {
    expect(parseJavaAnalysisSummary({ ...summary, coverage: { totalFiles: 276 } })?.coverage.parsedFiles).toBeNull()
    expect(parseJavaNullnessTrace([{ kind: 'source', path: '../secret.java', line: 1, column: 1 }])).toBeUndefined()
    expect(parseJavaNullnessTrace([{ kind: 'argument', path: 'src/Foo.java', line: 10, column: 2, message: 'may be null' }])).toEqual([
      { kind: 'argument', path: 'src/Foo.java', line: 10, column: 2, message: 'may be null' },
    ])
  })

  it('keeps bounded long diagnostics and explicitly marks omitted diagnostics', () => {
    const message = 'x'.repeat(4096)
    expect(parseJavaAnalysisSummary({ ...summary, diagnostics: [{ code: 'ANALYSIS_ERROR', message }] })?.diagnostics[0]?.message).toBe(message)
    expect(parseJavaAnalysisSummary({ ...summary, diagnostics: [{ code: 'ANALYSIS_ERROR', message: 'bad\0message' }] })?.diagnosticsTruncated).toBe(true)
  })

  it('retains incomplete trace warnings even when all navigation steps were rejected', async () => {
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(Response.json({ findings: [{ id: 1, ruleId: 'java-null-dereference', severity: 'medium', path: 'Foo.java', message: 'nullable', evidence: { traceIncomplete: true, nullnessTrace: [] } }] }))
      .mockResolvedValueOnce(Response.json({ runs: [{ id: 'run', subjectId: 'project' }] })))
    const result = await createLiveApiClient().listJavaAnalysisFindings('task', 'run')
    expect(result.items[0]?.nullness_trace_incomplete).toBe(true)
    expect(result.items[0]?.nullness_trace).toBeUndefined()
  })
})
