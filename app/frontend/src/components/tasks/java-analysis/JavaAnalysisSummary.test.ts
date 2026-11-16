import { createSSRApp } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { describe, expect, it } from 'vitest'
import type { JavaAnalysisRun } from '@/api/types'
import JavaAnalysisSummary from './JavaAnalysisSummary.vue'

function run(): JavaAnalysisRun {
  return {
    id: 'run', task_id: 'task', source_project_id: 'project', job_id: 'run', status: 'partial', analyzer_name: 'java-checker', analyzer_version: '2', ruleset_version: '2',
    source_project: { id: 'project', target_path: 'app.jar', status: 'complete', engine_name: 'vineflower', engine_version: '1' },
    source_manifest_sha256: '', input_sha256: '', bundle_sha256: '', source_size_bytes: 100, source_file_count: 276, finding_count: 0, diagnostic_count: null,
    coverage: { total_files: 276, analyzed_files: null, parsed_files: null, failed_files: null, recovered_files: null },
    severity_counts: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }, findings_truncated: false, diagnostics_truncated: false, error_code: null, error_message: null,
    started_at: null, completed_at: null, created_at: '2026-11-16T01:00:00Z', updated_at: '2026-11-16T01:00:00Z',
  }
}

describe('Java coverage presentation', () => {
  it('shows unknown history without presenting 100% coverage', async () => {
    const html = await renderToString(createSSRApp(JavaAnalysisSummary, { run: run() }))
    expect(html).toContain('覆盖统计未知')
    expect(html).not.toContain('100%')
    expect(html).toContain('检测结果不完整')
  })

  it('explains real parser failures and skipped bytecode analysis', async () => {
    const value = run()
    value.diagnostic_count = 73
    value.coverage = { total_files: 276, analyzed_files: 204, parsed_files: 204, failed_files: 72, recovered_files: null }
    value.analysis_summary = {
      version: 'java-analysis-summary-v1', coverage: { totalFiles: 276, parsedFiles: 204, analyzedFiles: 204, failedFiles: 72, totalMethods: null, analyzedMethods: null, unresolvedCalls: null },
      diagnosticCount: 73, diagnostics: [{ code: 'PARSE_ERROR', path: 'Foo.java', message: 'Bad syntax' }], diagnosticsTruncated: false, findingsTruncated: false,
      engines: { source: { status: 'partial' }, bytecode: { status: 'skipped', reason: 'input_too_large' } },
    }
    const html = await renderToString(createSSRApp(JavaAnalysisSummary, { run: value }))
    for (const expected of ['72 个文件未成功解析', '输入超过分析上限', '73 条诊断', 'Bad syntax']) expect(html).toContain(expected)
  })
})
