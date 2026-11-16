import type { JavaAnalysisSummary, JavaNullnessTraceStep, JsonValue } from '@/api/types'

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined
}

const counter = (value: unknown, max = 1_000_000): number | null =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max ? value : null
const text = (value: unknown, maximum = 2048): string | undefined =>
  typeof value === 'string' && value.length <= maximum && !value.includes('\0') ? value : undefined

// Unknown historical coverage is deliberately preserved; no missing counter is
// inferred from source-file counts or from an empty findings array.
export function parseJavaAnalysisSummary(value: unknown): JavaAnalysisSummary | undefined {
  const summary = object(value)
  if (summary?.version !== 'java-analysis-summary-v1') return undefined
  const coverage = object(summary.coverage)
  const total = counter(coverage?.totalFiles, 20_000)
  const parsed = counter(coverage?.parsedFiles, total ?? 20_000)
  const analyzed = counter(coverage?.analyzedFiles, parsed ?? total ?? 20_000)
  const failed = counter(coverage?.failedFiles, total ?? 20_000)
  if (total !== null && parsed !== null && failed !== null && parsed + failed > total) return undefined
  const engines = object(summary.engines)
  const engine = (name: string) => {
    const raw = object(engines?.[name])
    const allowed = new Set(['complete', 'partial', 'skipped', 'not_requested', 'failed', 'unknown'])
    return { status: typeof raw?.status === 'string' && allowed.has(raw.status) ? raw.status : 'unknown',
      ...(text(raw?.reason) ? { reason: text(raw?.reason)! } : {}),
      ...(text(raw?.name, 128) ? { name: text(raw?.name, 128)! } : {}) }
  }
  const diagnostics = Array.isArray(summary.diagnostics) ? summary.diagnostics.slice(0, 1000).flatMap((item) => {
    const raw = object(item)
    const message = text(raw?.message, 8192)
    if (message === undefined) return []
    return [{ code: text(raw?.code, 128) ?? 'ANALYSIS_DIAGNOSTIC', message,
      ...(text(raw?.path, 2048) ? { path: text(raw?.path, 2048)! } : {}),
      ...(counter(raw?.line) ? { line: counter(raw?.line)! } : {}),
      ...(counter(raw?.column) ? { column: counter(raw?.column)! } : {}) }]
  }) : []
  return {
    version: 'java-analysis-summary-v1',
    coverage: { totalFiles: total, parsedFiles: parsed, analyzedFiles: analyzed, failedFiles: failed,
      totalMethods: counter(coverage?.totalMethods), analyzedMethods: counter(coverage?.analyzedMethods), unresolvedCalls: counter(coverage?.unresolvedCalls) },
    diagnosticCount: counter(summary.diagnosticCount), diagnostics,
    diagnosticsTruncated: summary.diagnosticsTruncated === true || (Array.isArray(summary.diagnostics) && summary.diagnostics.length > diagnostics.length),
    findingsTruncated: summary.findingsTruncated === true,
    engines: { source: engine('source'), bytecode: engine('bytecode') },
    ...(summary.scope !== undefined ? { scope: summary.scope as JsonValue } : {}),
    ...(summary.historical === true ? { historical: true } : {}),
  }
}

export function javaSummaryIsPartial(summary: JavaAnalysisSummary | undefined): boolean {
  return !!summary && (summary.findingsTruncated || summary.diagnosticsTruncated ||
    Object.values(summary.engines).some((engine) => ['partial', 'skipped', 'failed'].includes(engine.status)))
}

export function parseJavaNullnessTrace(value: unknown): readonly JavaNullnessTraceStep[] | undefined {
  if (!Array.isArray(value) || value.length > 32) return undefined
  const steps = value.flatMap((item) => {
    const raw = object(item)
    const path = text(raw?.path, 2048)
    const line = counter(raw?.line)
    const column = counter(raw?.column)
    if (!path || path.startsWith('/') || path.includes('\\') || path.split('/').includes('..') || !line || !column) return []
    return [{ kind: text(raw?.kind, 128) ?? 'step', path, line, column, message: text(raw?.message, 4096) ?? '' }]
  })
  return steps.length ? steps : undefined
}
