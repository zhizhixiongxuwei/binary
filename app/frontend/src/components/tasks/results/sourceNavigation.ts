import type {
  CAnalysisFinding,
  JavaAnalysisFinding,
  PythonAnalysisFinding,
  SourceNavigationTarget,
} from '@/api/types'

type FileFinding = JavaAnalysisFinding | PythonAnalysisFinding

function target(
  projectId: string,
  sourceFileId: string | undefined,
  path: string | undefined,
  location: CAnalysisFinding['location'],
): SourceNavigationTarget | undefined {
  if (!projectId) return undefined
  return {
    projectId,
    ...(sourceFileId ? { sourceFileId } : {}),
    ...(path ? { path } : {}),
    startLine: location.start_line,
    startColumn: location.start_column,
    endLine: location.end_line,
    endColumn: location.end_column,
  }
}

export function cFindingSourceTarget(
  finding: CAnalysisFinding,
): SourceNavigationTarget | undefined {
  return target(
    finding.source_project_id || finding.function.result_id,
    finding.source_file_id,
    finding.source_path,
    finding.location,
  )
}

export function fileFindingSourceTarget(
  finding: FileFinding,
): SourceNavigationTarget | undefined {
  if (!finding.location) return undefined
  return target(
    finding.source_project_id || finding.file.result_id,
    finding.source_file_id,
    finding.source_path || finding.file.logical_path,
    finding.location,
  )
}

export function javaFindingSourceTarget(
  finding: JavaAnalysisFinding,
): SourceNavigationTarget | undefined {
  if (finding.location) return fileFindingSourceTarget(finding)
  const location = finding.decompiled_location
  if (!location) return undefined
  // The mapper locates a generated line. Columns only satisfy the editor's navigation range.
  return target(finding.file.result_id, undefined, location.path, {
    start_line: location.line,
    end_line: location.line,
    start_column: 1,
    end_column: 1,
  })
}
