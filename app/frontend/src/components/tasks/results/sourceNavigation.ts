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
  return target(
    finding.source_project_id || finding.file.result_id,
    finding.source_file_id,
    finding.source_path || finding.file.logical_path,
    finding.location,
  )
}
