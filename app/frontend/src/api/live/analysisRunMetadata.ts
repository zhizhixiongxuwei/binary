export interface LiveAnalysisRunMetadata {
  toolName: string | null
  toolVersion: string | null
  rulesetVersion?: string | null
}

export function mapLiveAnalysisRunMetadata(
  run: LiveAnalysisRunMetadata,
  fallbackAnalyzerName: string,
) {
  return {
    analyzer_name: run.toolName ?? fallbackAnalyzerName,
    analyzer_version: run.toolVersion ?? '',
    ruleset_version: run.rulesetVersion ?? '',
  }
}
