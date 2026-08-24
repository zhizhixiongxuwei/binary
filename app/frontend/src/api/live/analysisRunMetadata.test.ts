import { describe, expect, it } from 'vitest'

import { mapLiveAnalysisRunMetadata } from './analysisRunMetadata'

describe('mapLiveAnalysisRunMetadata', () => {
  it('maps the persisted checker ruleset version into the analysis contract', () => {
    expect(mapLiveAnalysisRunMetadata({
      toolName: 'java-checker',
      toolVersion: '1.0.0',
      rulesetVersion: 'checker-v1',
    }, 'java-checker')).toEqual({
      analyzer_name: 'java-checker',
      analyzer_version: '1.0.0',
      ruleset_version: 'checker-v1',
    })
  })

  it('keeps compatibility with runs that predate checker metadata', () => {
    expect(mapLiveAnalysisRunMetadata({
      toolName: null,
      toolVersion: null,
      rulesetVersion: null,
    }, 'python-checker')).toEqual({
      analyzer_name: 'python-checker',
      analyzer_version: '',
      ruleset_version: '',
    })
  })
})
