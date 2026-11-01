import { describe, expect, it } from 'vitest'
import { DEMO_TASK_IDS } from './fixtures'
import { DEMO_PROJECT_ID, DEMO_SOURCE_FILES, demoProjectInsight } from './insightFixtures'

describe('demo project insights', () => {
  it('keeps all preview navigation inside the supplied source files', () => {
    const files = new Map(DEMO_SOURCE_FILES.map(file => [file.id, file]))
    const architecture = demoProjectInsight(DEMO_TASK_IDS.apk, DEMO_PROJECT_ID, 'architecture', '')
    const search = demoProjectInsight(DEMO_TASK_IDS.apk, DEMO_PROJECT_ID, 'search', '找到数据库查询函数')
    expect(architecture?.result.nodes).toHaveLength(4)
    expect(search?.result.matches.length).toBeGreaterThan(0)
    for (const match of search?.result.matches ?? []) {
      const file = files.get(match.fileId)
      expect(file?.logicalPath).toBe(match.path)
      expect(match.startLine).toBeGreaterThan(0)
      expect(match.endLine).toBeLessThanOrEqual(file?.lineCount ?? 0)
    }
  })

  it('uses a distinct network example and empty state for absent behavior', () => {
    expect(demoProjectInsight(DEMO_TASK_IDS.apk, DEMO_PROJECT_ID, 'search', '网络请求')?.result.matches[0]?.name).toBe('sendPendingUpdates()')
    expect(demoProjectInsight(DEMO_TASK_IDS.apk, DEMO_PROJECT_ID, 'search', '文件写入')?.result.matches).toEqual([])
    expect(demoProjectInsight(DEMO_TASK_IDS.firmware, DEMO_PROJECT_ID, 'architecture', '')).toBeNull()
  })
})
