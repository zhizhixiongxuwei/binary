import type { AnalysisRuleCatalog } from '@/api/types'

export const testRuleCatalog: AnalysisRuleCatalog = {
  language: 'c', engine: { name: 'c-checker', version: '' }, catalogVersion: 'catalog-1',
  available: true, freshness: 'fresh', last_checked_at: '2026-11-04T04:00:00Z', detail: '',
  rules: [
    { id: 'c-memory-release', name: '无效内存释放', description: '检查释放非堆内存和偏移指针。',
      cwes: ['CWE-590'], severity: 'high', language: 'c', default_enabled: true,
      limitations: ['仅依据当前函数中的指针来源判断。'] },
    { id: 'c-bounds', name: '缓冲区边界检查', description: '检查缓冲区写入长度。',
      cwes: ['CWE-120'], severity: 'MEDIUM', language: 'c', default_enabled: true, limitations: [] },
  ],
}
