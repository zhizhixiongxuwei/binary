import { ApiError } from '@/api/client'
import { requestLiveJSON } from '@/api/live/client'
import { isDemoMode } from '@/api/runtime'

export type InsightKind = 'architecture' | 'search'
export type ModuleRole = 'entry' | 'core' | 'data' | 'external'
export interface ArchitectureNode { id: string; label: string; role: ModuleRole; description: string; fileIds: string[] }
export interface ArchitectureEdge { from: string; to: string; label: string }
export interface FunctionMatch { fileId: string; path: string; name: string; startLine: number; endLine: number; reason: string; evidence: string }
export interface ProjectInsight {
  kind: InsightKind
  query: string
  result: { summary: string; nodes: ArchitectureNode[]; edges: ArchitectureEdge[]; flow: string[]; matches: FunctionMatch[] }
  coverage: { totalFiles: number; sampledFiles: number; inputChars: number; truncated: boolean }
  model: string
  createdAt: string
}

export async function generateProjectInsight(taskId: string, projectId: string, kind: InsightKind, query: string, signal: AbortSignal): Promise<ProjectInsight> {
  if (isDemoMode) {
    if (signal.aborted) throw new DOMException('已停止生成', 'AbortError')
    const { demoProjectInsight } = await import('@/api/demo/insightFixtures')
    if (signal.aborted) throw new DOMException('已停止生成', 'AbortError')
    const fixture = demoProjectInsight(taskId, projectId, kind, query)
    if (fixture) return fixture
    throw new ApiError('当前任务没有可展示的示例项目', 404, { code: 'source_file_not_found' })
  }
  return requestLiveJSON<ProjectInsight>(`/tasks/${encodeURIComponent(taskId)}/projects/${encodeURIComponent(projectId)}/insights`, {
    method: 'POST', body: JSON.stringify({ kind, ...(kind === 'search' ? { query } : {}) }), signal,
  })
}
