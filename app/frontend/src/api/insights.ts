import { ApiError } from '@/api/client'
import { requestLiveJSON } from '@/api/live/client'
import { isDemoMode } from '@/api/runtime'
import type { SourceFunction } from '@/components/tasks/results/sourceFunctions'

export type InsightKind = 'architecture' | 'search'
export type ModuleRole = 'entry' | 'core' | 'data' | 'external'
export interface ArchitectureNode { id: string; label: string; role: ModuleRole; description: string; fileIds: string[] }
export interface ArchitectureEdge { from: string; to: string; label: string }
export interface FunctionMatch { fileId: string; path: string; name: string; startLine: number; endLine: number; reason: string; evidence: string }
export interface ProjectInsight {
  kind: InsightKind
  query: string
  result: { summary: string; nodes: ArchitectureNode[]; edges: ArchitectureEdge[]; flow: string[]; matches: FunctionMatch[] }
  coverage: { totalFiles: number; indexedFiles?: number; sampledFiles: number; candidateFunctions?: number; inputChars: number; truncated: boolean }
  model: string
  createdAt: string
}

export async function listProjectSourceFunctions(taskId: string, projectId: string, fileId: string, signal?: AbortSignal): Promise<SourceFunction[]> {
  if (isDemoMode) {
    const [{ DEMO_SOURCE_FILES }, { findSourceFunctions }] = await Promise.all([import('@/api/demo/insightFixtures'), import('@/components/tasks/results/sourceFunctions')])
    return findSourceFunctions(DEMO_SOURCE_FILES.find(file => file.id === fileId)?.content ?? '')
  }
  const response = await requestLiveJSON<{ functions: SourceFunction[] }>(`/tasks/${encodeURIComponent(taskId)}/projects/${encodeURIComponent(projectId)}/files/${encodeURIComponent(fileId)}/functions`, signal ? { signal } : {})
  return response.functions.filter(item => item.name && Number.isInteger(item.startLine) && item.startLine > 0 && Number.isInteger(item.endLine) && item.endLine >= item.startLine)
}

export async function getSavedProjectArchitecture(taskId: string, projectId: string, signal: AbortSignal): Promise<ProjectInsight | null> {
  if (isDemoMode) return null
  try {
    return await requestLiveJSON<ProjectInsight>(`/tasks/${encodeURIComponent(taskId)}/projects/${encodeURIComponent(projectId)}/insights?kind=architecture`, { signal })
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null
    throw error
  }
}

export async function generateProjectInsight(taskId: string, projectId: string, kind: InsightKind, query: string, signal: AbortSignal, regenerate = false): Promise<ProjectInsight> {
  if (isDemoMode) {
    if (signal.aborted) throw new DOMException('已停止生成', 'AbortError')
    const { demoProjectInsight } = await import('@/api/demo/insightFixtures')
    if (signal.aborted) throw new DOMException('已停止生成', 'AbortError')
    const fixture = demoProjectInsight(taskId, projectId, kind, query)
    if (fixture) return fixture
    throw new ApiError('当前任务没有可展示的示例项目', 404, { code: 'source_file_not_found' })
  }
  return requestLiveJSON<ProjectInsight>(`/tasks/${encodeURIComponent(taskId)}/projects/${encodeURIComponent(projectId)}/insights`, {
    method: 'POST', body: JSON.stringify({ kind, ...(kind === 'search' ? { query } : { regenerate }) }), signal,
  })
}
