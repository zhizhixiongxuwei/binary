import type { ArchiveImportStatus, ScanTask, TaskListQuery, UserRole } from '@/api/types'
import { taskExecutionIsActive } from '@/components/tasks/taskExecutionPresentation'

export const archiveStatusLabels: Record<ArchiveImportStatus, string> = {
  queued: '等待解析',
  running: '正在解析',
  ready: '解析完成',
  failed: '解析失败',
  unsupported: '不适用/无结果',
  deleting: '正在清理原始归档',
  deleted: '原始归档已清理',
}

export function canManageArchive(task: ScanTask, role: UserRole | null, userId: string | null): boolean {
  return role === 'administrator' || (role === 'operator' && task.creator_id === userId)
}

export function archiveChildFilters(task: ScanTask, filters: TaskListQuery): TaskListQuery {
  const {
    cursor: _cursor,
    analysis_mode: _mode,
    creator: _creator,
    created_from: _createdFrom,
    created_to: _createdTo,
    ...query
  } = filters
  // Creator and creation dates identify root records. Children may have been
  // created by a different operator or at another point in the batch lifecycle.
  // A parent ID/name or archive format locates the batch, rather than filtering
  // out every binary child beneath that matching batch.
  const keyword = query.keyword?.toLowerCase()
  if (keyword && (task.id.toLowerCase().includes(keyword) || task.name.toLowerCase().includes(keyword))) {
    delete query.keyword
  }
  if (query.input_type === task.input_type) delete query.input_type
  const tag = query.tag?.toLowerCase()
  if (tag && (tag === task.input_type.toLowerCase() || task.tags.some((item) => item.toLowerCase() === tag))) {
    delete query.tag
  }
  return { ...query, page_size: 10 }
}

export function taskIsActive(task: ScanTask): boolean {
  return taskExecutionIsActive(task)
}
