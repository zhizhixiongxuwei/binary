import type { TaskDetail, TaskStatus, UserRole } from '@/api/types'
import { resolveSampleRetention } from '@/utils/sampleRetention'

export {
  isSampleDeleted,
  isSampleExpired,
  parseSampleExpiry,
} from '@/utils/sampleRetention'

export type TaskActionMode = 'live' | 'preview'
export type TaskActionId = 'cancel' | 'retry' | 'delete'

export interface TaskActionState {
  enabled: boolean
  reason: string
}

export interface TaskActionModel {
  cancel: TaskActionState
  retry: TaskActionState
  delete: TaskActionState
  sampleExpired: boolean
  sampleDeleted: boolean
}

export interface TaskActionContext {
  task: Pick<
    TaskDetail,
    'status' | 'sample_expires_at' | 'sample_deleted_at'
  >
  mode: TaskActionMode
  userRole: UserRole | null
  isCreator: boolean
  now?: Date | undefined
}

const CANCEL_STATUSES = new Set([
  'QUEUED',
  'VALIDATING',
  'IDENTIFYING',
  'EXTRACTING',
  'INDEXING',
  'SCANNING',
  'REPORTING',
  'RUNNING',
])

const RETRY_STATUSES = new Set([
  'FAILED',
  'CANCELLED',
  'PARTIAL',
  'PARTIAL_SUCCEEDED',
])

const TERMINAL_DELETE_STATUSES = new Set(['DELETING', 'DELETED'])

function normalizedStatus(status: TaskStatus): string {
  return status.trim().toUpperCase()
}

function disabled(reason: string): TaskActionState {
  return { enabled: false, reason }
}

function enabled(reason: string): TaskActionState {
  return { enabled: true, reason }
}

export function getTaskActionModel(context: TaskActionContext): TaskActionModel {
  const { task, userRole, isCreator } = context
  const status = normalizedStatus(task.status)
  const retention = resolveSampleRetention({
    sampleExpiresAt: task.sample_expires_at,
    sampleDeletedAt: task.sample_deleted_at,
    now: context.now,
  })
  const sampleDeleted = retention.status === 'deleted'
  const sampleExpired =
    sampleDeleted || retention.status === 'expired'

  const canOperate = userRole === 'administrator' || userRole === 'operator'
  const cancel = !canOperate
    ? disabled('当前角色没有取消任务的权限。')
    : CANCEL_STATUSES.has(status)
      ? enabled('取消排队中或执行中的任务。')
      : disabled('仅排队中或执行中的任务可以取消。')

  const retry = !canOperate
    ? disabled('当前角色没有重新检测的权限。')
    : sampleDeleted
      ? disabled('任务原始样本已清理，无法重新检测。')
      : sampleExpired
        ? disabled('样本保留期已到，无法重新检测。')
      : !retention.canReuseSample
        ? disabled(retention.actionReason)
      : RETRY_STATUSES.has(status)
        ? enabled('以相同样本创建一次新的检测尝试。')
        : disabled('仅失败、已取消或部分成功的任务可以重试。')

  const canDelete =
    userRole === 'administrator' || (userRole === 'operator' && isCreator)
  const deleteAction = !canDelete
    ? disabled('只有管理员，或作为创建者的检测人员可以删除任务。')
    : TERMINAL_DELETE_STATUSES.has(status)
      ? disabled('任务已进入删除流程。')
      : enabled('删除任务及关联数据；其他任务共用的样本和审计记录会保留。')

  return {
    cancel,
    retry,
    delete: deleteAction,
    sampleExpired,
    sampleDeleted,
  }
}
