import type { ScanTask, TaskExecutionStatus, TaskStatus } from '@/api/types'

export const taskExecutionStatusLabels: Record<TaskExecutionStatus, string> = {
  UPLOADED: '已上传',
  PREPARING: '准备中',
  DECOMPILE_QUEUED: '等待反编译',
  DECOMPILING: '反编译中',
  DECOMPILED: '反编译完成',
  DECOMPILE_PARTIAL: '反编译部分完成',
  DECOMPILE_FAILED: '反编译失败',
  SCAN_QUEUED: '等待检测',
  SCANNING: '检测中',
  SCAN_COMPLETED: '检测完成',
  SCAN_PARTIAL: '检测部分完成',
  SCAN_FAILED: '检测失败',
  FAILED: '准备失败',
  CANCELLED: '已取消',
  DELETING: '删除中',
  DELETED: '已删除',
  UNSUPPORTED: '不支持分析',
}

const activeExecutionStatuses = new Set<TaskExecutionStatus>([
  'PREPARING', 'DECOMPILE_QUEUED', 'DECOMPILING', 'SCAN_QUEUED', 'SCANNING', 'DELETING',
])

export function getTaskExecutionStatus(task: ScanTask): TaskExecutionStatus | TaskStatus {
  if (task.execution_status) return task.execution_status
  // Historical file-ready states provide no evidence that an analyzer ran.
  const status = task.status.toUpperCase()
  if (['SUCCEEDED', 'PARTIAL_SUCCEEDED', 'PARTIAL'].includes(status)) return 'UPLOADED'
  if (['QUEUED', 'VALIDATING', 'IDENTIFYING', 'EXTRACTING', 'INDEXING', 'RUNNING'].includes(status)) return 'PREPARING'
  return task.status
}

export function taskExecutionIsActive(task: ScanTask): boolean {
  if (task.archive?.status === 'queued' || task.archive?.status === 'running') return true
  // An older server may report UPLOADED while its intake job is still queued.
  if (task.execution_status === 'UPLOADED' && ['QUEUED', 'SCANNING'].includes(task.status.toUpperCase())) return true
  if (task.execution_status) return activeExecutionStatuses.has(task.execution_status)
  return ['UPLOADING', 'PENDING', 'QUEUED', 'VALIDATING', 'IDENTIFYING', 'EXTRACTING',
    'INDEXING', 'SCANNING', 'REPORTING', 'RUNNING', 'CANCEL_REQUESTED', 'DELETING'].includes(task.status.toUpperCase())
}

export function taskExecutionProgressLabel(task: ScanTask): string {
  const status = getTaskExecutionStatus(task).toUpperCase()
  switch (status) {
    case 'UPLOADED': {
      const imageFormats = ['docker-tar', 'docker-archive', 'oci-tar', 'oci-archive', 'ext2', 'ext3', 'ext4', 'mbr-img', 'gpt-img', 'squashfs', 'iso9660', 'udf']
      if (task.analysis_mode === 'container' || (!task.analysis_mode && imageFormats.includes(task.input_type?.toLowerCase()))) return '待检测'
      return task.analysis_mode === 'archive' ? '待解析' : '待反编译'
    }
    case 'PREPARING': return '准备文件'
    case 'DECOMPILE_QUEUED': return '等待调度'
    case 'DECOMPILING': return '生成源码'
    case 'DECOMPILED': return '待检测'
    case 'SCAN_QUEUED': return '等待调度'
    case 'SCANNING': return '分析中'
    case 'SCAN_COMPLETED': return '检测已结束'
    case 'DECOMPILE_PARTIAL': return '查看反编译结果'
    case 'SCAN_PARTIAL': return '查看检测结果'
    case 'DECOMPILE_FAILED':
    case 'SCAN_FAILED':
    case 'FAILED': return '查看失败原因'
    case 'UNSUPPORTED': return '无可用分析结果'
    case 'CANCELLED': return '执行已取消'
    case 'DELETING': return '正在清理'
    case 'DELETED': return '已清理'
    default: return '等待处理'
  }
}
