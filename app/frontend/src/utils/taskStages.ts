import type { TaskDetail } from '@/api/types'
import type {
  TaskExecutionLogEntry,
  TaskWorkflowKind,
} from '@/components/tasks/taskExecutionLog'

export type TaskStageId =
  | 'queued'
  | 'preparing'
  | 'uploading'
  | 'starting'
  | 'running'
  | 'parsing'
  | 'indexing'
  | 'analyzing'
  | 'verifying'
  | 'database_ready'
  | 'targets_ready'
  | 'scanning'
  | 'publishing'
  | 'completed'

export type TaskStageState =
  | 'completed'
  | 'current'
  | 'pending'
  | 'failed'
  | 'cancelled'

export type TaskStageOutcome =
  | 'active'
  | 'queued'
  | 'succeeded'
  | 'failed'
  | 'cancelled'
  | 'waiting'

export interface TaskStageItem {
  id: TaskStageId
  label: string
  state: TaskStageState
  stateLabel: string
}

export interface TaskStageProgress {
  stages: TaskStageItem[]
  outcome: TaskStageOutcome
  progress: number
  indeterminate: boolean
  summary: string
  workflow: Exclude<TaskWorkflowKind, 'task'>
  workflowLabel: string
  updatedAt?: string
}

export type TaskStageSource = Pick<
  TaskDetail,
  | 'status'
  | 'current_stage'
  | 'progress'
  | 'progress_indeterminate'
> & { input_type?: string; analysis_mode?: string; execution_status?: TaskDetail['execution_status'] }

type AnalyzerWorkflow = Exclude<TaskWorkflowKind, 'task'>
type StageDefinition = Pick<TaskStageItem, 'id' | 'label'>

const containerFormats = new Set([
  'docker-tar',
  'docker-archive',
  'oci-tar',
  'oci-archive',
])

const vmImageFormats = new Set([
  'ext2',
  'ext3',
  'ext4',
  'mbr-img',
  'gpt-img',
])

const decompileFormats = new Set([
  'pe',
  'pe32',
  'pe32+',
  'elf',
  'elf32',
  'elf64',
  'macho',
  'macho-thin',
  'macho-fat',
  'java-class',
  'class',
  'jar',
  'war',
  'ear',
  'apk',
  'dex',
  'pyc',
  'python-bytecode',
])

const javaFormats = new Set([
  'java-class',
  'class',
  'jar',
  'war',
  'ear',
  'apk',
  'dex',
])

const nativeFormats = new Set([
  'pe',
  'pe32',
  'pe32+',
  'elf',
  'elf32',
  'elf64',
  'macho',
  'macho-thin',
  'macho-fat',
])

const pythonFormats = new Set(['pyc', 'python-bytecode'])

const workflowDefinitions: Readonly<Record<AnalyzerWorkflow, readonly StageDefinition[]>> = {
  decompile: [
    { id: 'queued', label: '等待调度' },
    { id: 'preparing', label: '准备输入' },
    { id: 'starting', label: '启动引擎' },
    { id: 'running', label: '反编译' },
    { id: 'publishing', label: '保存结果' },
    { id: 'completed', label: '完成' },
  ],
  'source-analysis': [
    { id: 'queued', label: '等待调度' },
    { id: 'preparing', label: '准备源码' },
    { id: 'uploading', label: '上传源码' },
    { id: 'parsing', label: '解析源码' },
    { id: 'indexing', label: '建立索引' },
    { id: 'analyzing', label: '源码检测' },
    { id: 'publishing', label: '保存结果' },
    { id: 'completed', label: '完成' },
  ],
  'image-scan': [
    { id: 'queued', label: '等待调度' },
    { id: 'verifying', label: '校验镜像' },
    { id: 'database_ready', label: '加载漏洞库' },
    { id: 'targets_ready', label: '准备目标' },
    { id: 'scanning', label: '漏洞扫描' },
    { id: 'publishing', label: '保存结果' },
    { id: 'completed', label: '完成' },
  ],
}

const stateLabels: Readonly<Record<TaskStageState, string>> = {
  completed: '已完成',
  current: '进行中',
  pending: '等待中',
  failed: '失败',
  cancelled: '已取消',
}

function normalizedInputType(value: string | undefined): string {
  return value?.trim().toLowerCase() ?? ''
}

function workflowFromTask(
  source: TaskStageSource,
  entries: readonly TaskExecutionLogEntry[],
): AnalyzerWorkflow {
  const inputType = normalizedInputType(source.input_type)
  if (source.analysis_mode === 'source') return 'source-analysis'
  const latestWorkflow = [...entries]
    .reverse()
    .find((entry) => entry.workflow !== 'task')?.workflow
  if (latestWorkflow === 'source-analysis') return latestWorkflow
  if (source.analysis_mode === 'container') return 'image-scan'
  if (source.analysis_mode === 'binary') return 'decompile'
  if (containerFormats.has(inputType) || vmImageFormats.has(inputType)) {
    return 'image-scan'
  }
  if (decompileFormats.has(inputType)) return 'decompile'

  if (latestWorkflow === 'decompile' || latestWorkflow === 'image-scan') {
    return latestWorkflow
  }
  return 'decompile'
}

function workflowLabel(
  source: TaskStageSource,
  workflow: AnalyzerWorkflow,
): string {
  if (workflow === 'source-analysis') return '源码检测'
  if (workflow === 'image-scan') {
    if (vmImageFormats.has(normalizedInputType(source.input_type))) {
      return '映像漏洞扫描'
    }
    return '镜像漏洞扫描'
  }
  const inputType = normalizedInputType(source.input_type)
  if (javaFormats.has(inputType)) return 'Java 反编译'
  if (nativeFormats.has(inputType)) return '类 C 反编译'
  if (pythonFormats.has(inputType)) return 'Python 字节码分析'
  return '反编译分析'
}

function analyzerEntries(
  entries: readonly TaskExecutionLogEntry[],
  workflow: AnalyzerWorkflow,
): readonly TaskExecutionLogEntry[] {
  let matching = entries.filter((entry) => entry.workflow === workflow)
  if (workflow === 'source-analysis' || workflow === 'decompile') {
    const latest = matching[matching.length - 1]
    if (latest?.runId) matching = matching.filter((entry) => entry.runId === latest.runId)

    // A leased job may retry the same run ID. Elapsed time restarts for each
    // worker attempt, so earlier attempts must not pin the new attempt's max.
    // Equal timestamps are normal for phase changes and activity heartbeats;
    // legacy events without elapsed time cannot identify an attempt boundary.
    let attemptStart = 0
    let previousElapsed: number | null = null
    for (let index = 0; index < matching.length; index += 1) {
      const elapsed = matching[index]?.elapsedSeconds
      if (typeof elapsed !== 'number') continue
      if (previousElapsed !== null && elapsed < previousElapsed) attemptStart = index
      previousElapsed = elapsed
    }
    matching = matching.slice(attemptStart)
  }
  let latestQueued = -1
  for (let index = matching.length - 1; index >= 0; index -= 1) {
    if (matching[index]?.phase === 'queued') {
      latestQueued = index
      break
    }
  }
  return latestQueued < 0 ? matching : matching.slice(latestQueued)
}

function stageIndex(
  definitions: readonly StageDefinition[],
  phase: string | null,
): number {
  if (phase === 'decompiling') phase = 'running'
  if (phase === 'collecting' || phase === 'uploading' && !definitions.some((stage) => stage.id === 'uploading')) phase = 'publishing'
  if (phase === 'target_completed' || phase === 'target_failed') {
    return definitions.findIndex((stage) => stage.id === 'scanning')
  }
  return definitions.findIndex((stage) => stage.id === phase)
}

function ratio(entry: TaskExecutionLogEntry | undefined): number | null {
  if (
    !entry
    || entry.current === null
    || entry.total === null
    || entry.total <= 0
    || entry.current < 0
    || entry.current > entry.total
  ) {
    return null
  }
  const fraction = entry.current / entry.total
  if (typeof entry.moduleTotal === 'number' && entry.moduleTotal > 0) {
    const moduleCurrent = entry.moduleCurrent ?? 0
    if (moduleCurrent <= entry.moduleTotal) return Math.min(1, (moduleCurrent + fraction) / entry.moduleTotal)
  }
  return fraction
}

function progressFor(
  workflow: AnalyzerWorkflow,
  phase: string | null,
  entry: TaskExecutionLogEntry | undefined,
): number {
  const fraction = ratio(entry)
  if (workflow === 'source-analysis') {
    if (phase === 'preparing' || phase === 'starting') return 5
    if (phase === 'uploading') return Math.round(5 + 5 * (fraction ?? 0))
    if (phase === 'parsing') return Math.round(10 + 20 * (fraction ?? 0))
    if (phase === 'indexing') return Math.round(30 + 10 * (fraction ?? 0))
    if (phase === 'analyzing' || phase === 'running') return Math.round(40 + 50 * (fraction ?? 0))
    if (phase === 'publishing' || phase === 'collecting') return 95
    if (phase === 'completed') return 100
    return 0
  }
  if (workflow === 'decompile') {
    const moduleTotal = entry?.moduleTotal
    const moduleCurrent = entry?.moduleCurrent ?? (typeof moduleTotal === 'number' && moduleTotal > 0 ? 0 : null)
    if (typeof moduleCurrent === 'number' && typeof moduleTotal === 'number' && moduleTotal > 0 && moduleCurrent <= moduleTotal) {
      if (phase === 'preparing' || phase === 'starting') return Math.round(30 + 50 * moduleCurrent / moduleTotal)
      if (phase === 'collecting' || phase === 'uploading' || phase === 'publishing') return Math.round(30 + 50 * Math.min(1, (moduleCurrent + 1) / moduleTotal))
      if (phase === 'running' || phase === 'decompiling') return Math.round(30 + 50 * (fraction ?? moduleCurrent / moduleTotal))
    }
    if (phase === 'preparing') return Math.round(5 + 20 * (fraction ?? 0))
    if (phase === 'starting') return 25
    if (phase === 'running' || phase === 'decompiling') return Math.round(30 + 50 * (fraction ?? 0))
    if (phase === 'publishing' || phase === 'collecting' || phase === 'uploading') return 90
    if (phase === 'completed') return 100
    return 0
  }
  if (phase === 'verifying') return 10
  if (phase === 'database_ready') return 25
  if (phase === 'targets_ready') return 40
  if (phase === 'scanning' || phase === 'target_completed' || phase === 'target_failed') {
    return Math.round(45 + 40 * (fraction ?? 0))
  }
  if (phase === 'publishing') return 92
  if (phase === 'completed') return 100
  return 0
}

function buildStages(
  definitions: readonly StageDefinition[],
  currentIndex: number,
  currentState: TaskStageState | null,
): TaskStageItem[] {
  return definitions.map((definition, index) => {
    let state: TaskStageState = 'pending'
    if (index < currentIndex) state = 'completed'
    if (index === currentIndex && currentState) state = currentState
    return { ...definition, state, stateLabel: stateLabels[state] }
  })
}

function waitingModel(
  source: TaskStageSource,
  workflow: AnalyzerWorkflow,
): TaskStageProgress {
  const definitions = workflowDefinitions[workflow]
  return {
    stages: buildStages(definitions, -1, null),
    outcome: 'waiting',
    progress: 0,
    indeterminate: false,
    summary: workflow === 'decompile'
      ? '尚未收到反编译执行日志，可从文件结构中手动发起'
      : workflow === 'source-analysis'
        ? '等待源码检测进度更新'
      : '尚未收到镜像漏洞检测日志，等待检测任务开始',
    workflow,
    workflowLabel: workflowLabel(source, workflow),
  }
}

export function deriveTaskStageProgress(
  source: TaskStageSource,
  entries: readonly TaskExecutionLogEntry[] = [],
): TaskStageProgress {
  const workflow = workflowFromTask(source, entries)
  const definitions = workflowDefinitions[workflow]
  const relevant = analyzerEntries(entries, workflow)
  const latest = relevant[relevant.length - 1]
  if (!latest) return waitingModel(source, workflow)

  const executionFailed = source.execution_status === 'FAILED'
    || workflow === 'source-analysis' && source.execution_status === 'SCAN_FAILED'
    || workflow === 'decompile' && source.execution_status === 'DECOMPILE_FAILED'
  const failed = latest.phase === 'failed' || latest.phase === 'target_failed' || executionFailed || source.status.toUpperCase() === 'FAILED'
  const cancelled = latest.phase === 'cancelled' || source.status.toUpperCase() === 'CANCELLED' || source.execution_status === 'CANCELLED'
  const completed = latest.phase === 'completed' && !failed && !cancelled
  let currentIndex = stageIndex(definitions, latest.phase)
  if ((failed || cancelled) && latest.phase === 'completed') {
    currentIndex = definitions.findIndex((stage) => stage.id === (workflow === 'source-analysis' ? 'analyzing' : workflow === 'decompile' ? 'running' : 'scanning'))
  }
  if (latest.phase === 'failed' || latest.phase === 'cancelled') {
    const previous = [...relevant]
      .reverse()
      .find((entry) => entry.phase !== 'failed' && entry.phase !== 'cancelled')
    currentIndex = Math.max(stageIndex(definitions, previous?.phase ?? null), 0)
  }

  if (completed) {
    return {
      stages: definitions.map((definition) => ({
        ...definition,
        state: 'completed',
        stateLabel: stateLabels.completed,
      })),
      outcome: 'succeeded',
      progress: 100,
      indeterminate: false,
      summary: workflow === 'decompile' ? '反编译结果已保存' : workflow === 'source-analysis' ? '源码检测已结束' : '镜像漏洞扫描已完成',
      workflow,
      workflowLabel: workflowLabel(source, workflow),
      updatedAt: latest.createdAt,
    }
  }

  const currentState: TaskStageState = failed
    ? 'failed'
    : cancelled
      ? 'cancelled'
      : 'current'
  if (workflow === 'source-analysis' && (latest.phase === 'running' || latest.phase === 'starting')) {
    currentIndex = definitions.findIndex((stage) => stage.id === (latest.phase === 'running' ? 'analyzing' : 'preparing'))
  }
  const currentLabel = definitions[currentIndex]?.label ?? '当前'
  const progressEntry = failed || cancelled ? [...relevant].reverse().find((entry) => entry.phase !== 'failed' && entry.phase !== 'cancelled') ?? latest : latest
  const progress = workflow === 'decompile' || workflow === 'source-analysis'
    ? Math.max(...relevant.map((entry) => progressFor(workflow, entry.phase, entry)))
    : progressFor(workflow, progressEntry.phase, progressEntry)
  return {
    stages: buildStages(definitions, Math.max(currentIndex, 0), currentState),
    outcome: failed ? 'failed' : cancelled ? 'cancelled' : latest.phase === 'queued' ? 'queued' : 'active',
    progress,
    indeterminate: !failed && !cancelled && latest.phase !== 'queued' && ratio(latest) === null,
    summary: failed
      ? `${currentLabel}阶段失败`
      : cancelled
        ? `已在${currentLabel}阶段取消`
        : latest.phase === 'queued'
          ? `${currentLabel}，等待 Worker 接收任务`
          : `${currentLabel}阶段进行中${latest.detailLabel ? ' · ' + latest.detailLabel : ''}`,
    workflow,
    workflowLabel: workflowLabel(source, workflow),
    updatedAt: latest.createdAt,
  }
}
