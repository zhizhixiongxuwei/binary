import type { ApiClient } from '@/api/contract'
import { ApiError, apiEndpoint, parseApiErrorBody } from '@/api/client'
import {
  DecompileSourceContractError,
  parseDecompileSourceFileContent,
  parseDecompileSourceFileList,
} from '@/api/decompileSourceContract'
import {
  ArchiveImportContractError,
  parseArchiveImport,
  parseArchiveImportEntryPage,
  parseArchiveImportPage,
  parseArchiveTaskBatchResult,
} from '@/api/archiveImportContract'
import {
  ArchiveReportBundleContractError,
  parseArchiveReportBundle,
  parseArchiveReportBundleList,
} from '@/api/archiveReportBundleContract'
import {
  parseCompletedUpload,
  parseCreatedUploadSession,
  parseUploadAnalysisTask,
  parseUploadPage,
  parseUploadSession,
  UploadIntakeContractError,
} from '@/api/uploadIntakeContract'
import {
  mapLiveAnalysisRunMetadata,
  type LiveAnalysisRunMetadata,
} from '@/api/live/analysisRunMetadata'
import type * as Model from '@/api/types'

interface LiveUser {
  id: string
  username: string
  role: Model.UserRole
  mustChangePassword: boolean
  csrfToken?: string
}

interface LiveTask {
  id: string
  displayName: string
  status: string
  creatorId?: string
  creatorName?: string
  inputSha256?: string
  detectedFormat?: string
  analysisMode?: Model.AnalysisMode
  createdAt: string
  updatedAt: string
}

interface LiveFile {
  id: string
  parentId: string | null
  path: string
  kind: string
  detectedFormat: string | null
  sizeBytes: number
  sha256: string
}

interface LiveRun extends LiveAnalysisRunMetadata {
  id: string
  kind: string
  status: string
  subjectType: string
  subjectId: string
  resultQuality: string | null
  errorCode: string | null
  errorMessage: string | null
  createdAt: string
  startedAt: string | null
  completedAt: string | null
}

interface LiveProject {
  id: string
  fileId: string
  runId: string
  sourceKind: 'native' | 'jvm' | 'pyc'
  language: 'c' | 'java' | 'python'
  resultQuality: 'source' | 'partial_source' | 'bytecode_only'
  fileCount: number
  sizeBytes: number
  createdAt: string
}

interface LiveTaskDetail {
  task: LiveTask
  files: LiveFile[]
  runs: LiveRun[]
  projects: LiveProject[]
}

interface LiveFinding {
  id: number | string
  runId: string
  type: string
  language: string | null
  severity: string
  ruleId: string | null
  cwe: string | null
  externalId: string | null
  path: string | null
  sourceProjectId?: string | null
  sourceFileId?: string | null
  startLine?: number | null
  startColumn?: number | null
  endLine?: number | null
  endColumn?: number | null
  snippet?: string | null
  snippetStartLine?: number | null
  line?: number | null
  column?: number | null
  title: string
  message: string
  evidence: Record<string, unknown> | null
  createdAt: string
}

interface LiveReport {
  id: string
  taskId: string
  format: Model.ReportFormat
  schemaVersion: string
  status: string
  sha256?: string | null
  sizeBytes?: number | null
  createdAt: string
  completedAt?: string | null
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? '/api/v1').replace(/\/$/, '')

// 后端实时 DTO 使用 camelCase，而页面和 demo 客户端共享稳定的 snake_case 模型。
// 该文件集中完成协议适配，使业务组件不必感知两套字段命名和状态枚举。
// CSRF 令牌与当前用户只保存在本页内存中，刷新后会由会话恢复接口重新取得。
let csrfToken = ''
let currentUser: Model.CurrentUser | null = null

function plusDays(value: string, days: number): string {
  const date = new Date(value)
  date.setUTCDate(date.getUTCDate() + days)
  return date.toISOString()
}

function encode(value: string): string {
  return encodeURIComponent(value)
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (init.body && !(init.body instanceof FormData) && !(init.body instanceof Blob)) {
    headers.set('Content-Type', 'application/json')
  }
  if (!SAFE_METHODS.has(method) && csrfToken) {
    // 认证 Cookie 由浏览器随 credentials 发送；有副作用的方法再叠加 CSRF 令牌。
    headers.set('X-CSRF-Token', csrfToken)
  }
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    method,
    headers,
    credentials: 'include',
  })
  if (!response.ok) {
    // 页面只处理稳定的 code/status/message；这里同时兼容后端 JSON 错误和
    // 反向代理偶尔返回的 HTML/纯文本错误页。
    let code = 'REQUEST_FAILED'
    let details: unknown
    try {
      const body = parseApiErrorBody(await response.json())
      if (body?.code) code = body.code
      details = body?.details
    } catch {
      // Keep a stable fallback for non-JSON proxy errors.
    }
    throw new ApiError(errorMessage(code, response.status), response.status, {
      code,
      message: errorMessage(code, response.status),
      details,
    })
  }
  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

function errorMessage(code: string, status: number): string {
  const messages: Record<string, string> = {
    invalid_credentials: '用户名或密码错误',
    unauthenticated: '登录状态已失效，请重新登录',
    operation_not_allowed: '当前账号没有执行此操作的权限',
    csrf_validation_failed: '登录状态已更新，请刷新页面后重试',
    task_not_found: '任务不存在或已被删除',
    file_not_found: '文件节点不存在',
    source_project_not_found: '反编译源码项目不存在或已失效',
    source_file_not_found: '反编译源码文件不存在或已失效',
    source_file_too_large: '源码文件过大，无法在线预览，请下载源码项目后查看',
    source_storage_corrupt: '源码存储校验失败，当前文件不能安全展示',
    decompile_not_supported: '该文件格式暂不支持反编译',
    source_required: '当前反编译结果没有可供检测的源码',
    checker_not_supported: '该源码类型暂不支持安全检测',
    upload_not_found: '上传会话不存在或已失效',
    upload_incomplete: '上传分片尚未完整到达服务端',
    upload_conflict: '上传分片或会话内容发生冲突',
    upload_invalid_state: '上传状态已变化，请刷新后重试',
    upload_not_completed: '文件尚未完成上传和格式识别',
    upload_expired: '上传会话已过期，请重新选择文件',
    chunk_sha256_mismatch: '上传分片校验失败，请重试',
    input_category_mismatch: '文件实际类别与所选上传入口不一致',
    unsupported_input_format: '服务端无法识别或暂不支持该文件格式',
    invalid_analysis_mode: '请选择二进制、压缩包或容器/映像分析模式',
    task_creation_failed: '分析任务创建失败，请重试',
    archive_import_not_found: '归档导入不存在或已删除',
    archive_reports_not_ready: '所选格式还没有可打包的已完成子任务报告',
    archive_report_bundle_too_large: '归档报告包内容超过安全上限，请减少格式或取消包含源码',
    archive_report_bundle_idempotency_conflict: '归档报告包请求参数已经变化，请重新提交',
    archive_report_bundle_not_found: '归档报告包不存在或已删除',
    archive_report_bundle_storage_corrupt: '归档报告包存储校验失败，当前文件不能安全下载',
    idempotency_key_required: '请求标识无效，请刷新页面后重试',
    report_run_not_finished: '仍有处理流程未结束，暂时不能生成报告',
    invalid_report_request: '当前报告格式或分析快照无效',
    invalid_report_encoding: '报告下载编码无效',
    report_idempotency_conflict: '该报告生成请求已被用于不同的格式或分析流程，请重新提交',
  }
  return messages[code] ?? `请求失败（HTTP ${status}，${code}）`
}

function mapUser(value: LiveUser): Model.CurrentUser {
  if (value.csrfToken) csrfToken = value.csrfToken
  const mapped: Model.CurrentUser = {
    id: value.id,
    username: value.username,
    display_name: value.username,
    role: value.role,
    must_change_password: Boolean(value.mustChangePassword),
  }
  currentUser = mapped
  return mapped
}

function taskStatus(value: string): Model.TaskStatus {
  switch (value) {
    case 'queued': return 'QUEUED'
    case 'scanning': return 'SCANNING'
    case 'ready': return 'SUCCEEDED'
    case 'partial': return 'PARTIAL_SUCCEEDED'
    case 'failed': return 'FAILED'
    case 'deleting': return 'DELETING'
    case 'deleted': return 'DELETED'
    default: return value as Model.TaskStatus
  }
}

function taskProgress(value: string): { progress: number; indeterminate: boolean } {
  // 列表接口没有精确百分比，因此这里只给状态级展示估值，并用 indeterminate
  // 表明“仍在执行”；该数值不能作为后台流程真实完成度。
  switch (value) {
    case 'queued': return { progress: 5, indeterminate: true }
    case 'scanning': return { progress: 58, indeterminate: true }
    case 'ready':
    case 'partial':
    case 'failed':
    case 'deleted': return { progress: 100, indeterminate: false }
    default: return { progress: 0, indeterminate: true }
  }
}

function mapTask(value: LiveTask): Model.ScanTask {
  const progress = taskProgress(value.status)
  return {
    id: value.id,
    name: value.displayName,
    input_type: value.detectedFormat || 'binary',
    ...(value.analysisMode ? { analysis_mode: value.analysisMode } : {}),
    status: taskStatus(value.status),
    risk_level: 'UNKNOWN',
    progress: progress.progress,
    progress_indeterminate: progress.indeterminate,
    creator_id: value.creatorId ?? currentUser?.id ?? '',
    creator_name:
      value.creatorName ?? currentUser?.display_name ?? currentUser?.username ?? '系统用户',
    tags: value.detectedFormat ? [value.detectedFormat.toUpperCase()] : [],
    created_at: value.createdAt,
    updated_at: value.updatedAt,
    sample_expires_at: plusDays(value.createdAt, 30),
    sample_deleted_at: null,
  }
}

export function buildLiveTaskListQuery(query: Model.TaskListQuery): string {
  const params = new URLSearchParams({
    page_size: String(Math.min(Math.max(query.page_size, 1), 100)),
  })
  if (query.cursor) params.set('cursor', query.cursor)
  if (query.keyword) params.set('keyword', query.keyword)
  if (query.status) params.set('status', query.status)
  if (query.input_type) params.set('input_type', query.input_type)
  if (query.creator) params.set('creator', query.creator)
  if (query.tag) params.set('tag', query.tag)
  if (query.created_from) params.set('created_from', query.created_from)
  if (query.created_to) params.set('created_to', query.created_to)
  return params.toString()
}

function mapTaskDetail(value: LiveTaskDetail): Model.TaskDetail {
  // 根文件、运行阶段和失败原因来自不同集合：分别映射可避免某个子检测失败
  // 覆盖任务的样本身份，或把已结束的失败 run 误当成当前阶段。
  const root = value.files.find((file) => file.parentId === null) ?? value.files[0]
  const active = value.runs.find((run) => run.status === 'running' || run.status === 'queued')
  const base = mapTask(value.task)
  const failed = value.runs.find(
    (run) => run.status === 'failed' || run.status === 'unsupported',
  )
  return {
    ...base,
    original_filename: root?.path ?? value.task.displayName,
    size_bytes: root?.sizeBytes ?? 0,
    sha256: value.task.inputSha256 ?? '',
    current_stage: active ? stageForRun(active.kind) : value.task.status === 'ready' ? 'COMPLETED' : base.status,
    ...(failed?.errorCode ? { error_code: failed.errorCode } : {}),
    ...(failed?.errorMessage ? { error_message: failed.errorMessage } : {}),
  }
}

function stageForRun(kind: string): string {
  if (kind === 'scan') return 'IDENTIFYING'
  if (kind === 'archive_import') return 'EXTRACTING'
  if (kind.endsWith('_decompile')) return 'SCANNING'
  if (kind.endsWith('_check') || kind === 'trivy_scan') return 'SCANNING'
  return 'SCANNING'
}

async function loadTask(taskId: string): Promise<LiveTaskDetail> {
  return request<LiveTaskDetail>(`/tasks/${encode(taskId)}`)
}

function displayName(path: string): string {
  const parts = path.replace(/\\/g, '/').split('/').filter(Boolean)
  return parts[parts.length - 1] ?? path
}

function depth(path: string): number {
  return Math.max(path.replace(/^\/+|\/+$/g, '').split('/').filter(Boolean).length - 1, 0)
}

function mapFile(value: LiveFile, all: readonly LiveFile[]): Model.FileNodeDetail {
  const format = value.detectedFormat ?? ''
  const parent = value.parentId ? all.find((file) => file.id === value.parentId) : undefined
  const sourceContainer = parent ? {
    id: parent.id,
    logical_path: parent.path,
    format: parent.detectedFormat ?? '',
  } : null
  return {
    id: value.id,
    parent_id: value.parentId,
    logical_path: value.path,
    display_name: displayName(value.path),
    archive_name_id: value.id,
    node_type: value.kind === 'directory' ? 'directory' : 'file',
    depth: depth(value.path),
    format,
    mime_type: '',
    architecture: '',
    size_bytes: value.kind === 'directory' ? null : value.sizeBytes,
    sha256: value.sha256,
    extraction_status: value.parentId ? 'extracted' : 'indexed',
    error_code: '',
    error_message: '',
    source_container: sourceContainer,
    has_children: all.some((file) => file.parentId === value.id),
    metadata_json: {},
    source_parent: parent ? { id: parent.id, logical_path: parent.path } : null,
  }
}

function mapProject(value: LiveProject, detail: LiveTaskDetail): Model.DecompileProject {
  const file = detail.files.find((candidate) => candidate.id === value.fileId)
  const run = detail.runs.find((candidate) => candidate.id === value.runId)
  const sourceKind: Model.DecompileProjectSourceKind = value.sourceKind === 'native'
    ? 'ghidra-pseudoc'
    : value.sourceKind === 'pyc' ? 'python' : 'java'
  return {
    id: value.id,
    task_id: detail.task.id,
    job_id: value.runId,
    file_node_id: value.fileId,
    target_path: file?.path ?? detail.task.displayName,
    layout_version: 'project-v1',
    source_kind: sourceKind,
    language: value.language,
    engine_name: run?.toolName ?? (value.sourceKind === 'native' ? 'ghidra' : value.sourceKind === 'pyc' ? 'pycdc' : 'vineflower'),
    engine_version: run?.toolVersion ?? '',
    status: value.resultQuality === 'source' ? 'complete' : value.resultQuality === 'partial_source' ? 'partial' : 'bytecode_only',
    source_file_count: value.fileCount,
    symbol_count: 0,
    source_size_bytes: value.sizeBytes,
    ...(file ? { canonical_filename: displayName(file.path) } : {}),
    manifest_available: true,
    created_at: value.createdAt,
    completed_at: run?.completedAt ?? value.createdAt,
  }
}

function runStatus(value: string): Model.CAnalysisRunStatus {
  if (value === 'complete') return 'succeeded'
  if (value === 'partial') return 'partial'
  if (value === 'running') return 'running'
  if (value === 'failed') return 'failed'
  if (value === 'cancelled') return 'cancelled'
  return 'queued'
}

function severity(value: string): Model.CAnalysisSeverity {
  const candidate = value.toUpperCase()
  return candidate === 'CRITICAL' || candidate === 'HIGH' || candidate === 'MEDIUM' ? candidate : 'LOW'
}

function severityCounts(findings: readonly LiveFinding[]): Model.CAnalysisSeverityCounts {
  const counts: Record<Model.CAnalysisSeverity, number> = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }
  for (const finding of findings) counts[severity(finding.severity)] += 1
  return counts
}

async function loadFindings(taskId: string, runId?: string): Promise<LiveFinding[]> {
  const suffix = runId ? `?runId=${encode(runId)}&limit=1000` : '?limit=1000'
  const result = await request<{ findings: LiveFinding[] }>(`/tasks/${encode(taskId)}/findings${suffix}`)
  return result.findings
}

function projectSummary(project: Model.DecompileProject) {
  return {
    id: project.id,
    target_path: project.target_path,
    status: project.status === 'partial' ? 'partial' as const : 'complete' as const,
    engine_name: project.engine_name,
    engine_version: project.engine_version,
  }
}

async function mapCAnalysisRun(detail: LiveTaskDetail, run: LiveRun): Promise<Model.CAnalysisRun> {
  const rawProject = detail.projects.find((project) => project.id === run.subjectId)
  if (!rawProject) throw new ApiError('找不到检测所使用的反编译源码', 404, { code: 'SOURCE_PROJECT_NOT_FOUND' })
  const project = mapProject(rawProject, detail)
  const findings = await loadFindings(detail.task.id, run.id)
  const count = findings.length
  return {
    id: run.id, task_id: detail.task.id, source_project_id: project.id,
    source_project: projectSummary(project), job_id: run.id, status: runStatus(run.status),
    ...mapLiveAnalysisRunMetadata(run, 'c-checker'),
    source_sha256: '', source_size_bytes: project.source_size_bytes, finding_count: count, diagnostic_count: 0,
    coverage: { total_functions: project.source_file_count, parsed_functions: project.source_file_count, failed_functions: 0 },
    severity_counts: severityCounts(findings), findings_truncated: false, diagnostics_truncated: false,
    error_code: run.errorCode, error_message: run.errorMessage, started_at: run.startedAt,
    completed_at: run.completedAt, created_at: run.createdAt, updated_at: run.completedAt ?? run.createdAt,
  }
}

async function mapJavaAnalysisRun(detail: LiveTaskDetail, run: LiveRun): Promise<Model.JavaAnalysisRun> {
  const rawProject = detail.projects.find((project) => project.id === run.subjectId)
  if (!rawProject) throw new ApiError('找不到检测所使用的反编译源码', 404, { code: 'SOURCE_PROJECT_NOT_FOUND' })
  const project = mapProject(rawProject, detail)
  const findings = await loadFindings(detail.task.id, run.id)
  const count = findings.length
  return {
    id: run.id, task_id: detail.task.id, source_project_id: project.id, source_project: projectSummary(project),
    job_id: run.id, status: runStatus(run.status), ...mapLiveAnalysisRunMetadata(run, 'java-checker'),
    source_manifest_sha256: '', input_sha256: '', bundle_sha256: '',
    source_size_bytes: project.source_size_bytes, source_file_count: project.source_file_count,
    finding_count: count, diagnostic_count: 0,
    coverage: { total_files: project.source_file_count, analyzed_files: project.source_file_count, parsed_files: project.source_file_count, recovered_files: 0, failed_files: 0 },
    severity_counts: severityCounts(findings), findings_truncated: false, diagnostics_truncated: false,
    error_code: run.errorCode, error_message: run.errorMessage, started_at: run.startedAt,
    completed_at: run.completedAt, created_at: run.createdAt, updated_at: run.completedAt ?? run.createdAt,
  }
}

async function mapPythonAnalysisRun(detail: LiveTaskDetail, run: LiveRun): Promise<Model.PythonAnalysisRun> {
  const java = await mapJavaAnalysisRun(detail, run)
  return { ...java, analyzer_name: run.toolName ?? 'python-checker' }
}

function positiveCoordinate(value: number | null | undefined, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value)
    ? Math.max(Math.trunc(value), 1)
    : fallback
}

function findingLocation(value: LiveFinding): Model.CAnalysisLocation {
  // 检测器坐标可能缺字段或越界，进入 UI 前统一收敛为 Monaco 使用的 1 基范围。
  const startLine = positiveCoordinate(value.startLine ?? value.line, 1)
  const startColumn = positiveCoordinate(value.startColumn ?? value.column, 1)
  const endLine = Math.max(positiveCoordinate(value.endLine, startLine), startLine)
  const endColumn = Math.max(
    positiveCoordinate(
      value.endColumn,
      endLine === startLine ? startColumn + 1 : 1,
    ),
    endLine === startLine ? startColumn : 1,
  )
  return {
    start_line: startLine,
    start_column: startColumn,
    end_line: endLine,
    end_column: endColumn,
  }
}

function findingSnippet(value: LiveFinding): string | undefined {
  if (typeof value.snippet === 'string') return value.snippet
  return typeof value.evidence?.snippet === 'string'
    ? value.evidence.snippet
    : undefined
}

function sourceProjectId(value: LiveFinding, fallbackProjectId: string): string {
  return value.sourceProjectId?.trim() || fallbackProjectId
}

function mapSourceFinding(
  value: LiveFinding,
  fallbackProjectId = '',
): Model.CAnalysisFinding {
  const projectId = sourceProjectId(value, fallbackProjectId)
  const snippet = findingSnippet(value)
  return {
    id: String(value.id), cwe: value.cwe ?? '', rule_id: value.ruleId ?? '', severity: severity(value.severity),
    function: { result_id: projectId, address: '', name: value.path ? displayName(value.path) : 'unknown' },
    ...(projectId ? { source_project_id: projectId } : {}),
    ...(value.sourceFileId ? { source_file_id: value.sourceFileId } : {}),
    ...(value.path ? { source_path: value.path } : {}),
    location: findingLocation(value),
    message: value.message,
    ...(snippet !== undefined ? { snippet } : {}),
    created_at: value.createdAt,
  }
}

function mapJavaFinding(
  value: LiveFinding,
  fallbackProjectId = '',
): Model.JavaAnalysisFinding {
  const projectId = sourceProjectId(value, fallbackProjectId)
  const location = findingLocation(value)
  const snippet = findingSnippet(value)
  return {
    id: String(value.id), cwe: value.cwe ?? '', rule_id: value.ruleId ?? '', severity: severity(value.severity),
    file: { result_id: projectId, logical_path: value.path ?? '', binary_name: value.path ? displayName(value.path) : '' },
    ...(projectId ? { source_project_id: projectId } : {}),
    ...(value.sourceFileId ? { source_file_id: value.sourceFileId } : {}),
    ...(value.path ? { source_path: value.path } : {}),
    callable: { kind: '', type_name: '', name: '', signature: '' },
    location,
    message: value.message,
    ...(snippet !== undefined ? { snippet } : {}),
    snippet_start_line: positiveCoordinate(value.snippetStartLine, location.start_line),
    created_at: value.createdAt,
  }
}

function mapPythonFinding(
  value: LiveFinding,
  fallbackProjectId = '',
): Model.PythonAnalysisFinding {
  return mapJavaFinding(value, fallbackProjectId)
}

async function findingsWithProject(
  taskId: string,
  runId: string,
): Promise<{ findings: LiveFinding[]; projectId: string }> {
  // finding 端点只返回检测结果；同时读取任务详情才能把 run.subjectId 补成
  // 持久化源码项目 ID，供后续“在源码中定位”使用。
  const [findings, detail] = await Promise.all([
    loadFindings(taskId, runId),
    loadTask(taskId),
  ])
  return {
    findings,
    projectId: detail.runs.find((run) => run.id === runId)?.subjectId ?? '',
  }
}

function mapReport(value: LiveReport): Model.TaskReport {
  return {
    id: value.id, task_id: value.taskId, format: value.format, schema_version: value.schemaVersion,
    status: value.status === 'ready' ? 'complete' : value.status === 'generating' ? 'generating' : value.status === 'queued' ? 'queued' : 'failed',
    sha256: value.sha256 ?? null, size_bytes: value.sizeBytes ?? null,
    error_code: null, error_message: null, created_at: value.createdAt,
    completed_at: value.completedAt ?? (value.status === 'ready' ? value.createdAt : null),
  }
}

function unsupported(message: string): never {
  throw new ApiError(message, 409, { code: 'OPERATION_NOT_AVAILABLE' })
}

export function createLiveApiClient(): ApiClient {
  // 同一次报告生成重试必须沿用首次快照的 runIds，否则新完成的运行会让同一
  // 幂等键对应不同请求体。成功或服务端明确报告冲突后才释放这份意图缓存。
  const reportRunIdsByIntent = new Map<string, readonly string[]>()
  const client: ApiClient = {
    async login(input) {
      reportRunIdsByIntent.clear()
      const result = await request<{ user: LiveUser }>('/auth/login', { method: 'POST', body: JSON.stringify(input) })
      return mapUser(result.user)
    },
    async logout() {
      await request<void>('/auth/logout', { method: 'POST' })
      csrfToken = ''
      currentUser = null
      reportRunIdsByIntent.clear()
    },
    async getMe() {
      const result = await request<{ user: LiveUser }>('/auth/me')
      return mapUser(result.user)
    },
    async changePassword(input) {
      await request<void>('/auth/password', {
        method: 'POST',
        body: JSON.stringify({ currentPassword: input.current_password, newPassword: input.new_password }),
      })
      csrfToken = ''
      currentUser = null
      reportRunIdsByIntent.clear()
    },
    async listTasks(query) {
      const result = await request<{ tasks: LiveTask[]; next_cursor?: string }>(
        `/tasks?${buildLiveTaskListQuery(query)}`,
      )
      return {
        items: result.tasks.map(mapTask),
        ...(result.next_cursor ? { next_cursor: result.next_cursor } : {}),
      }
    },
    async getTask(id) { return mapTaskDetail(await loadTask(id)) },
    async cancelTask() { return unsupported('当前处理任务不能在此阶段取消') },
    async retryTask(id) { return mapTaskDetail(await loadTask(id)) },
    async deleteTask(id) {
      const detail = await loadTask(id)
      await request<void>(`/tasks/${encode(id)}`, { method: 'DELETE' })
      return { ...mapTaskDetail(detail), status: 'DELETED', sample_deleted_at: new Date().toISOString() }
    },
    async extendTaskRetention(id, input) {
      return { ...mapTaskDetail(await loadTask(id)), sample_expires_at: input.sample_expires_at }
    },
    async listTaskFiles(taskId, query = {}) {
      const detail = await loadTask(taskId)
      let files = detail.files
      if (query.parent_id !== undefined) files = files.filter((file) => file.parentId === query.parent_id)
      else files = files.filter((file) => file.parentId === null)
      return { items: files.map((file) => mapFile(file, detail.files)) }
    },
    async getTaskFile(taskId, fileId) {
      const detail = await loadTask(taskId)
      const file = detail.files.find((candidate) => candidate.id === fileId)
      if (!file) throw new ApiError('文件节点不存在', 404, { code: 'FILE_NOT_FOUND' })
      return mapFile(file, detail.files)
    },
    async createFileDecompileRequest(taskId, fileId, input, idempotencyKey) {
      const result = await request<{ run: { id: string; kind: string; status: string; createdAt: string } }>(
        `/tasks/${encode(taskId)}/files/${encode(fileId)}/decompile`,
        { method: 'POST', headers: { 'Idempotency-Key': idempotencyKey }, body: JSON.stringify(input) },
      )
      const kind = result.run.kind
      return {
        request_id: result.run.id, job_id: result.run.id, task_id: taskId, file_node_id: fileId,
        target_class: kind === 'native_decompile' ? 'native' : 'bytecode',
        engine_target: kind === 'native_decompile' ? 'ghidra' : kind === 'pyc_decompile' ? 'python-bytecode' : 'vineflower',
        status: result.run.status === 'complete' ? 'succeeded' : result.run.status as Model.FileDecompileRequest['status'],
        created_at: result.run.createdAt,
      }
    },
    async getFileDecompileRequest(taskId, jobId) {
      const detail = await loadTask(taskId)
      const run = detail.runs.find((candidate) => candidate.id === jobId)
      if (!run) throw new ApiError('反编译任务不存在', 404, { code: 'DECOMPILE_RUN_NOT_FOUND' })
      return {
        request_id: run.id, job_id: run.id, task_id: taskId, file_node_id: run.subjectId,
        target_class: run.kind === 'native_decompile' ? 'native' : 'bytecode',
        engine_target: run.kind === 'native_decompile' ? 'ghidra' : run.kind === 'pyc_decompile' ? 'python-bytecode' : 'vineflower',
        status: run.status === 'complete' ? 'succeeded' : run.status as Model.FileDecompileRequest['status'],
        created_at: run.createdAt,
        ...(run.completedAt ? { completed_at: run.completedAt } : {}),
        ...(run.errorCode ? { error_code: run.errorCode } : {}),
        ...(run.errorMessage ? { error_message: run.errorMessage } : {}),
      }
    },
    async listDecompileProjects(taskId) {
      const detail = await loadTask(taskId)
      return { items: detail.projects.map((project) => mapProject(project, detail)) }
    },
    async getDecompileProject(taskId, projectId) {
      const detail = await loadTask(taskId)
      const project = detail.projects.find((candidate) => candidate.id === projectId)
      if (!project) throw new ApiError('反编译源码项目不存在', 404, { code: 'SOURCE_PROJECT_NOT_FOUND' })
      return mapProject(project, detail)
    },
    async downloadDecompileProject(taskId, projectId) {
      return { kind: 'url', url: apiEndpoint(`/tasks/${encode(taskId)}/projects/${encode(projectId)}/content`) }
    },
    async deleteDecompileProject() { unsupported('当前版本不允许单独删除反编译源码项目') },
    async previewDecompileProjectDeletion() { return unsupported('当前版本不允许单独删除反编译源码项目') },
    async confirmDecompileProjectDeletion() { return unsupported('当前版本不允许单独删除反编译源码项目') },
    async getDecompileProjectDeletion() { return unsupported('当前版本不允许单独删除反编译源码项目') },
    async createCAnalysisRun(taskId, projectId, idempotencyKey) {
      await request(`/tasks/${encode(taskId)}/projects/${encode(projectId)}/check`, { method: 'POST', headers: { 'Idempotency-Key': idempotencyKey } })
      const detail = await loadTask(taskId)
      const run = detail.runs.find((candidate) => candidate.subjectId === projectId && candidate.kind === 'c_check')
      if (!run) throw new ApiError('C 检测任务创建后未返回', 502, { code: 'RUN_NOT_FOUND' })
      return mapCAnalysisRun(detail, run)
    },
    async listCAnalysisRuns(taskId, query = {}) {
      const detail = await loadTask(taskId)
      const runs = detail.runs.filter((run) => run.kind === 'c_check' && (!query.project_id || run.subjectId === query.project_id))
      return { items: await Promise.all(runs.map((run) => mapCAnalysisRun(detail, run))) }
    },
    async getCAnalysisRun(taskId, runId) {
      const detail = await loadTask(taskId)
      const run = detail.runs.find((candidate) => candidate.id === runId && candidate.kind === 'c_check')
      if (!run) throw new ApiError('C 检测任务不存在', 404, { code: 'RUN_NOT_FOUND' })
      return mapCAnalysisRun(detail, run)
    },
    async listCAnalysisFindings(taskId, runId) {
      const result = await findingsWithProject(taskId, runId)
      return { items: result.findings.map((finding) => mapSourceFinding(finding, result.projectId)) }
    },
    async cancelCAnalysisRun(taskId, runId) { return client.getCAnalysisRun(taskId, runId) },
    async deleteCAnalysisRun() { unsupported('检测运行记录由统一任务生命周期管理') },
    async createJavaAnalysisRun(taskId, projectId, idempotencyKey) {
      await request(`/tasks/${encode(taskId)}/projects/${encode(projectId)}/check`, { method: 'POST', headers: { 'Idempotency-Key': idempotencyKey } })
      const detail = await loadTask(taskId)
      const run = detail.runs.find((candidate) => candidate.subjectId === projectId && candidate.kind === 'java_check')
      if (!run) throw new ApiError('Java 检测任务创建后未返回', 502, { code: 'RUN_NOT_FOUND' })
      return mapJavaAnalysisRun(detail, run)
    },
    async listJavaAnalysisRuns(taskId, query = {}) {
      const detail = await loadTask(taskId)
      const runs = detail.runs.filter((run) => run.kind === 'java_check' && (!query.project_id || run.subjectId === query.project_id))
      return { items: await Promise.all(runs.map((run) => mapJavaAnalysisRun(detail, run))) }
    },
    async getJavaAnalysisRun(taskId, runId) {
      const detail = await loadTask(taskId)
      const run = detail.runs.find((candidate) => candidate.id === runId && candidate.kind === 'java_check')
      if (!run) throw new ApiError('Java 检测任务不存在', 404, { code: 'RUN_NOT_FOUND' })
      return mapJavaAnalysisRun(detail, run)
    },
    async listJavaAnalysisFindings(taskId, runId) {
      const result = await findingsWithProject(taskId, runId)
      return { items: result.findings.map((finding) => mapJavaFinding(finding, result.projectId)) }
    },
    async cancelJavaAnalysisRun(taskId, runId) { return client.getJavaAnalysisRun(taskId, runId) },
    async deleteJavaAnalysisRun() { unsupported('检测运行记录由统一任务生命周期管理') },
    async createPythonAnalysisRun(taskId, projectId, idempotencyKey) {
      await request(`/tasks/${encode(taskId)}/projects/${encode(projectId)}/check`, { method: 'POST', headers: { 'Idempotency-Key': idempotencyKey } })
      const detail = await loadTask(taskId)
      const run = detail.runs.find((candidate) => candidate.subjectId === projectId && candidate.kind === 'python_check')
      if (!run) throw new ApiError('Python 检测任务创建后未返回', 502, { code: 'RUN_NOT_FOUND' })
      return mapPythonAnalysisRun(detail, run)
    },
    async listPythonAnalysisRuns(taskId, query = {}) {
      const detail = await loadTask(taskId)
      const runs = detail.runs.filter((run) => run.kind === 'python_check' && (!query.project_id || run.subjectId === query.project_id))
      return { items: await Promise.all(runs.map((run) => mapPythonAnalysisRun(detail, run))) }
    },
    async getPythonAnalysisRun(taskId, runId) {
      const detail = await loadTask(taskId)
      const run = detail.runs.find((candidate) => candidate.id === runId && candidate.kind === 'python_check')
      if (!run) throw new ApiError('Python 检测任务不存在', 404, { code: 'RUN_NOT_FOUND' })
      return mapPythonAnalysisRun(detail, run)
    },
    async listPythonAnalysisFindings(taskId, runId) {
      const result = await findingsWithProject(taskId, runId)
      return { items: result.findings.map((finding) => mapPythonFinding(finding, result.projectId)) }
    },
    async cancelPythonAnalysisRun(taskId, runId) { return client.getPythonAnalysisRun(taskId, runId) },
    async deletePythonAnalysisRun() { unsupported('检测运行记录由统一任务生命周期管理') },
    async createManualImageScanRequest(taskId, fileId, idempotencyKey) {
      return request<Model.ManualImageScanRequest>(
        `/tasks/${encode(taskId)}/files/${encode(fileId)}/image-scan`,
        {
          method: 'POST',
          body: JSON.stringify({}),
          headers: { 'Idempotency-Key': idempotencyKey },
        },
      )
    },
    async listDecompileResults(taskId) {
      const detail = await loadTask(taskId)
      return {
        items: detail.projects.map((project) => ({
          id: project.id, file_node_id: project.fileId, symbol_key: project.id, symbol_kind: 'module' as const,
          display_name: detail.files.find((file) => file.id === project.fileId)?.path ?? project.id,
          group_name: project.language, location: '', signature: '', detail: '', language: project.language,
          engine_name: detail.runs.find((run) => run.id === project.runId)?.toolName ?? '',
          engine_version: detail.runs.find((run) => run.id === project.runId)?.toolVersion ?? '',
          status: project.resultQuality === 'source' ? 'complete' as const : project.resultQuality === 'partial_source' ? 'partial' as const : 'bytecode_only' as const,
          size_bytes: project.sizeBytes, diagnostics: {}, created_at: project.createdAt,
          completed_at: detail.runs.find((run) => run.id === project.runId)?.completedAt ?? project.createdAt,
        })),
      }
    },
    async listDecompileSourceFiles(taskId, projectId) {
      try {
        const payload = await request<unknown>(
          `/tasks/${encode(taskId)}/projects/${encode(projectId)}/files`,
        )
        return parseDecompileSourceFileList(payload)
      } catch (error) {
        if (!(error instanceof DecompileSourceContractError)) throw error
        throw new ApiError('源码文件列表响应不符合接口契约', 502, {
          code: 'INVALID_SOURCE_FILE_RESPONSE',
        })
      }
    },
    async getDecompileSourceFileContent(taskId, projectId, fileId) {
      try {
        const payload = await request<unknown>(
          `/tasks/${encode(taskId)}/projects/${encode(projectId)}/files/${encode(fileId)}/content`,
        )
        return parseDecompileSourceFileContent(payload)
      } catch (error) {
        if (!(error instanceof DecompileSourceContractError)) throw error
        throw new ApiError('源码文件内容响应不符合接口契约', 502, {
          code: 'INVALID_SOURCE_CONTENT_RESPONSE',
        })
      }
    },
    async getDecompileSource(taskId, resultId, query = {}) {
      const params = new URLSearchParams({ offset: String(query.offset ?? 0), limit: String(query.limit ?? 262144) })
      return request<Model.DecompileSourceChunk>(`/tasks/${encode(taskId)}/projects/${encode(resultId)}/source?${params}`)
    },
    async downloadDecompileSources(taskId, includeCombined = false) {
      return { kind: 'url', url: apiEndpoint(`/tasks/${encode(taskId)}/sources?combined=${includeCombined ? '1' : '0'}`) }
    },
    async listTaskVulnerabilities(taskId, query = {}) {
      let findings = (await loadFindings(taskId)).filter((finding) => finding.type === 'vulnerability')
      if (query.severity) findings = findings.filter((finding) => finding.severity.toUpperCase() === query.severity)
      const items = findings.map((finding): Model.VulnerabilityFinding => ({
        id: String(finding.id), vulnerability_id: finding.externalId ?? finding.ruleId ?? finding.title,
        severity: severity(finding.severity), package_name: String(finding.evidence?.packageName ?? ''),
        installed_version: String(finding.evidence?.installedVersion ?? ''), fixed_version: String(finding.evidence?.fixedVersion ?? ''),
        title: finding.title, description_summary: finding.message, image_logical_path: finding.path ?? '', image_platform: '',
        evidence: (finding.evidence ?? null) as Model.VulnerabilityEvidence | null, references: null, database_bundle: null,
        created_at: finding.createdAt,
      }))
      const bySeverity: Record<Model.VulnerabilitySeverity, number> = { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }
      for (const item of items) bySeverity[item.severity] += 1
      return { summary: { total: items.length, fixable: items.filter((item) => item.fixed_version).length, by_severity: bySeverity }, items }
    },
    async getTaskVulnerability(taskId, findingId) {
      const page = await client.listTaskVulnerabilities(taskId, { page_size: 1000 })
      const finding = page.items.find((item) => item.id === findingId)
      if (!finding) throw new ApiError('漏洞记录不存在', 404, { code: 'FINDING_NOT_FOUND' })
      return finding
    },
    async listTaskReports(taskId) {
      const result = await request<{ reports: LiveReport[] }>(`/tasks/${encode(taskId)}/reports`)
      return { items: result.reports.map(mapReport), sample_relation: 'retained' }
    },
    async createTaskReport(taskId, input, idempotencyKey) {
      const intentKey = `${taskId}\u0000${idempotencyKey}`
      let runIds = reportRunIdsByIntent.get(intentKey)
      if (!runIds) {
        const detail = await loadTask(taskId)
        runIds = detail.runs
          .filter((run) => !['queued', 'running'].includes(run.status))
          .map((run) => run.id)
          .sort()
      }
      if (runIds.length === 0) throw new ApiError('任务还没有可写入报告的已完成流程', 409, { code: 'NO_COMPLETED_RUNS' })
      reportRunIdsByIntent.set(intentKey, runIds)
      try {
        const result = await request<{ report: LiveReport }>(`/tasks/${encode(taskId)}/reports`, {
          method: 'POST', headers: { 'Idempotency-Key': idempotencyKey }, body: JSON.stringify({ format: input.format, runIds }),
        })
        reportRunIdsByIntent.delete(intentKey)
        return mapReport(result.report)
      } catch (error) {
        if (error instanceof ApiError && error.code === 'report_idempotency_conflict') {
          reportRunIdsByIntent.delete(intentKey)
        }
        throw error
      }
    },
    async downloadTaskReport(_taskId, reportId, _format, encoding = 'identity') {
      const suffix = encoding === 'gzip' ? '?encoding=gzip' : ''
      return { kind: 'url', url: apiEndpoint(`/reports/${encode(reportId)}/content${suffix}`) }
    },
    async getSystemStatus() {
      const [info, tasks] = await Promise.all([
        request<{ name: string; version: string }>('/system/info'),
        request<{ tasks: LiveTask[] }>('/tasks?limit=100'),
      ])
      const queued = tasks.tasks.filter((task) => task.status === 'queued').length
      const active = tasks.tasks.filter((task) => task.status === 'scanning').length
      const names = ['scanner', 'native-decompiler', 'jvm-decompiler', 'pyc-decompiler', 'c-checker', 'java-checker', 'python-checker']
      return {
        version: info.version, service_status: 'healthy', active_tasks: active, queued_tasks: queued,
        queue_depth: queued, task_counts: Object.fromEntries(tasks.tasks.map((task) => task.status).map((status) => [status, tasks.tasks.filter((task) => task.status === status).length])),
        repository_used_bytes: 0, repository_total_bytes: 0,
        analyzers: names.map((name) => ({
          name, version: info.version, expected_version: info.version, status: 'available' as const,
          required_worker_kinds: [] as ('image' | 'native' | 'trivy')[], ready_worker_kinds: [] as ('image' | 'native' | 'trivy')[],
          ready_workers: 1, runtime_name: 'container', runtime_version: info.version,
        })),
        collected_at: new Date().toISOString(),
      }
    },
    async listAdminUsers(query = {}) {
      const result = await request<{ users: Array<{ id: string; username: string; role: Model.UserRole; active: boolean; mustChangePassword: boolean; createdAt: string; updatedAt: string }> }>('/admin/users')
      let items = result.users.map((user): Model.AdminUser => ({
        id: user.id, username: user.username, display_name: user.username, role: user.role,
        status: user.active ? 'active' : 'disabled', must_change_password: false, failed_login_count: 0,
        locked_until: null, last_login_at: null, created_at: user.createdAt, updated_at: user.updatedAt,
      }))
      if (query.keyword) items = items.filter((user) => user.username.includes(query.keyword!))
      if (query.role) items = items.filter((user) => user.role === query.role)
      if (query.status) items = items.filter((user) => user.status === query.status)
      return { items }
    },
    async createAdminUser(input) {
      const result = await request<{ user: { id: string; username: string; role: Model.UserRole; active: boolean; createdAt: string; updatedAt: string } }>('/admin/users', {
        method: 'POST', body: JSON.stringify({ username: input.username, password: input.temporary_password, role: input.role }),
      })
      return { id: result.user.id, username: result.user.username, display_name: input.display_name || result.user.username,
        role: result.user.role, status: 'active', must_change_password: false, failed_login_count: 0, locked_until: null,
        last_login_at: null, created_at: result.user.createdAt, updated_at: result.user.updatedAt }
    },
    async updateAdminUser(id, input) {
      const result = await request<{ user: { id: string; username: string; role: Model.UserRole; active: boolean; createdAt: string; updatedAt: string } }>(`/admin/users/${encode(id)}`, {
        method: 'PATCH', body: JSON.stringify({ ...(input.role ? { role: input.role } : {}), ...(input.status ? { active: input.status === 'active' } : {}) }),
      })
      return { id: result.user.id, username: result.user.username, display_name: result.user.username, role: result.user.role,
        status: result.user.active ? 'active' : 'disabled', must_change_password: false, failed_login_count: 0,
        locked_until: null, last_login_at: null, created_at: result.user.createdAt, updated_at: result.user.updatedAt }
    },
    async resetAdminUserPassword(id, input) {
      const result = await request<{ user: { id: string; username: string; role: Model.UserRole; active: boolean; createdAt: string; updatedAt: string } }>(`/admin/users/${encode(id)}`, {
        method: 'PATCH', body: JSON.stringify({ password: input.temporary_password }),
      })
      return { id: result.user.id, username: result.user.username, display_name: result.user.username, role: result.user.role,
        status: result.user.active ? 'active' : 'disabled', must_change_password: false, failed_login_count: 0,
        locked_until: null, last_login_at: null, created_at: result.user.createdAt, updated_at: result.user.updatedAt }
    },
    async listAuditLogs(query = {}) {
      const params = new URLSearchParams({ limit: String(query.page_size ?? 100) })
      if (query.cursor) params.set('beforeId', query.cursor)
      const result = await request<{ entries: Array<{ id: number; actorId: string | null; actorUsername: string | null; action: string; objectType: string | null; objectId: string | null; requestId: string | null; outcome: string; details: Model.JsonValue | null; createdAt: string }>; nextBeforeId: number | null }>(`/admin/audit?${params}`)
      let items: Model.AuditLog[] = result.entries.map((entry) => ({
        id: String(entry.id), actor: entry.actorId ? { id: entry.actorId, username: entry.actorUsername ?? '', display_name: entry.actorUsername ?? '' } : null,
        action: entry.action, outcome: entry.outcome === 'failure' || entry.outcome === 'denied' ? entry.outcome : 'success',
        object_type: entry.objectType ?? '', object_id: entry.objectId, request_id: entry.requestId ?? '', metadata: entry.details, created_at: entry.createdAt,
      }))
      if (query.action) items = items.filter((entry) => entry.action === query.action)
      if (query.outcome) items = items.filter((entry) => entry.outcome === query.outcome)
      return result.nextBeforeId === null
        ? { items }
        : { items, next_cursor: String(result.nextBeforeId) }
    },
    // 上传、归档和源码内容会驱动后续文件读写，不能只依赖 TypeScript 的编译期
    // 类型。对应 parse* 在运行时校验服务端响应，并把契约漂移转换成明确的 502。
    async createUpload(input, idempotencyKey) {
      try {
        return parseCreatedUploadSession(
          await request<unknown>('/uploads', {
            method: 'POST',
            body: JSON.stringify(input),
            headers: { 'Idempotency-Key': idempotencyKey },
          }),
        )
      } catch (error) {
        if (error instanceof UploadIntakeContractError) {
          throw new ApiError('上传响应不符合接口契约', 502, {
            code: 'INVALID_UPLOAD_RESPONSE',
          })
        }
        throw error
      }
    },
    async listUploads(query = {}) {
      const params = new URLSearchParams()
      if (query.pending_analysis !== undefined) {
        params.set('pending_analysis', String(query.pending_analysis))
      }
      if (query.limit !== undefined) params.set('limit', String(query.limit))
      const suffix = params.size ? `?${params.toString()}` : ''
      try {
        return parseUploadPage(await request<unknown>(`/uploads${suffix}`))
      } catch (error) {
        if (error instanceof UploadIntakeContractError) {
          throw new ApiError('上传响应不符合接口契约', 502, {
            code: 'INVALID_UPLOAD_RESPONSE',
          })
        }
        throw error
      }
    },
    async getUpload(uploadId) {
      try {
        return parseUploadSession(
          await request<unknown>(`/uploads/${encode(uploadId)}`),
          uploadId,
        )
      } catch (error) {
        if (error instanceof UploadIntakeContractError) {
          throw new ApiError('上传响应不符合接口契约', 502, {
            code: 'INVALID_UPLOAD_RESPONSE',
          })
        }
        throw error
      }
    },
    async uploadPart(uploadId, input) {
      await request<void>(
        `/uploads/${encode(uploadId)}/parts/${input.part_number}`,
        {
          method: 'PUT',
          body: input.chunk,
          headers: {
            'Content-Type': 'application/octet-stream',
            'Content-Range': `bytes ${input.start}-${input.end}/${input.total}`,
            'X-Chunk-SHA256': input.sha256.toLowerCase(),
          },
        },
      )
    },
    async completeUpload(uploadId) {
      try {
        return parseCompletedUpload(
          await request<unknown>(`/uploads/${encode(uploadId)}/complete`, {
            method: 'POST',
          }),
          uploadId,
        )
      } catch (error) {
        if (error instanceof UploadIntakeContractError) {
          throw new ApiError('上传响应不符合接口契约', 502, {
            code: 'INVALID_UPLOAD_RESPONSE',
          })
        }
        throw error
      }
    },
    async createUploadAnalysisTask(uploadId, input, idempotencyKey) {
      try {
        return parseUploadAnalysisTask(
          await request<unknown>(`/uploads/${encode(uploadId)}/tasks`, {
            method: 'POST',
            body: JSON.stringify(input),
            headers: { 'Idempotency-Key': idempotencyKey },
          }),
        )
      } catch (error) {
        if (error instanceof UploadIntakeContractError) {
          throw new ApiError('任务创建响应不符合接口契约', 502, {
            code: 'INVALID_UPLOAD_RESPONSE',
          })
        }
        throw error
      }
    },
    async deleteUpload(uploadId) {
      await request<void>(`/uploads/${encode(uploadId)}`, { method: 'DELETE' })
    },
    async listArchiveImports(query = {}) {
      const params = new URLSearchParams()
      if (query.cursor) params.set('cursor', query.cursor)
      if (query.page_size !== undefined) params.set('page_size', String(query.page_size))
      try {
        return parseArchiveImportPage(
          await request<unknown>(`/archive-imports${params.size ? `?${params}` : ''}`),
        )
      } catch (error) {
        if (error instanceof ArchiveImportContractError) {
          throw new ApiError('归档导入响应不符合接口契约', 502, {
            code: 'INVALID_ARCHIVE_IMPORT_RESPONSE',
          })
        }
        throw error
      }
    },
    async getArchiveImport(importId) {
      try {
        const result = parseArchiveImport(
          await request<unknown>(`/archive-imports/${encode(importId)}`),
        )
        if (result.id !== importId) {
          throw new ArchiveImportContractError('data.id')
        }
        return result
      } catch (error) {
        if (error instanceof ArchiveImportContractError) {
          throw new ApiError('归档导入响应不符合接口契约', 502, {
            code: 'INVALID_ARCHIVE_IMPORT_RESPONSE',
          })
        }
        throw error
      }
    },
    async listArchiveImportEntries(importId, query = {}) {
      const params = new URLSearchParams()
      if (query.filter) params.set('filter', query.filter)
      if (query.cursor) params.set('cursor', query.cursor)
      if (query.page_size !== undefined) params.set('page_size', String(query.page_size))
      try {
        return parseArchiveImportEntryPage(
          await request<unknown>(
            `/archive-imports/${encode(importId)}/entries${params.size ? `?${params}` : ''}`,
          ),
        )
      } catch (error) {
        if (error instanceof ArchiveImportContractError) {
          throw new ApiError('归档导入响应不符合接口契约', 502, {
            code: 'INVALID_ARCHIVE_IMPORT_RESPONSE',
          })
        }
        throw error
      }
    },
    async createArchiveTaskBatch(importId, input, idempotencyKey) {
      try {
        return parseArchiveTaskBatchResult(
          await request<unknown>(`/archive-imports/${encode(importId)}/task-batches`, {
            method: 'POST',
            body: JSON.stringify(input),
            headers: { 'Idempotency-Key': idempotencyKey },
          }),
          input.entry_ids,
        )
      } catch (error) {
        if (error instanceof ArchiveImportContractError) {
          throw new ApiError('归档导入响应不符合接口契约', 502, {
            code: 'INVALID_ARCHIVE_IMPORT_RESPONSE',
          })
        }
        throw error
      }
    },
    async listArchiveReportBundles(importId) {
      try {
        return parseArchiveReportBundleList(
          await request<unknown>(
            `/archive-imports/${encode(importId)}/report-bundles`,
          ),
        )
      } catch (error) {
        if (error instanceof ArchiveReportBundleContractError) {
          throw new ApiError('归档报告包响应不符合接口契约', 502, {
            code: 'INVALID_ARCHIVE_REPORT_BUNDLE_RESPONSE',
          })
        }
        throw error
      }
    },
    async createArchiveReportBundle(importId, input, idempotencyKey) {
      try {
        return parseArchiveReportBundle(
          await request<unknown>(
            `/archive-imports/${encode(importId)}/report-bundles`,
            {
              method: 'POST',
              body: JSON.stringify(input),
              headers: { 'Idempotency-Key': idempotencyKey },
            },
          ),
        )
      } catch (error) {
        if (error instanceof ArchiveReportBundleContractError) {
          throw new ApiError('归档报告包响应不符合接口契约', 502, {
            code: 'INVALID_ARCHIVE_REPORT_BUNDLE_RESPONSE',
          })
        }
        throw error
      }
    },
    async downloadArchiveReportBundle(bundleId) {
      return {
        kind: 'url',
        url: apiEndpoint(
          `/archive-report-bundles/${encode(bundleId)}/content`,
        ),
      }
    },
    async createTask(input) {
      const session = await client.getUpload(input.upload_id)
      if (!session.task_id) {
        throw new ApiError('上传会话尚未生成任务', 409, {
          code: 'TASK_NOT_READY',
        })
      }
      return { id: session.task_id }
    },
  }
  return client
}
