<script setup lang="ts">
import {
  Activity,
  Archive,
  ArrowLeft,
  Binary,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  CircleGauge,
  Clock3,
  Code2,
  Database,
  FileCode2,
  FileScan,
  FileText,
  FolderCode,
  HardDrive,
  ListChecks,
  LogOut,
  Menu,
  PackageOpen,
  Play,
  Plus,
  RefreshCw,
  ServerCog,
  ShieldCheck,
  Upload,
  Users,
  X,
} from 'lucide-vue-next'
import { computed, onMounted, onUnmounted, ref } from 'vue'

type User = { id: string; username: string; role: string; csrfToken: string }
type Task = { id: string; displayName: string; status: string; detectedFormat?: string; createdAt: string }
type FileNode = { id: string; path: string; kind: string; detectedFormat?: string; sizeBytes: number }
type Run = { id: string; kind: string; status: string; resultQuality?: string; toolName?: string; errorMessage?: string; createdAt: string }
type Project = { id: string; language: string; resultQuality: string; fileCount: number; sizeBytes: number }
type Finding = { id: number; severity: string; ruleId?: string; cwe?: string; path?: string; line?: number; title: string; message: string }
type Report = { id: string; format: string; status: string; createdAt: string }
type TaskDetail = { task: Task; files: FileNode[]; runs: Run[]; projects: Project[] }
type ManagedUser = { id: string; username: string; role: string; active: boolean; createdAt: string; updatedAt: string }
type AuditEntry = { id: number; actorUsername?: string; action: string; objectType?: string; objectId?: string; outcome: string; details?: unknown; createdAt: string }
type ViewName = 'overview' | 'tasks' | 'new' | 'detail' | 'admin'
type DetailTab = 'files' | 'runs' | 'projects' | 'findings' | 'reports'

const version = ref('')
const user = ref<User | null>(null)
const username = ref('')
const password = ref('')
const tasks = ref<Task[]>([])
const selected = ref<TaskDetail | null>(null)
const findings = ref<Finding[]>([])
const reports = ref<Report[]>([])
const selectedRuns = ref<string[]>([])
const uploadFile = ref<File | null>(null)
const view = ref<ViewName>('overview')
const detailTab = ref<DetailTab>('files')
const collapsed = ref(false)
const mobileOpen = ref(false)
const managedUsers = ref<ManagedUser[]>([])
const auditEntries = ref<AuditEntry[]>([])
const createUsername = ref('')
const createPassword = ref('')
const createRole = ref('operator')
const resetPasswords = ref<Record<string, string>>({})
const busy = ref('')
const error = ref('')
let pollTimer: number | undefined

const canOperate = computed(() => user.value?.role !== 'reader')
const roleLabel = computed(() => ({ administrator: '系统管理员', operator: '操作员', reader: '只读用户' }[user.value?.role ?? ''] ?? '当前用户'))
const taskStats = computed(() => {
  const terminal = new Set(['complete', 'partial', 'unsupported', 'failed', 'cancelled'])
  return {
    total: tasks.value.length,
    active: tasks.value.filter(task => !terminal.has(task.status)).length,
    completed: tasks.value.filter(task => ['complete', 'partial'].includes(task.status)).length,
    alerts: tasks.value.filter(task => ['failed', 'unsupported'].includes(task.status)).length,
  }
})

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  const response = await fetch(path, { credentials: 'same-origin', ...options, headers })
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: response.statusText }))
    throw new Error(body.error ?? response.statusText)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

function csrfHeaders(extra: Record<string, string> = {}) { return { 'X-CSRF-Token': user.value?.csrfToken ?? '', ...extra } }
function validPassword(value: string) { const bytes = new TextEncoder().encode(value).length; return bytes >= 8 && bytes <= 72 }
async function loadInfo() { version.value = (await request<{ version: string }>('/api/v1/system/info')).version }

async function loadCurrentUser() {
  try { user.value = (await request<{ user: User }>('/api/v1/auth/me')).user; await loadTasks() } catch { user.value = null }
}

async function login() {
  busy.value = 'login'; error.value = ''
  try {
    user.value = (await request<{ user: User }>('/api/v1/auth/login', { method: 'POST', body: JSON.stringify({ username: username.value, password: password.value }) })).user
    password.value = ''; view.value = 'overview'; await loadTasks()
  } catch (cause) { error.value = messageOf(cause) } finally { busy.value = '' }
}

async function logout() {
  if (!user.value) return
  await request('/api/v1/auth/logout', { method: 'POST', headers: csrfHeaders() })
  user.value = null; selected.value = null; view.value = 'overview'
}

function goTo(next: ViewName) {
  mobileOpen.value = false; error.value = ''
  if (next === 'admin') { void openAdmin(); return }
  view.value = next
}

async function openAdmin() {
  view.value = 'admin'; mobileOpen.value = false; busy.value = 'admin-load'; error.value = ''
  try { await Promise.all([loadManagedUsers(), loadAudit()]) } catch (cause) { error.value = messageOf(cause) } finally { busy.value = '' }
}

async function loadManagedUsers() { managedUsers.value = (await request<{ users: ManagedUser[] }>('/api/v1/admin/users')).users }
async function loadAudit() { auditEntries.value = (await request<{ entries: AuditEntry[] }>('/api/v1/admin/audit?limit=100')).entries }

async function createManagedUser() {
  busy.value = 'admin-create'; error.value = ''
  try {
    await request('/api/v1/admin/users', { method: 'POST', headers: csrfHeaders(), body: JSON.stringify({ username: createUsername.value, password: createPassword.value, role: createRole.value }) })
    createUsername.value = ''; createPassword.value = ''; createRole.value = 'operator'; await Promise.all([loadManagedUsers(), loadAudit()])
  } catch (cause) { error.value = messageOf(cause) } finally { busy.value = '' }
}

async function updateManagedUser(target: ManagedUser, change: { role?: string; active?: boolean; password?: string }) {
  busy.value = `admin-update-${target.id}`; error.value = ''
  try {
    await request(`/api/v1/admin/users/${target.id}`, { method: 'PATCH', headers: csrfHeaders(), body: JSON.stringify(change) })
    resetPasswords.value[target.id] = ''; await Promise.all([loadManagedUsers(), loadAudit()])
  } catch (cause) { error.value = messageOf(cause) } finally { busy.value = '' }
}

async function loadTasks() { if (user.value) tasks.value = (await request<{ tasks: Task[] }>('/api/v1/tasks')).tasks }

async function openTask(taskID: string, quiet = false) {
  if (!quiet) { busy.value = 'detail'; view.value = 'detail'; mobileOpen.value = false }
  try {
    selected.value = await request<TaskDetail>(`/api/v1/tasks/${taskID}`)
    const terminal = selected.value.runs.filter(run => terminalRun(run.status)).map(run => run.id)
    selectedRuns.value = selectedRuns.value.filter(id => terminal.includes(id))
    findings.value = (await request<{ findings: Finding[] }>(`/api/v1/tasks/${taskID}/findings`)).findings
    reports.value = (await request<{ reports: Report[] }>(`/api/v1/tasks/${taskID}/reports`)).reports
  } catch (cause) { if (!quiet) error.value = messageOf(cause) } finally { if (!quiet) busy.value = '' }
}

async function upload() {
  if (!uploadFile.value) return
  busy.value = 'upload'; error.value = ''
  const body = new FormData(); body.append('file', uploadFile.value)
  try {
    const result = await request<{ task: Task }>('/api/v1/tasks', { method: 'POST', headers: csrfHeaders(), body })
    uploadFile.value = null; await loadTasks(); await openTask(result.task.id)
  } catch (cause) { error.value = messageOf(cause) } finally { busy.value = '' }
}

async function decompile(file: FileNode) {
  if (!selected.value) return
  busy.value = `decompile-${file.id}`; error.value = ''
  try {
    await request(`/api/v1/tasks/${selected.value.task.id}/files/${file.id}/decompile`, { method: 'POST', headers: csrfHeaders({ 'Idempotency-Key': crypto.randomUUID() }) })
    await openTask(selected.value.task.id, true)
  } catch (cause) { error.value = messageOf(cause) } finally { busy.value = '' }
}

async function importArchive(file: FileNode) {
  if (!selected.value) return
  busy.value = `archive-${file.id}`; error.value = ''
  try {
    await request(`/api/v1/tasks/${selected.value.task.id}/files/${file.id}/archive-import`, { method: 'POST', headers: csrfHeaders({ 'Idempotency-Key': 'archive-import-v1' }) })
    await openTask(selected.value.task.id, true)
  } catch (cause) { error.value = messageOf(cause) } finally { busy.value = '' }
}

async function runCheck(project: Project) {
  if (!selected.value) return
  busy.value = `check-${project.id}`; error.value = ''
  try {
    await request(`/api/v1/tasks/${selected.value.task.id}/projects/${project.id}/check`, { method: 'POST', headers: csrfHeaders({ 'Idempotency-Key': crypto.randomUUID() }) })
    await openTask(selected.value.task.id, true)
  } catch (cause) { error.value = messageOf(cause) } finally { busy.value = '' }
}

async function createReport(format: 'json' | 'html') {
  if (!selected.value || selectedRuns.value.length === 0) return
  busy.value = 'report'; error.value = ''
  try {
    await request(`/api/v1/tasks/${selected.value.task.id}/reports`, { method: 'POST', headers: csrfHeaders(), body: JSON.stringify({ format, runIds: selectedRuns.value }) })
    await openTask(selected.value.task.id, true)
  } catch (cause) { error.value = messageOf(cause) } finally { busy.value = '' }
}

function onFile(event: Event) { uploadFile.value = (event.target as HTMLInputElement).files?.[0] ?? null }
function canDecompile(format?: string) { return ['pe', 'elf', 'mach-o', 'class', 'jar', 'war', 'ear', 'dex', 'apk', 'pyc'].includes(format ?? '') }
function canImportArchive(format?: string) { return ['zip', 'tar', 'gzip'].includes(format ?? '') }
function terminalRun(status: string) { return ['complete', 'partial', 'unsupported', 'failed', 'cancelled'].includes(status) }
function statusLabel(status: string) { return ({ queued: '排队中', running: '执行中', complete: '已完成', partial: '部分完成', failed: '失败', unsupported: '不支持', cancelled: '已取消', created: '已创建', scanning: '扫描中', ready: '就绪' }[status] ?? status) }
function runKindLabel(kind: string) { return ({ scan: '基础扫描', trivy: 'Trivy 检测', archive_import: '归档导入', decompile: '反编译', check: '源码检查', report: '报告生成' }[kind] ?? kind) }
function qualityLabel(quality?: string) { return ({ source: '源码', decompiled: '反编译源码', partial: '部分源码', bytecode_only: '仅字节码' }[quality ?? ''] ?? quality ?? '—') }
function formatBytes(bytes: number) { if (bytes < 1024) return `${bytes} B`; if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`; if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`; return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB` }
function formatTime(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).format(date) }
function shortID(value: string) { return value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-5)}` : value }
function messageOf(cause: unknown) { return cause instanceof Error ? cause.message : '操作失败' }

onMounted(async () => {
  await Promise.all([loadInfo(), loadCurrentUser()])
  pollTimer = window.setInterval(async () => {
    if (!user.value) return
    await loadTasks().catch(() => undefined)
    if (selected.value) await openTask(selected.value.task.id, true).catch(() => undefined)
  }, 3000)
})
onUnmounted(() => pollTimer && window.clearInterval(pollTimer))
</script>

<template>
  <main v-if="!user" class="login-page">
    <section class="identity-panel" aria-label="系统标识">
      <div class="identity-grid" aria-hidden="true"><span v-for="index in 54" :key="index" :class="{ active: index % 7 === 0 || index % 11 === 0 }" /></div>
      <div class="identity-content">
        <div class="identity-mark"><Binary :size="31" /></div><p class="identity-kicker mono">OFFLINE ANALYSIS CONSOLE</p><h1>BinaryScan</h1><p class="identity-subtitle">离线二进制、归档与镜像检测</p>
        <div class="identity-status"><span><CheckCircle2 :size="15" />服务节点</span><strong>ONLINE</strong></div>
        <div class="identity-meta"><span><HardDrive :size="15" />业务数据仓库</span><span><Database :size="15" />本地任务队列</span></div>
      </div>
    </section>
    <section class="login-panel">
      <form class="login-box" @submit.prevent="login">
        <div class="login-heading"><span class="mono">AUTH / 01</span><h2>登录操作台</h2></div><p class="login-description">使用单位内部账号进入分析工作台。</p>
        <label>用户名<input v-model.trim="username" autocomplete="username" required></label><label>密码<input v-model="password" type="password" autocomplete="current-password" required></label>
        <p v-if="error" class="form-error">{{ error }}</p><button class="primary-button login-submit" :disabled="busy === 'login'">{{ busy === 'login' ? '登录中…' : '登录' }}</button>
        <footer class="login-footer"><span class="status-dot" /><span>单位服务节点</span><strong class="mono">{{ version || 'LOADING' }}</strong></footer>
      </form>
    </section>
  </main>

  <div v-else class="app-shell" :class="{ 'app-shell--collapsed': collapsed }">
    <button class="mobile-menu icon-button" aria-label="打开导航" @click="mobileOpen = true"><Menu :size="20" /></button><div v-if="mobileOpen" class="sidebar-scrim" @click="mobileOpen = false" />
    <aside class="sidebar" :class="{ 'sidebar--mobile-open': mobileOpen }">
      <div class="brand"><span class="brand-mark"><Binary :size="22" /></span><div v-show="!collapsed" class="brand-copy"><strong>BinaryScan</strong><span>二进制安全检测平台</span></div><button class="mobile-close icon-button" aria-label="关闭导航" @click="mobileOpen = false"><X :size="18" /></button></div>
      <div v-show="!collapsed" class="environment"><span class="environment-dot" />OFFLINE / PRIVATE SERVER</div>
      <nav class="primary-nav" aria-label="主导航">
        <button class="nav-item" :class="{ active: view === 'overview' }" :title="collapsed ? '系统概览' : ''" @click="goTo('overview')"><CircleGauge :size="19" /><span v-show="!collapsed">系统概览</span></button>
        <button class="nav-item" :class="{ active: view === 'tasks' || view === 'detail' }" :title="collapsed ? '检测任务' : ''" @click="goTo('tasks')"><FileScan :size="19" /><span v-show="!collapsed">检测任务</span></button>
        <button v-if="canOperate" class="nav-item" :class="{ active: view === 'new' }" :title="collapsed ? '新建任务' : ''" @click="goTo('new')"><Plus :size="19" /><span v-show="!collapsed">新建任务</span></button>
        <button v-if="user.role === 'administrator'" class="nav-item" :class="{ active: view === 'admin' }" :title="collapsed ? '系统维护' : ''" @click="goTo('admin')"><ServerCog :size="19" /><span v-show="!collapsed">系统维护</span></button>
      </nav>
      <div class="sidebar-bottom"><div class="account"><span class="account-avatar">{{ user.username.slice(0, 1).toUpperCase() }}</span><span v-show="!collapsed" class="account-copy"><strong>{{ user.username }}</strong><small>{{ roleLabel }}</small></span><button v-show="!collapsed" class="icon-command" aria-label="退出登录" title="退出登录" @click="logout"><LogOut :size="17" /></button></div><button class="collapse-command" :aria-label="collapsed ? '展开导航' : '收起导航'" @click="collapsed = !collapsed"><ChevronRight v-if="collapsed" :size="17" /><ChevronLeft v-else :size="17" /><span v-show="!collapsed">收起导航</span></button></div>
    </aside>

    <main class="main-area">
      <header class="topbar"><span class="topbar-caption">BINARYSCAN / PRIVATE NODE</span><span class="topbar-version mono">{{ version }}</span></header>
      <div class="content"><div v-if="error" class="global-error"><span>{{ error }}</span><button class="icon-button" aria-label="关闭错误提示" @click="error = ''"><X :size="16" /></button></div>
        <section v-if="view === 'overview'" class="page-view">
          <header class="page-header"><div><span class="page-eyebrow mono">OVERVIEW / NODE</span><h1>系统概览</h1><p>查看当前节点的任务状态与最近活动。</p></div><button class="secondary-button" :disabled="busy !== ''" @click="loadTasks"><RefreshCw :size="16" />刷新数据</button></header>
          <div class="metrics-grid"><article><span class="metric-icon teal"><FileScan :size="19" /></span><div><small>全部任务</small><strong>{{ taskStats.total }}</strong></div></article><article><span class="metric-icon blue"><Activity :size="19" /></span><div><small>处理中</small><strong>{{ taskStats.active }}</strong></div></article><article><span class="metric-icon green"><CheckCircle2 :size="19" /></span><div><small>完成任务</small><strong>{{ taskStats.completed }}</strong></div></article><article><span class="metric-icon amber"><ShieldCheck :size="19" /></span><div><small>需要关注</small><strong>{{ taskStats.alerts }}</strong></div></article></div>
          <section class="surface-panel table-panel"><header class="panel-header"><div><span class="panel-kicker mono">RECENT / TASKS</span><h2>最近检测任务</h2></div><button class="text-button" @click="goTo('tasks')">查看全部 <ChevronRight :size="15" /></button></header>
            <div v-if="tasks.length" class="data-table-wrap"><table class="data-table"><thead><tr><th>任务</th><th>类型</th><th>执行状态</th><th>创建时间</th><th class="action-column">操作</th></tr></thead><tbody><tr v-for="task in tasks.slice(0, 6)" :key="task.id" @click="openTask(task.id)"><td><div class="task-cell"><span class="table-file-icon"><FileCode2 :size="17" /></span><span><strong>{{ task.displayName }}</strong><small class="mono">{{ shortID(task.id) }}</small></span></div></td><td><span class="table-token mono">{{ task.detectedFormat || 'PENDING' }}</span></td><td><span class="status-badge" :class="`status-${task.status}`">{{ statusLabel(task.status) }}</span></td><td class="table-muted">{{ formatTime(task.createdAt) }}</td><td class="action-column"><button class="row-command" aria-label="查看任务" @click.stop="openTask(task.id)"><ChevronRight :size="18" /></button></td></tr></tbody></table></div>
            <div v-else class="empty-panel"><FileScan :size="30" /><strong>暂无检测任务</strong><p>上传文件后，任务会显示在这里。</p><button v-if="canOperate" class="primary-button" @click="goTo('new')"><Plus :size="16" />新建任务</button></div>
          </section>
        </section>

        <section v-else-if="view === 'tasks'" class="page-view">
          <header class="page-header"><div><span class="page-eyebrow mono">TASKS / INDEX</span><h1>检测任务</h1><p>任务上传后先进行基础扫描，后续处理由用户手动触发。</p></div><button v-if="canOperate" class="primary-button" @click="goTo('new')"><Plus :size="16" />新建任务</button></header>
          <section class="surface-panel table-panel"><header class="panel-header compact"><div><span class="panel-kicker mono">TASK LIST</span><h2>全部任务</h2></div><span class="count-label">共 {{ tasks.length }} 个任务</span></header>
            <div v-if="tasks.length" class="data-table-wrap"><table class="data-table"><thead><tr><th>任务</th><th>输入类型</th><th>执行状态</th><th>创建时间</th><th class="action-column">操作</th></tr></thead><tbody><tr v-for="task in tasks" :key="task.id" @click="openTask(task.id)"><td><div class="task-cell"><span class="table-file-icon"><FileCode2 :size="17" /></span><span><strong>{{ task.displayName }}</strong><small class="mono">{{ task.id }}</small></span></div></td><td><span class="table-token mono">{{ task.detectedFormat || 'PENDING' }}</span></td><td><span class="status-badge" :class="`status-${task.status}`">{{ statusLabel(task.status) }}</span></td><td class="table-muted">{{ formatTime(task.createdAt) }}</td><td class="action-column"><button class="row-command" aria-label="查看任务详情" title="查看任务详情" @click.stop="openTask(task.id)"><ChevronRight :size="18" /></button></td></tr></tbody></table></div>
            <div v-else class="empty-panel"><FileScan :size="30" /><strong>当前没有任务</strong><p>创建首个检测任务开始分析。</p></div></section>
        </section>

        <section v-else-if="view === 'new'" class="page-view narrow-page"><header class="page-header"><div><span class="page-eyebrow mono">TASKS / CREATE</span><h1>新建任务</h1><p>上传一个样本；系统不会自动反编译其中的全部文件。</p></div></header>
          <section class="surface-panel upload-panel"><div class="section-title"><span class="section-icon"><Upload :size="20" /></span><div><h2>选择检测样本</h2><p>支持 Native、JVM / Android、Python PYC 以及归档格式。</p></div></div>
            <label class="upload-zone"><input type="file" required @change="onFile"><span class="upload-visual"><PackageOpen :size="34" /></span><strong>{{ uploadFile?.name || '点击选择需要检测的文件' }}</strong><span>{{ uploadFile ? formatBytes(uploadFile.size) : '文件将保存到业务数据目录，并立即创建基础扫描任务' }}</span></label>
            <div class="notice-box"><ShieldCheck :size="18" /><p><strong>交互式处理流程</strong><br>上传后仅执行基础识别和扫描。归档导入、反编译、源码检查与报告生成仍需在任务详情中手动选择。</p></div><div class="form-actions"><button class="secondary-button" @click="goTo('tasks')">取消</button><button class="primary-button" :disabled="!uploadFile || busy === 'upload'" @click="upload"><Upload :size="16" />{{ busy === 'upload' ? '上传中…' : '上传并创建任务' }}</button></div>
          </section>
        </section>

        <section v-else-if="view === 'detail'" class="page-view"><template v-if="selected">
          <header class="page-header detail-header"><div><button class="back-link" @click="goTo('tasks')"><ArrowLeft :size="15" />返回任务列表</button><span class="page-eyebrow mono">TASK / {{ shortID(selected.task.id) }}</span><h1>{{ selected.task.displayName }}</h1><p>创建于 {{ formatTime(selected.task.createdAt) }}</p></div><span class="status-badge large" :class="`status-${selected.task.status}`">{{ statusLabel(selected.task.status) }}</span></header>
          <div class="detail-summary"><div><small>输入类型</small><strong class="mono">{{ selected.task.detectedFormat || 'PENDING' }}</strong></div><div><small>文件数量</small><strong>{{ selected.files.length }}</strong></div><div><small>运行记录</small><strong>{{ selected.runs.length }}</strong></div><div><small>源码项目</small><strong>{{ selected.projects.length }}</strong></div><div><small>安全发现</small><strong>{{ findings.length }}</strong></div></div>
          <section class="surface-panel detail-panel"><nav class="detail-tabs" aria-label="任务详情分类"><button :class="{ active: detailTab === 'files' }" @click="detailTab = 'files'"><FileCode2 :size="16" />文件 <span>{{ selected.files.length }}</span></button><button :class="{ active: detailTab === 'runs' }" @click="detailTab = 'runs'"><Activity :size="16" />运行记录 <span>{{ selected.runs.length }}</span></button><button :class="{ active: detailTab === 'projects' }" @click="detailTab = 'projects'"><FolderCode :size="16" />源码项目 <span>{{ selected.projects.length }}</span></button><button :class="{ active: detailTab === 'findings' }" @click="detailTab = 'findings'"><ListChecks :size="16" />安全发现 <span>{{ findings.length }}</span></button><button :class="{ active: detailTab === 'reports' }" @click="detailTab = 'reports'"><FileText :size="16" />报告 <span>{{ reports.length }}</span></button></nav>
            <div v-if="detailTab === 'files'" class="tab-content"><header class="content-header"><div><h2>任务文件</h2><p>从需要处理的文件右侧手动发起归档导入或反编译。</p></div></header><div v-if="selected.files.length" class="data-table-wrap"><table class="data-table"><thead><tr><th>路径</th><th>类型</th><th>大小</th><th>处理能力</th><th class="action-wide">操作</th></tr></thead><tbody><tr v-for="file in selected.files" :key="file.id"><td><div class="task-cell"><span class="table-file-icon"><FileCode2 :size="17" /></span><span><strong>{{ file.path }}</strong><small>{{ file.kind }}</small></span></div></td><td><span class="table-token mono">{{ file.detectedFormat || 'UNKNOWN' }}</span></td><td class="table-muted mono">{{ formatBytes(file.sizeBytes) }}</td><td class="table-muted">{{ canImportArchive(file.detectedFormat) ? '归档导入' : canDecompile(file.detectedFormat) ? '反编译' : '基础扫描' }}</td><td class="action-wide"><div class="inline-actions"><button v-if="canOperate && canImportArchive(file.detectedFormat)" class="small-button" :disabled="busy === `archive-${file.id}`" @click="importArchive(file)"><Archive :size="14" />导入归档</button><button v-if="canOperate && canDecompile(file.detectedFormat)" class="small-button" :disabled="busy === `decompile-${file.id}`" @click="decompile(file)"><Code2 :size="14" />反编译</button><span v-if="!canImportArchive(file.detectedFormat) && !canDecompile(file.detectedFormat)" class="table-muted">—</span></div></td></tr></tbody></table></div><div v-else class="empty-panel small"><FileCode2 :size="26" /><strong>暂无文件记录</strong></div></div>
            <div v-else-if="detailTab === 'runs'" class="tab-content"><header class="content-header"><div><h2>运行记录</h2><p>终态运行可以勾选并用于生成报告。</p></div><span class="count-label">已选择 {{ selectedRuns.length }} 项</span></header><div v-if="selected.runs.length" class="data-table-wrap"><table class="data-table"><thead><tr><th class="check-column">选择</th><th>流程</th><th>工具</th><th>结果质量</th><th>状态</th><th>创建时间</th></tr></thead><tbody><tr v-for="run in selected.runs" :key="run.id"><td class="check-column"><input v-if="terminalRun(run.status)" v-model="selectedRuns" type="checkbox" :value="run.id"><span v-else>—</span></td><td><strong>{{ runKindLabel(run.kind) }}</strong><small v-if="run.errorMessage" class="row-error">{{ run.errorMessage }}</small></td><td class="table-muted">{{ run.toolName || '等待 worker' }}</td><td><span class="table-token">{{ qualityLabel(run.resultQuality) }}</span></td><td><span class="status-badge" :class="`status-${run.status}`">{{ statusLabel(run.status) }}</span></td><td class="table-muted">{{ formatTime(run.createdAt) }}</td></tr></tbody></table></div><div v-else class="empty-panel small"><Activity :size="26" /><strong>暂无运行记录</strong></div></div>
            <div v-else-if="detailTab === 'projects'" class="tab-content"><header class="content-header"><div><h2>源码项目</h2><p>反编译产物会统一形成源码项目，再由对应 checker 检查。</p></div></header><div v-if="selected.projects.length" class="data-table-wrap"><table class="data-table"><thead><tr><th>语言</th><th>结果质量</th><th>文件数</th><th>大小</th><th class="action-wide">操作</th></tr></thead><tbody><tr v-for="project in selected.projects" :key="project.id"><td><div class="task-cell"><span class="table-file-icon"><FolderCode :size="17" /></span><span><strong>{{ project.language.toUpperCase() }}</strong><small class="mono">{{ shortID(project.id) }}</small></span></div></td><td><span class="table-token">{{ qualityLabel(project.resultQuality) }}</span></td><td class="table-muted">{{ project.fileCount }}</td><td class="table-muted mono">{{ formatBytes(project.sizeBytes) }}</td><td class="action-wide"><button v-if="canOperate" class="small-button" :disabled="project.resultQuality === 'bytecode_only' || busy === `check-${project.id}`" @click="runCheck(project)"><Play :size="14" />运行检查</button></td></tr></tbody></table></div><div v-else class="empty-panel small"><FolderCode :size="26" /><strong>暂无源码项目</strong><p>选择支持的文件手动反编译后，项目会显示在这里。</p></div></div>
            <div v-else-if="detailTab === 'findings'" class="tab-content"><header class="content-header"><div><h2>安全发现</h2><p>这里展示已经持久化的检测证据，不包含未执行的检查。</p></div></header><div v-if="findings.length" class="finding-list"><article v-for="finding in findings" :key="finding.id"><span class="severity-badge" :class="`severity-${finding.severity}`">{{ finding.severity }}</span><div><strong>{{ finding.ruleId || finding.cwe || 'Finding' }} · {{ finding.title }}</strong><small>{{ finding.path || '任务级' }}<template v-if="finding.line">:{{ finding.line }}</template></small><p>{{ finding.message }}</p></div></article></div><div v-else class="empty-panel small"><ShieldCheck :size="26" /><strong>当前没有安全发现</strong><p>运行源码检查后，结果会显示在这里。</p></div></div>
            <div v-else class="tab-content"><header class="content-header"><div><h2>检测报告</h2><p>先在“运行记录”中选择终态运行，再生成所需格式。</p></div><div v-if="canOperate" class="inline-actions"><button class="small-button" :disabled="selectedRuns.length === 0 || busy === 'report'" @click="createReport('json')"><FileText :size="14" />生成 JSON</button><button class="primary-button small" :disabled="selectedRuns.length === 0 || busy === 'report'" @click="createReport('html')"><FileText :size="14" />生成 HTML</button></div></header><div class="selection-notice"><ListChecks :size="17" /><span>已选择 <strong>{{ selectedRuns.length }}</strong> 个终态运行</span><button class="text-button" @click="detailTab = 'runs'">调整选择</button></div><div v-if="reports.length" class="report-list"><a v-for="report in reports" :key="report.id" :href="`/api/v1/reports/${report.id}/content`"><span class="report-icon"><FileText :size="18" /></span><span><strong>{{ report.format.toUpperCase() }} 检测报告</strong><small>{{ formatTime(report.createdAt) }} · {{ statusLabel(report.status) }}</small></span><ChevronRight :size="17" /></a></div><div v-else class="empty-panel small"><FileText :size="26" /><strong>暂无检测报告</strong></div></div>
          </section></template><div v-else class="surface-panel empty-panel loading"><Activity :size="28" /><strong>{{ busy === 'detail' ? '正在加载任务…' : '未选择任务' }}</strong></div>
        </section>

        <section v-else class="page-view"><header class="page-header"><div><span class="page-eyebrow mono">SYSTEM / MAINTENANCE</span><h1>系统维护</h1><p>管理单位内部账号，并查看最近审计事件。</p></div><button class="secondary-button" :disabled="busy === 'admin-load'" @click="openAdmin"><RefreshCw :size="16" />刷新</button></header>
          <div class="admin-layout"><section class="surface-panel form-panel"><div class="section-title"><span class="section-icon"><Users :size="20" /></span><div><h2>创建用户</h2><p>账号创建后可以直接登录使用。</p></div></div><form class="stack-form" @submit.prevent="createManagedUser"><label>用户名<input v-model.trim="createUsername" minlength="3" maxlength="64" pattern="[a-z0-9][a-z0-9._-]{2,63}" autocomplete="off" required></label><label>初始密码<input v-model="createPassword" type="password" autocomplete="new-password" required></label><label>角色<select v-model="createRole"><option value="reader">只读用户</option><option value="operator">操作员</option><option value="administrator">管理员</option></select></label><p class="field-hint">密码须为 8–72 个 UTF-8 字节；用户名会统一转为小写。</p><button class="primary-button" :disabled="busy === 'admin-create' || !validPassword(createPassword)">创建用户</button></form></section>
            <section class="surface-panel users-panel"><header class="panel-header compact"><div><span class="panel-kicker mono">ACCESS / USERS</span><h2>账号与角色</h2></div><span class="count-label">{{ managedUsers.length }} 个账号</span></header><div class="user-list"><article v-for="target in managedUsers" :key="target.id"><div class="user-summary"><span class="account-avatar light">{{ target.username.slice(0, 1).toUpperCase() }}</span><span><strong>{{ target.username }}</strong><small>{{ target.active ? '已启用' : '已停用' }}</small></span><span class="role-token">{{ { administrator: '管理员', operator: '操作员', reader: '只读用户' }[target.role] || target.role }}</span></div><div class="user-actions"><label>角色<select :value="target.role" :disabled="target.id === user.id || busy === `admin-update-${target.id}`" @change="updateManagedUser(target, { role: ($event.target as HTMLSelectElement).value })"><option value="reader">只读用户</option><option value="operator">操作员</option><option value="administrator">管理员</option></select></label><button class="small-button" :disabled="target.id === user.id || busy === `admin-update-${target.id}`" @click="updateManagedUser(target, { active: !target.active })">{{ target.active ? '停用账号' : '启用账号' }}</button><label class="reset-field">重置密码<input v-model="resetPasswords[target.id]" type="password" autocomplete="new-password" placeholder="输入新密码" :disabled="target.id === user.id"></label><button class="small-button" :disabled="target.id === user.id || !validPassword(resetPasswords[target.id] ?? '') || busy === `admin-update-${target.id}`" @click="updateManagedUser(target, { password: resetPasswords[target.id] })">重置</button></div></article><div v-if="!managedUsers.length" class="empty-panel small"><Users :size="26" /><strong>{{ busy === 'admin-load' ? '正在加载…' : '暂无用户' }}</strong></div></div></section></div>
          <section class="surface-panel audit-panel"><header class="panel-header compact"><div><span class="panel-kicker mono">AUDIT / RECENT</span><h2>最近审计事件</h2></div><span class="count-label">最近 {{ auditEntries.length }} 条</span></header><div v-if="auditEntries.length" class="data-table-wrap"><table class="data-table"><thead><tr><th>结果</th><th>事件</th><th>操作者</th><th>对象</th><th>时间</th></tr></thead><tbody><tr v-for="entry in auditEntries" :key="entry.id"><td><span class="status-badge" :class="entry.outcome === 'success' ? 'status-complete' : 'status-failed'">{{ entry.outcome }}</span></td><td><strong>{{ entry.action }}</strong></td><td class="table-muted">{{ entry.actorUsername || 'system' }}</td><td class="table-muted mono">{{ entry.objectType || 'system' }}<template v-if="entry.objectId">/{{ shortID(entry.objectId) }}</template></td><td class="table-muted">{{ formatTime(entry.createdAt) }}</td></tr></tbody></table></div><div v-else class="empty-panel small"><Clock3 :size="26" /><strong>暂无审计事件</strong></div></section>
        </section>
      </div>
    </main>
  </div>
</template>
