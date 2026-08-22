<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'

type User = { id: string; username: string; role: string; mustChangePassword: boolean; csrfToken: string }
type Task = { id: string; displayName: string; status: string; detectedFormat?: string; createdAt: string }
type FileNode = { id: string; path: string; kind: string; detectedFormat?: string; sizeBytes: number }
type Run = { id: string; kind: string; status: string; resultQuality?: string; toolName?: string; errorMessage?: string; createdAt: string }
type Project = { id: string; language: string; resultQuality: string; fileCount: number; sizeBytes: number }
type Finding = { id: number; severity: string; ruleId?: string; cwe?: string; path?: string; line?: number; title: string; message: string }
type Report = { id: string; format: string; status: string; createdAt: string }
type TaskDetail = { task: Task; files: FileNode[]; runs: Run[]; projects: Project[] }
type ManagedUser = { id: string; username: string; role: string; active: boolean; mustChangePassword: boolean; createdAt: string; updatedAt: string }
type AuditEntry = { id: number; actorUsername?: string; action: string; objectType?: string; objectId?: string; outcome: string; details?: unknown; createdAt: string }

const version = ref('')
const user = ref<User | null>(null)
const username = ref('')
const password = ref('')
const currentPassword = ref('')
const newPassword = ref('')
const tasks = ref<Task[]>([])
const selected = ref<TaskDetail | null>(null)
const findings = ref<Finding[]>([])
const reports = ref<Report[]>([])
const selectedRuns = ref<string[]>([])
const uploadFile = ref<File | null>(null)
const view = ref<'workspace' | 'admin'>('workspace')
const managedUsers = ref<ManagedUser[]>([])
const auditEntries = ref<AuditEntry[]>([])
const createUsername = ref('')
const createPassword = ref('')
const createRole = ref('operator')
const resetPasswords = ref<Record<string, string>>({})
const busy = ref('')
const error = ref('')
let pollTimer: number | undefined

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  const response = await fetch(path, { credentials: 'same-origin', ...options, headers })
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: response.statusText }))
    throw new Error(body.error ?? response.statusText)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

function csrfHeaders(extra: Record<string, string> = {}) {
  return { 'X-CSRF-Token': user.value?.csrfToken ?? '', ...extra }
}

function validPassword(value: string) {
  const bytes = new TextEncoder().encode(value).length
  return bytes >= 12 && bytes <= 72
}

async function loadInfo() {
  version.value = (await request<{ version: string }>('/api/v1/system/info')).version
}

async function loadCurrentUser() {
  try {
    user.value = (await request<{ user: User }>('/api/v1/auth/me')).user
    await loadTasks()
  } catch {
    user.value = null
  }
}

async function login() {
  busy.value = 'login'
  error.value = ''
  try {
    user.value = (await request<{ user: User }>('/api/v1/auth/login', {
      method: 'POST', body: JSON.stringify({ username: username.value, password: password.value }),
    })).user
    password.value = ''
    await loadTasks()
  } catch (cause) {
    error.value = messageOf(cause)
  } finally {
    busy.value = ''
  }
}

async function changePassword() {
  busy.value = 'password'
  error.value = ''
  try {
    await request('/api/v1/auth/password', {
      method: 'POST', headers: csrfHeaders(),
      body: JSON.stringify({ currentPassword: currentPassword.value, newPassword: newPassword.value }),
    })
    user.value = null
    currentPassword.value = ''
    newPassword.value = ''
  } catch (cause) {
    error.value = messageOf(cause)
  } finally {
    busy.value = ''
  }
}

async function logout() {
  if (!user.value) return
  await request('/api/v1/auth/logout', { method: 'POST', headers: csrfHeaders() })
  user.value = null
  selected.value = null
  view.value = 'workspace'
}

async function openAdmin() {
  view.value = 'admin'
  busy.value = 'admin-load'
  error.value = ''
  try {
    await Promise.all([loadManagedUsers(), loadAudit()])
  } catch (cause) {
    error.value = messageOf(cause)
  } finally {
    busy.value = ''
  }
}

async function loadManagedUsers() {
  managedUsers.value = (await request<{ users: ManagedUser[] }>('/api/v1/admin/users')).users
}

async function loadAudit() {
  auditEntries.value = (await request<{ entries: AuditEntry[] }>('/api/v1/admin/audit?limit=100')).entries
}

async function createManagedUser() {
  busy.value = 'admin-create'
  error.value = ''
  try {
    await request('/api/v1/admin/users', {
      method: 'POST', headers: csrfHeaders(),
      body: JSON.stringify({ username: createUsername.value, password: createPassword.value, role: createRole.value }),
    })
    createUsername.value = ''
    createPassword.value = ''
    createRole.value = 'operator'
    await Promise.all([loadManagedUsers(), loadAudit()])
  } catch (cause) {
    error.value = messageOf(cause)
  } finally {
    busy.value = ''
  }
}

async function updateManagedUser(target: ManagedUser, change: { role?: string; active?: boolean; password?: string }) {
  busy.value = `admin-update-${target.id}`
  error.value = ''
  try {
    await request(`/api/v1/admin/users/${target.id}`, {
      method: 'PATCH', headers: csrfHeaders(), body: JSON.stringify(change),
    })
    resetPasswords.value[target.id] = ''
    await Promise.all([loadManagedUsers(), loadAudit()])
  } catch (cause) {
    error.value = messageOf(cause)
  } finally {
    busy.value = ''
  }
}

async function loadTasks() {
  if (!user.value) return
  tasks.value = (await request<{ tasks: Task[] }>('/api/v1/tasks')).tasks
}

async function openTask(taskID: string, quiet = false) {
  if (!quiet) busy.value = 'detail'
  try {
    selected.value = await request<TaskDetail>(`/api/v1/tasks/${taskID}`)
    const terminal = selected.value.runs.filter(run => terminalRun(run.status)).map(run => run.id)
    selectedRuns.value = selectedRuns.value.filter(id => terminal.includes(id))
    findings.value = (await request<{ findings: Finding[] }>(`/api/v1/tasks/${taskID}/findings`)).findings
    reports.value = (await request<{ reports: Report[] }>(`/api/v1/tasks/${taskID}/reports`)).reports
  } finally {
    if (!quiet) busy.value = ''
  }
}

async function upload() {
  if (!uploadFile.value) return
  busy.value = 'upload'
  error.value = ''
  const body = new FormData()
  body.append('file', uploadFile.value)
  try {
    const result = await request<{ task: Task }>('/api/v1/tasks', {
      method: 'POST', headers: csrfHeaders(), body,
    })
    uploadFile.value = null
    await loadTasks()
    await openTask(result.task.id)
  } catch (cause) {
    error.value = messageOf(cause)
  } finally {
    busy.value = ''
  }
}

async function decompile(file: FileNode) {
  if (!selected.value) return
  busy.value = `decompile-${file.id}`
  error.value = ''
  try {
    await request(`/api/v1/tasks/${selected.value.task.id}/files/${file.id}/decompile`, {
      method: 'POST', headers: csrfHeaders({ 'Idempotency-Key': crypto.randomUUID() }),
    })
    await openTask(selected.value.task.id, true)
  } catch (cause) {
    error.value = messageOf(cause)
  } finally {
    busy.value = ''
  }
}

async function importArchive(file: FileNode) {
  if (!selected.value) return
  busy.value = `archive-${file.id}`
  error.value = ''
  try {
    await request(`/api/v1/tasks/${selected.value.task.id}/files/${file.id}/archive-import`, {
      method: 'POST', headers: csrfHeaders({ 'Idempotency-Key': 'archive-import-v1' }),
    })
    await openTask(selected.value.task.id, true)
  } catch (cause) {
    error.value = messageOf(cause)
  } finally {
    busy.value = ''
  }
}

async function runCheck(project: Project) {
  if (!selected.value) return
  busy.value = `check-${project.id}`
  error.value = ''
  try {
    await request(`/api/v1/tasks/${selected.value.task.id}/projects/${project.id}/check`, {
      method: 'POST', headers: csrfHeaders({ 'Idempotency-Key': crypto.randomUUID() }),
    })
    await openTask(selected.value.task.id, true)
  } catch (cause) {
    error.value = messageOf(cause)
  } finally {
    busy.value = ''
  }
}

async function createReport(format: 'json' | 'html') {
  if (!selected.value || selectedRuns.value.length === 0) return
  busy.value = 'report'
  error.value = ''
  try {
    await request(`/api/v1/tasks/${selected.value.task.id}/reports`, {
      method: 'POST', headers: csrfHeaders(),
      body: JSON.stringify({ format, runIds: selectedRuns.value }),
    })
    await openTask(selected.value.task.id, true)
  } catch (cause) {
    error.value = messageOf(cause)
  } finally {
    busy.value = ''
  }
}

function onFile(event: Event) {
  uploadFile.value = (event.target as HTMLInputElement).files?.[0] ?? null
}

function canDecompile(format?: string) {
  return ['pe', 'elf', 'mach-o', 'class', 'jar', 'war', 'ear', 'dex', 'apk', 'pyc'].includes(format ?? '')
}

function canImportArchive(format?: string) {
  return ['zip', 'tar', 'gzip'].includes(format ?? '')
}

function terminalRun(status: string) {
  return ['complete', 'partial', 'unsupported', 'failed', 'cancelled'].includes(status)
}

function messageOf(cause: unknown) {
  return cause instanceof Error ? cause.message : '操作失败'
}

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
  <main class="shell">
    <header class="masthead">
      <div><p class="eyebrow">Binary analysis workspace</p><h1>BinaryScan</h1></div>
      <div class="header-actions"><span class="version">{{ version || 'loading' }}</span><button v-if="user && !user.mustChangePassword" class="ghost" :class="{ active: view === 'workspace' }" @click="view = 'workspace'">工作台</button><button v-if="user?.role === 'administrator' && !user.mustChangePassword" class="ghost" :class="{ active: view === 'admin' }" @click="openAdmin">管理</button><button v-if="user" class="ghost" @click="logout">退出</button></div>
    </header>

    <section v-if="!user" class="panel login-panel">
      <div><p class="section-label">单位内部系统</p><h2>登录工作台</h2><p class="muted">上传后只执行基础扫描。反编译、源码检查和报告均由用户手动触发。</p></div>
      <form class="login-form" @submit.prevent="login">
        <label>用户名<input v-model.trim="username" autocomplete="username" required></label>
        <label>密码<input v-model="password" type="password" autocomplete="current-password" required></label>
        <p v-if="error" class="error">{{ error }}</p>
        <button :disabled="busy === 'login'">{{ busy === 'login' ? '登录中…' : '登录' }}</button>
      </form>
    </section>

    <section v-else-if="user.mustChangePassword" class="panel login-panel">
      <div><p class="section-label">首次登录</p><h2>修改初始密码</h2><p class="muted">修改后所有现有会话会失效，请使用新密码重新登录。</p></div>
      <form class="login-form" @submit.prevent="changePassword">
        <label>当前密码<input v-model="currentPassword" type="password" required></label>
        <label>新密码<input v-model="newPassword" type="password" required></label>
        <small>UTF-8 编码后须为 12–72 字节。</small>
        <p v-if="error" class="error">{{ error }}</p>
        <button :disabled="busy === 'password' || !validPassword(newPassword)">保存新密码</button>
      </form>
    </section>

    <template v-else>
      <p v-if="error" class="error global-error">{{ error }}</p>
      <section v-if="view === 'workspace'" class="workspace-grid">
        <aside class="panel task-sidebar">
          <div><p class="section-label">分析任务</p><h2>文件工作区</h2></div>
          <form class="upload" @submit.prevent="upload">
            <input type="file" required @change="onFile">
            <button :disabled="!uploadFile || busy === 'upload'">{{ busy === 'upload' ? '上传中…' : '上传并扫描' }}</button>
          </form>
          <button v-for="task in tasks" :key="task.id" class="task-row" :class="{ active: selected?.task.id === task.id }" @click="openTask(task.id)">
            <span>{{ task.displayName }}</span><small>{{ task.detectedFormat || '待识别' }} · {{ task.status }}</small>
          </button>
          <p v-if="tasks.length === 0" class="muted empty">暂无任务</p>
        </aside>

        <section v-if="selected" class="panel detail">
          <div class="detail-title"><div><p class="section-label">{{ selected.task.detectedFormat || '识别中' }}</p><h2>{{ selected.task.displayName }}</h2></div><span class="status-pill">{{ selected.task.status }}</span></div>
          <h3>文件</h3>
          <div class="data-list"><div v-for="file in selected.files" :key="file.id" class="data-row"><div><strong>{{ file.path }}</strong><small>{{ file.detectedFormat || 'unknown' }} · {{ file.sizeBytes }} bytes</small></div><div class="row-actions"><button v-if="canImportArchive(file.detectedFormat)" class="secondary" :disabled="busy === `archive-${file.id}`" @click="importArchive(file)">手动导入归档</button><button v-if="canDecompile(file.detectedFormat)" class="secondary" :disabled="busy === `decompile-${file.id}`" @click="decompile(file)">手动反编译</button></div></div></div>
          <h3>运行记录</h3>
          <div class="data-list"><label v-for="run in selected.runs" :key="run.id" class="data-row run-row"><input v-if="terminalRun(run.status)" v-model="selectedRuns" type="checkbox" :value="run.id"><span v-else class="checkbox-placeholder"></span><div><strong>{{ run.kind }}</strong><small>{{ run.toolName || '等待 worker' }} · {{ run.status }}<template v-if="run.errorMessage"> · {{ run.errorMessage }}</template></small></div></label></div>
          <h3>源码项目</h3>
          <div class="data-list"><div v-for="project in selected.projects" :key="project.id" class="data-row"><div><strong>{{ project.language.toUpperCase() }}</strong><small>{{ project.resultQuality }} · {{ project.fileCount }} files</small></div><button class="secondary" :disabled="project.resultQuality === 'bytecode_only' || busy === `check-${project.id}`" @click="runCheck(project)">手动检查</button></div><p v-if="selected.projects.length === 0" class="muted empty">反编译完成后会在这里出现源码项目。</p></div>
          <h3>发现</h3>
          <div class="data-list findings"><div v-for="finding in findings" :key="finding.id" class="data-row finding-row"><span class="severity" :class="finding.severity">{{ finding.severity }}</span><div><strong>{{ finding.ruleId || finding.cwe || 'Finding' }} · {{ finding.title }}</strong><small>{{ finding.path || '任务级' }}<template v-if="finding.line">:{{ finding.line }}</template> · {{ finding.message }}</small></div></div><p v-if="findings.length === 0" class="muted empty">当前任务没有持久化 finding。</p></div>
          <div class="report-bar"><span>已选择 {{ selectedRuns.length }} 个终态运行</span><button class="secondary" :disabled="selectedRuns.length === 0 || busy === 'report'" @click="createReport('json')">生成 JSON</button><button class="secondary" :disabled="selectedRuns.length === 0 || busy === 'report'" @click="createReport('html')">生成 HTML</button></div>
          <div class="report-links"><a v-for="report in reports" :key="report.id" :href="`/api/v1/reports/${report.id}/content`">{{ report.format.toUpperCase() }} · {{ report.createdAt }}</a></div>
        </section>
        <section v-else class="panel detail empty-state"><h2>选择一个任务</h2><p class="muted">任务详情、手动处理入口和报告选择会显示在这里。</p></section>
      </section>

      <section v-else class="admin-grid">
        <section class="panel admin-card">
          <p class="section-label">访问控制</p><h2>创建用户</h2>
          <form class="admin-form" @submit.prevent="createManagedUser">
            <label>用户名<input v-model.trim="createUsername" minlength="3" maxlength="64" pattern="[a-z0-9][a-z0-9._-]{2,63}" autocomplete="off" required></label>
            <label>初始密码<input v-model="createPassword" type="password" autocomplete="new-password" required></label>
            <label>角色<select v-model="createRole"><option value="reader">只读用户</option><option value="operator">操作员</option><option value="administrator">管理员</option></select></label>
            <small>密码须为 12–72 个 UTF-8 字节，新用户首次登录必须修改密码。用户名会统一转为小写。</small>
            <button :disabled="busy === 'admin-create' || !validPassword(createPassword)">{{ busy === 'admin-create' ? '创建中…' : '创建用户' }}</button>
          </form>
        </section>

        <section class="panel admin-card admin-users">
          <div class="detail-title"><div><p class="section-label">用户管理</p><h2>账号与角色</h2></div><span class="status-pill">{{ managedUsers.length }} 个账号</span></div>
          <div class="data-list">
            <div v-for="target in managedUsers" :key="target.id" class="admin-user-row">
              <div class="admin-user-title"><div><strong>{{ target.username }}</strong><small>{{ target.active ? '已启用' : '已停用' }}<template v-if="target.mustChangePassword"> · 待修改密码</template></small></div><span class="status-pill">{{ target.role }}</span></div>
              <div class="admin-user-actions">
                <label>角色<select :value="target.role" :disabled="target.id === user.id || busy === `admin-update-${target.id}`" @change="updateManagedUser(target, { role: ($event.target as HTMLSelectElement).value })"><option value="reader">只读用户</option><option value="operator">操作员</option><option value="administrator">管理员</option></select></label>
                <button class="secondary" :disabled="target.id === user.id || busy === `admin-update-${target.id}`" @click="updateManagedUser(target, { active: !target.active })">{{ target.active ? '停用' : '启用' }}</button>
                <label>重置密码<input v-model="resetPasswords[target.id]" type="password" autocomplete="new-password" placeholder="12–72 个 UTF-8 字节" :disabled="target.id === user.id"></label>
                <button class="secondary" :disabled="target.id === user.id || !validPassword(resetPasswords[target.id] ?? '') || busy === `admin-update-${target.id}`" @click="updateManagedUser(target, { password: resetPasswords[target.id] })">重置</button>
              </div>
            </div>
            <p v-if="managedUsers.length === 0" class="muted empty">{{ busy === 'admin-load' ? '加载中…' : '暂无用户' }}</p>
          </div>
        </section>

        <section class="panel admin-card admin-audit">
          <div class="detail-title"><div><p class="section-label">不可变记录</p><h2>最近审计事件</h2></div><button class="ghost" @click="loadAudit">刷新</button></div>
          <div class="data-list"><div v-for="entry in auditEntries" :key="entry.id" class="data-row audit-row"><span class="severity" :class="entry.outcome === 'success' ? 'success' : 'high'">{{ entry.outcome }}</span><div><strong>{{ entry.action }}</strong><small>{{ entry.actorUsername || 'system' }} · {{ entry.objectType || 'system' }}<template v-if="entry.objectId">/{{ entry.objectId }}</template> · {{ entry.createdAt }}</small></div></div><p v-if="auditEntries.length === 0" class="muted empty">暂无审计事件。</p></div>
        </section>
      </section>
    </template>
    <footer>Native · JVM/Android · Python PYC</footer>
  </main>
</template>
