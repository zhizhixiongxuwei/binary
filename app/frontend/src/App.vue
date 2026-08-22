<script setup lang="ts">
import { onMounted, ref } from 'vue'

type User = {
  id: string
  username: string
  role: string
  mustChangePassword: boolean
  csrfToken: string
}

const version = ref('')
const user = ref<User | null>(null)
const username = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(options?.headers ?? {}) },
    ...options,
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: response.statusText }))
    throw new Error(body.error ?? response.statusText)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

async function loadInfo() {
  const result = await request<{ version: string }>('/api/v1/system/info')
  version.value = result.version
}

async function loadCurrentUser() {
  try {
    const result = await request<{ user: User }>('/api/v1/auth/me')
    user.value = result.user
  } catch {
    user.value = null
  }
}

async function login() {
  loading.value = true
  error.value = ''
  try {
    const result = await request<{ user: User }>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: username.value, password: password.value }),
    })
    user.value = result.user
    password.value = ''
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : '登录失败'
  } finally {
    loading.value = false
  }
}

async function logout() {
  if (!user.value) return
  await request('/api/v1/auth/logout', {
    method: 'POST',
    headers: { 'X-CSRF-Token': user.value.csrfToken },
  })
  user.value = null
}

onMounted(async () => {
  await Promise.all([loadInfo(), loadCurrentUser()])
})
</script>

<template>
  <main class="shell">
    <header class="masthead">
      <div>
        <p class="eyebrow">Binary analysis workspace</p>
        <h1>BinaryScan</h1>
      </div>
      <span class="version">{{ version || 'loading' }}</span>
    </header>

    <section v-if="!user" class="panel login-panel">
      <div>
        <p class="section-label">单位内部系统</p>
        <h2>登录工作台</h2>
        <p class="muted">上传后只执行基础扫描。反编译、源码检查和报告均由用户手动触发。</p>
      </div>
      <form class="login-form" @submit.prevent="login">
        <label>
          用户名
          <input v-model.trim="username" autocomplete="username" required>
        </label>
        <label>
          密码
          <input v-model="password" type="password" autocomplete="current-password" required>
        </label>
        <p v-if="error" class="error">{{ error }}</p>
        <button :disabled="loading">{{ loading ? '登录中…' : '登录' }}</button>
      </form>
    </section>

    <section v-else class="panel workspace-panel">
      <div>
        <p class="section-label">当前用户</p>
        <h2>{{ user.username }}</h2>
        <p class="muted">角色：{{ user.role }}</p>
        <p v-if="user.mustChangePassword" class="notice">首次登录必须先修改初始密码。</p>
      </div>
      <div class="actions">
        <span class="status"><i></i> 基础服务已连接</span>
        <button class="secondary" @click="logout">退出</button>
      </div>
    </section>

    <footer>Native · JVM/Android · Python PYC</footer>
  </main>
</template>
