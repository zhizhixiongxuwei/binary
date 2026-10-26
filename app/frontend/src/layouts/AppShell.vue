<script setup lang="ts">
import {
  Binary,
  Archive,
  ChevronLeft,
  ChevronRight,
  CircleGauge,
  FileScan,
  KeyRound,
  LogOut,
  Menu,
  Plus,
  ServerCog,
  X,
} from 'lucide-vue-next'
import {
  computed,
  nextTick,
  onMounted,
  onScopeDispose,
  shallowRef,
  useTemplateRef,
  watch,
} from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { ApiError } from '@/api/client'
import LogoutErrorAlert from '@/components/auth/LogoutErrorAlert.vue'
import { useTaskCreationLauncher } from '@/composables/useTaskCreationLauncher'
import {
  PRODUCT_DESCRIPTION,
  PRODUCT_NAME,
  PRODUCT_SHORT_NAME,
} from '@/config/branding'
import { useSessionStore } from '@/stores/session'

const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const { launchTaskCreation } = useTaskCreationLauncher()
const collapsed = shallowRef(false)
const mobileOpen = shallowRef(false)
const narrowLayout = shallowRef(false)
const loggingOut = shallowRef(false)
const logoutError = shallowRef('')
const mobileMenuButton = useTemplateRef<HTMLButtonElement>('mobileMenuButton')
const mobileCloseButton = useTemplateRef<HTMLButtonElement>('mobileCloseButton')
let mobileMediaQuery: MediaQueryList | null = null

const navigation = computed(() => {
  if (session.user?.must_change_password) return []
  const entries = [
    { label: '系统概览', to: '/', icon: CircleGauge, adminOnly: false },
    { label: '检测任务', to: '/tasks', icon: FileScan, adminOnly: false },
    { label: '归档批次', to: '/archives', icon: Archive, adminOnly: false },
    { label: '新建任务', to: '/tasks/new', icon: Plus, adminOnly: false, operatorOnly: true, command: true },
    { label: '系统维护', to: '/system', icon: ServerCog, adminOnly: true },
  ]
  return entries.filter((entry) => {
    if (entry.adminOnly) return session.user?.role === 'administrator'
    if (entry.operatorOnly) return session.user?.role !== 'reader'
    return true
  })
})

const displayName = computed(
  () => session.user?.display_name || session.user?.username || '当前用户',
)
const roleLabel = computed(() => {
  const labels = {
    administrator: '系统管理员',
    operator: '操作员',
    reader: '只读用户',
  } as const
  return session.user ? labels[session.user.role] : '未登录'
})
const drawerHidden = computed(() => narrowLayout.value && !mobileOpen.value)

function isActive(path: string): boolean {
  if (path === '/') return route.path === '/'
  return route.path === path || route.path.startsWith(`${path}/`)
}

function openMobileNavigation(): void {
  mobileOpen.value = true
  void nextTick(() => mobileCloseButton.value?.focus())
}

function closeMobileNavigation(restoreFocus = false): void {
  if (!mobileOpen.value) return
  mobileOpen.value = false
  if (restoreFocus) {
    void nextTick(() => mobileMenuButton.value?.focus())
  }
}

function launchFromNavigation(): void {
  closeMobileNavigation()
  void launchTaskCreation()
}

function syncNarrowLayout(event: MediaQueryList | MediaQueryListEvent): void {
  narrowLayout.value = event.matches
  if (!event.matches) mobileOpen.value = false
}

function handleKeydown(event: KeyboardEvent): void {
  if (event.key === 'Escape' && mobileOpen.value) {
    closeMobileNavigation(true)
  }
}

async function handleLogout(): Promise<void> {
  loggingOut.value = true
  logoutError.value = ''
  try {
    await session.logout()
    await router.replace({ name: 'login' })
  } catch (error) {
    logoutError.value =
      error instanceof ApiError ? error.message : '无法退出登录，请稍后重试'
  } finally {
    loggingOut.value = false
  }
}

watch(
  () => route.fullPath,
  () => {
    mobileOpen.value = false
  },
)

watch(
  () => mobileOpen.value && narrowLayout.value,
  (locked, _, onCleanup) => {
    if (!locked) return
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    onCleanup(() => {
      document.body.style.overflow = previousOverflow
    })
  },
)

onMounted(() => {
  document.addEventListener('keydown', handleKeydown)
  if (typeof window.matchMedia === 'function') {
    mobileMediaQuery = window.matchMedia('(max-width: 840px)')
    syncNarrowLayout(mobileMediaQuery)
    mobileMediaQuery.addEventListener('change', syncNarrowLayout)
  }
})

onScopeDispose(() => {
  document.removeEventListener('keydown', handleKeydown)
  mobileMediaQuery?.removeEventListener('change', syncNarrowLayout)
})
</script>

<template>
  <div class="app-shell" :class="{ 'app-shell--collapsed': collapsed }">
    <a class="skip-link" href="#main-content">跳到主要内容</a>
    <button
      ref="mobileMenuButton"
      class="mobile-menu"
      type="button"
      aria-label="打开主导航"
      title="打开主导航"
      aria-controls="primary-sidebar"
      :aria-expanded="mobileOpen"
      @click="openMobileNavigation"
    >
      <Menu :size="20" aria-hidden="true" />
    </button>

    <div
      v-if="mobileOpen"
      class="sidebar-scrim"
      aria-hidden="true"
      @click="closeMobileNavigation(true)"
    />

    <aside
      id="primary-sidebar"
      class="sidebar"
      :class="{ 'sidebar--mobile-open': mobileOpen }"
      :aria-hidden="drawerHidden"
      :inert="drawerHidden"
    >
      <div class="brand" :aria-label="PRODUCT_NAME">
        <span class="brand-mark" aria-hidden="true"><Binary :size="22" /></span>
        <div v-show="!collapsed" class="brand-copy">
          <strong>{{ PRODUCT_SHORT_NAME }}</strong>
          <span>{{ PRODUCT_DESCRIPTION }}</span>
        </div>
        <button
          ref="mobileCloseButton"
          class="mobile-close"
          type="button"
          aria-label="关闭主导航"
          title="关闭主导航"
          @click="closeMobileNavigation(true)"
        >
          <X :size="18" aria-hidden="true" />
        </button>
      </div>

      <div v-show="!collapsed" class="environment">
        <span class="environment-dot" aria-hidden="true" />
        <span>本地分析工作台</span>
      </div>

      <nav class="primary-nav" aria-label="主导航">
        <template
          v-for="item in navigation"
          :key="item.to"
        >
          <button
            v-if="item.command"
            class="nav-item nav-item--command"
            :class="{ 'nav-item--active': isActive(item.to) }"
            type="button"
            :aria-current="isActive(item.to) ? 'page' : false"
            :aria-label="item.label"
            :title="collapsed ? item.label : ''"
            @click="launchFromNavigation"
          >
            <component :is="item.icon" :size="19" aria-hidden="true" />
            <span v-show="!collapsed">{{ item.label }}</span>
          </button>
          <RouterLink
            v-else
            :to="item.to"
            class="nav-item"
            :class="{ 'nav-item--active': isActive(item.to) }"
            :aria-current="isActive(item.to) ? 'page' : false"
            :aria-label="item.label"
            :title="collapsed ? item.label : ''"
            @click="closeMobileNavigation()"
          >
            <component :is="item.icon" :size="19" aria-hidden="true" />
            <span v-show="!collapsed">{{ item.label }}</span>
          </RouterLink>
        </template>
      </nav>

      <div class="sidebar-bottom">
        <RouterLink
          :to="{ name: 'change-password' }"
          class="nav-item account-password"
          :class="{ 'nav-item--active': route.name === 'change-password' }"
          aria-label="修改密码"
          :aria-current="route.name === 'change-password' ? 'page' : false"
          :title="collapsed ? '修改密码' : ''"
          @click="closeMobileNavigation()"
        >
          <KeyRound :size="18" aria-hidden="true" />
          <span v-show="!collapsed">修改密码</span>
        </RouterLink>
        <div class="account" :title="collapsed ? displayName : ''">
          <span class="account-avatar">{{ displayName.slice(0, 1).toUpperCase() }}</span>
          <span v-show="!collapsed" class="account-copy">
            <strong>{{ displayName }}</strong>
            <small>{{ roleLabel }}</small>
          </span>
          <button
            v-show="!collapsed"
            class="icon-command"
            type="button"
            aria-label="退出登录"
            title="退出登录"
            :disabled="loggingOut"
            @click="handleLogout"
          >
            <LogOut :size="17" aria-hidden="true" />
          </button>
        </div>
        <button
          class="collapse-command"
          type="button"
          :aria-label="collapsed ? '展开导航' : '收起导航'"
          :title="collapsed ? '展开导航' : '收起导航'"
          @click="collapsed = !collapsed"
        >
          <ChevronRight v-if="collapsed" :size="17" aria-hidden="true" />
          <ChevronLeft v-else :size="17" aria-hidden="true" />
          <span v-show="!collapsed">收起导航</span>
        </button>
      </div>
    </aside>

    <main
      id="main-content"
      class="main-area"
      tabindex="-1"
      :aria-hidden="mobileOpen && narrowLayout"
      :inert="mobileOpen && narrowLayout"
    >
      <header class="topbar">
        <span class="topbar-caption">{{ PRODUCT_NAME }}</span>
        <LogoutErrorAlert
          v-if="logoutError"
          :message="logoutError"
          @dismiss="logoutError = ''"
        />
      </header>
      <div class="content">
        <RouterView />
      </div>
    </main>
  </div>
</template>

<style scoped>
.skip-link {
  position: fixed;
  z-index: 200;
  top: 8px;
  left: 12px;
  padding: 8px 12px;
  border: 1px solid var(--line-strong);
  border-radius: var(--radius-sm);
  color: var(--ink-950);
  background: var(--surface);
  box-shadow: var(--shadow-panel);
  font-size: 12px;
  transform: translateY(-160%);
}

.skip-link:focus {
  transform: translateY(0);
}

.app-shell {
  --sidebar-width: 240px;
  min-height: 100vh;
  padding-left: var(--sidebar-width);
  background: var(--surface-muted);
  transition: padding-left 180ms ease;
}

.app-shell--collapsed {
  --sidebar-width: 76px;
}

.sidebar {
  position: fixed;
  inset: 0 auto 0 0;
  z-index: 30;
  display: flex;
  width: var(--sidebar-width);
  flex-direction: column;
  border-right: 1px solid var(--line);
  background: var(--surface);
  color: var(--ink-700);
  transition: width 180ms ease, transform 180ms ease;
}

.brand {
  display: flex;
  min-height: 82px;
  flex-shrink: 0;
  align-items: center;
  gap: 11px;
  margin: 20px 14px 0;
  padding: 14px 12px;
  border: 1px solid var(--primary-border);
  border-radius: 14px;
  background: var(--primary-soft);
}

.brand-mark {
  display: grid;
  width: 40px;
  height: 40px;
  flex: 0 0 40px;
  place-items: center;
  border-radius: 11px;
  color: var(--surface);
  background: var(--primary);
  box-shadow: 0 4px 10px rgb(37 99 235 / 16%);
}

.brand-copy {
  min-width: 0;
}

.brand-copy strong,
.brand-copy span {
  display: block;
}

.brand-copy strong {
  color: var(--primary-hover);
  font-size: 19px;
  letter-spacing: 0.04em;
}

.brand-copy span {
  margin-top: 3px;
  color: var(--ink-600);
  font-size: 10px;
  line-height: 1.6;
}

.environment {
  display: flex;
  min-height: 46px;
  flex-shrink: 0;
  align-items: center;
  gap: 8px;
  padding: 8px 26px;
  color: var(--ink-500);
  font-size: 11px;
  white-space: nowrap;
}

.environment-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--primary);
  box-shadow: 0 0 0 3px var(--primary-soft);
}

.primary-nav {
  display: grid;
  min-height: 0;
  flex: 1;
  align-content: start;
  gap: 7px;
  padding: 8px 14px 20px;
  overflow-y: auto;
}

.nav-item {
  display: flex;
  min-height: 47px;
  flex-shrink: 0;
  align-items: center;
  gap: 13px;
  padding: 0 15px;
  border: 1px solid transparent;
  border-radius: 10px;
  color: var(--ink-600);
  background: transparent;
  font-size: 14px;
  font-weight: 500;
  white-space: nowrap;
  transition: color 150ms ease, background 150ms ease;
}

.nav-item > svg {
  flex-shrink: 0;
}

.nav-item--command {
  width: 100%;
  font-family: inherit;
  cursor: pointer;
  text-align: left;
}

.nav-item span {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
}

.nav-item:hover {
  color: var(--primary);
  background: var(--surface-muted);
}

.nav-item--active,
.nav-item--active:hover {
  color: var(--primary);
  background: var(--primary-soft);
  font-weight: 600;
}

.sidebar-bottom {
  flex-shrink: 0;
  margin-top: auto;
  padding: 12px 14px 14px;
  border-top: 1px solid var(--line);
}

.account {
  display: flex;
  min-height: 70px;
  align-items: center;
  gap: 10px;
  padding: 12px 10px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: var(--surface-raised);
}

.account-password {
  min-height: 42px;
  margin-bottom: 10px;
}

.account-avatar {
  display: grid;
  width: 34px;
  height: 34px;
  flex: 0 0 34px;
  place-items: center;
  border-radius: 50%;
  color: var(--primary);
  background: var(--primary-border);
  font-size: 13px;
  font-weight: 700;
}

.account-copy {
  min-width: 0;
  flex: 1;
}

.account-copy strong,
.account-copy small {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.account-copy strong {
  color: var(--ink-800);
  font-size: 13px;
  font-weight: 600;
}

.account-copy small {
  margin-top: 3px;
  color: var(--ink-500);
  font-size: 11px;
}

.icon-command,
.collapse-command,
.mobile-menu,
.mobile-close {
  border: 0;
  color: inherit;
  background: transparent;
  cursor: pointer;
}

.icon-command {
  display: grid;
  width: 28px;
  height: 32px;
  flex-shrink: 0;
  place-items: center;
  border-radius: var(--radius-sm);
  color: var(--ink-500);
}

.icon-command:hover {
  color: var(--primary);
  background: var(--primary-soft);
}

.icon-command:disabled {
  color: var(--ink-400);
  cursor: wait;
}

.collapse-command {
  display: flex;
  width: 100%;
  min-height: 38px;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-top: 10px;
  border-radius: var(--radius-sm);
  color: var(--ink-500);
  font-size: 12px;
}

.collapse-command:hover {
  color: var(--primary);
  background: var(--surface-muted);
}

.app-shell--collapsed .brand {
  min-height: 68px;
  justify-content: center;
  padding: 12px 0;
  border-color: transparent;
  background: transparent;
}

.app-shell--collapsed .primary-nav {
  padding-right: 12px;
  padding-left: 12px;
}

.app-shell--collapsed .nav-item {
  justify-content: center;
  padding: 0;
}

.app-shell--collapsed .sidebar-bottom {
  padding-right: 12px;
  padding-left: 12px;
}

.app-shell--collapsed .account {
  justify-content: center;
  padding-right: 0;
  padding-left: 0;
  border-color: transparent;
  background: transparent;
}

.main-area {
  min-width: 0;
  min-height: 100vh;
}

.topbar {
  display: flex;
  min-height: 64px;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 10px 32px;
  border-bottom: 1px solid var(--line);
  background: var(--surface);
}

.topbar-caption {
  min-width: 0;
  overflow: hidden;
  color: var(--ink-600);
  font-size: 13px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.content {
  min-width: 0;
  padding: 30px 32px 48px;
}

.mobile-menu,
.mobile-close {
  display: none;
}

@media (max-width: 1100px) {
  .content {
    padding-right: 24px;
    padding-left: 24px;
  }

  .topbar {
    padding-right: 24px;
    padding-left: 24px;
  }
}

@media (max-width: 840px) {
  .app-shell,
  .app-shell--collapsed {
    padding-left: 0;
  }

  .sidebar {
    width: min(284px, 86vw);
    box-shadow: 14px 0 40px rgb(30 58 138 / 12%);
    transform: translateX(-100%);
  }

  .sidebar--mobile-open {
    transform: translateX(0);
  }

  .sidebar .brand-copy,
  .sidebar .nav-item span,
  .sidebar .account-copy {
    display: block !important;
  }

  .sidebar .environment {
    display: flex !important;
  }

  .sidebar .icon-command {
    display: grid !important;
  }

  .sidebar .brand {
    min-height: 82px;
    justify-content: flex-start;
    gap: 11px;
    padding: 14px 12px;
    border-color: var(--primary-border);
    background: var(--primary-soft);
  }

  .sidebar .nav-item {
    justify-content: flex-start;
    padding: 0 15px;
  }

  .sidebar .account {
    justify-content: flex-start;
    padding-right: 10px;
    padding-left: 10px;
    border-color: var(--line);
    background: var(--surface-raised);
  }

  .sidebar .collapse-command {
    display: none;
  }

  .mobile-menu {
    position: fixed;
    z-index: 20;
    top: 14px;
    left: 12px;
    display: grid;
    width: 36px;
    height: 36px;
    place-items: center;
    border: 1px solid var(--line);
    border-radius: 10px;
    color: var(--ink-700);
    background: var(--surface);
    box-shadow: var(--shadow-sm);
  }

  .mobile-close {
    display: grid;
    width: 28px;
    height: 34px;
    flex: 0 0 28px;
    margin-left: auto;
    place-items: center;
    color: var(--ink-500);
  }

  .sidebar-scrim {
    position: fixed;
    z-index: 25;
    inset: 0;
    background: rgb(30 41 59 / 34%);
  }

  .topbar {
    padding-left: 62px;
  }

  .content {
    padding: 24px 16px 36px;
  }
}

@media (max-width: 520px) {
  .topbar {
    padding-right: 16px;
  }

  .topbar-caption {
    font-size: 11px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .app-shell,
  .sidebar,
  .nav-item {
    transition: none;
  }
}
</style>
