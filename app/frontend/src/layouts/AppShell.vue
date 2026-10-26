<script setup lang="ts">
import { Archive, Binary, ChevronLeft, ChevronRight, ChevronsUpDown, CircleGauge, FileScan, KeyRound, LogOut, Menu, Plus, ServerCog, X } from 'lucide-vue-next'
import { computed, nextTick, onMounted, onScopeDispose, shallowRef, useTemplateRef, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { ApiError } from '@/api/client'
import LogoutErrorAlert from '@/components/auth/LogoutErrorAlert.vue'
import { useTaskCreationLauncher } from '@/composables/useTaskCreationLauncher'
import { PRODUCT_DESCRIPTION, PRODUCT_NAME, PRODUCT_SHORT_NAME } from '@/config/branding'
import { useSessionStore } from '@/stores/session'
import { readSidebarPreference, resolveSidebarCollapsed, SIDEBAR_COLLAPSED_KEY, sidebarPathIsActive } from './sidebarState'

const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const { launchTaskCreation } = useTaskCreationLauncher()
const preferredCollapsed = shallowRef(false)
const readingFocus = shallowRef(false)
const focusOverride = shallowRef<boolean | null>(null)
const mobileOpen = shallowRef(false)
const narrowLayout = shallowRef(false)
const collapsed = computed(() => resolveSidebarCollapsed(preferredCollapsed.value, narrowLayout.value, readingFocus.value, focusOverride.value))
const accountOpen = shallowRef(false)
const loggingOut = shallowRef(false)
const logoutError = shallowRef('')
const mobileMenuButton = useTemplateRef<HTMLButtonElement>('mobileMenuButton')
const mobileCloseButton = useTemplateRef<HTMLButtonElement>('mobileCloseButton')
const accountRoot = useTemplateRef<HTMLDivElement>('accountRoot')
const accountButton = useTemplateRef<HTMLButtonElement>('accountButton')
const accountMenu = useTemplateRef<HTMLDivElement>('accountMenu')
let mobileMediaQuery: MediaQueryList | null = null

const canCreateTask = computed(() => Boolean(session.user && !session.user.must_change_password && session.user.role !== 'reader'))
const navigationGroups = computed(() => {
  if (session.user?.must_change_password) return []
  return [
    { label: '工作区', items: [
      { label: '系统概览', to: '/', icon: CircleGauge },
      { label: '检测任务', to: '/tasks', icon: FileScan },
      { label: '归档批次', to: '/archives', icon: Archive },
    ] },
    ...(session.user?.role === 'administrator' ? [{ label: '系统管理', items: [{ label: '系统维护', to: '/system', icon: ServerCog }] }] : []),
  ]
})
const displayName = computed(() => session.user?.display_name || session.user?.username || '当前用户')
const roleLabel = computed(() => {
  const labels = { administrator: '系统管理员', operator: '操作员', reader: '只读用户' } as const
  return session.user ? labels[session.user.role] : '未登录'
})
const drawerHidden = computed(() => narrowLayout.value && !mobileOpen.value)
const isActive = (path: string) => sidebarPathIsActive(route.path, path)

function closeAccountMenu(restoreFocus = false): void {
  accountOpen.value = false
  if (restoreFocus) void nextTick(() => accountButton.value?.focus({ preventScroll: true }))
}
function menuItems(): HTMLElement[] {
  return [...(accountMenu.value?.querySelectorAll<HTMLElement>('[role="menuitem"]:not([disabled])') ?? [])]
}
async function openAccountMenu(last = false): Promise<void> {
  accountOpen.value = true
  await nextTick()
  const items = menuItems()
  ;(last ? items[items.length - 1] : items[0])?.focus({ preventScroll: true })
}
function toggleAccountMenu(): void { if (accountOpen.value) closeAccountMenu(); else void openAccountMenu() }
function accountButtonKeys(event: KeyboardEvent): void {
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault()
    void openAccountMenu(event.key === 'ArrowUp')
  }
}
function accountMenuKeys(event: KeyboardEvent): void {
  if (event.key === 'Escape' || event.key === 'Tab') {
    event.preventDefault(); event.stopPropagation(); closeAccountMenu(true); return
  }
  if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return
  event.preventDefault()
  const items = menuItems()
  const current = items.indexOf(document.activeElement as HTMLElement)
  const index = event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1 : (current + (event.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length
  items[index]?.focus({ preventScroll: true })
}
function outsideAccount(event: PointerEvent): void {
  if (accountOpen.value && event.target instanceof Node && !accountRoot.value?.contains(event.target)) closeAccountMenu()
}
function toggleCollapsed(): void {
  closeAccountMenu()
  if (readingFocus.value) { focusOverride.value = !collapsed.value; return }
  preferredCollapsed.value = !preferredCollapsed.value
  try { localStorage.setItem(SIDEBAR_COLLAPSED_KEY, preferredCollapsed.value ? '1' : '0') } catch { /* Keep the UI usable when storage is unavailable. */ }
}
function handleReadingFocus(event: Event): void {
  if (!(event instanceof CustomEvent) || typeof event.detail?.active !== 'boolean') return
  readingFocus.value = event.detail.active
  focusOverride.value = null
  closeAccountMenu()
}
function openMobileNavigation(): void {
  mobileOpen.value = true
  void nextTick(() => mobileCloseButton.value?.focus())
}
function closeMobileNavigation(restoreFocus = false): void {
  closeAccountMenu()
  if (!mobileOpen.value) return
  mobileOpen.value = false
  if (restoreFocus) void nextTick(() => mobileMenuButton.value?.focus())
}
function launchFromNavigation(): void { closeMobileNavigation(); void launchTaskCreation() }
function navigatePassword(): void { closeAccountMenu(); closeMobileNavigation() }
function syncNarrowLayout(event: MediaQueryList | MediaQueryListEvent): void {
  narrowLayout.value = event.matches
  closeAccountMenu()
  if (!event.matches) mobileOpen.value = false
}
function handleKeydown(event: KeyboardEvent): void {
  if (event.key !== 'Escape') return
  if (accountOpen.value) { event.preventDefault(); closeAccountMenu(true) }
  else if (mobileOpen.value) closeMobileNavigation(true)
}
async function handleLogout(): Promise<void> {
  if (loggingOut.value) return
  loggingOut.value = true; logoutError.value = ''
  try { await session.logout(); await router.replace({ name: 'login' }) }
  catch (error) {
    logoutError.value = error instanceof ApiError ? error.message : '无法退出登录，请稍后重试'
    closeAccountMenu(true)
  } finally { loggingOut.value = false }
}

watch(() => route.fullPath, () => { mobileOpen.value = false; closeAccountMenu() })
watch(() => route.path, () => { readingFocus.value = false; focusOverride.value = null })
watch(collapsed, () => closeAccountMenu())
watch(() => mobileOpen.value && narrowLayout.value, (locked, _, onCleanup) => {
  if (!locked) return
  const previousOverflow = document.body.style.overflow
  document.body.style.overflow = 'hidden'
  onCleanup(() => { document.body.style.overflow = previousOverflow })
})
onMounted(() => {
  try { preferredCollapsed.value = readSidebarPreference(localStorage.getItem(SIDEBAR_COLLAPSED_KEY)) } catch { /* Use expanded navigation by default. */ }
  document.addEventListener('keydown', handleKeydown)
  document.addEventListener('pointerdown', outsideAccount)
  window.addEventListener('binaryscan:reading-focus', handleReadingFocus)
  if (typeof window.matchMedia === 'function') {
    mobileMediaQuery = window.matchMedia('(max-width: 840px)')
    syncNarrowLayout(mobileMediaQuery)
    mobileMediaQuery.addEventListener('change', syncNarrowLayout)
  }
})
onScopeDispose(() => {
  document.removeEventListener('keydown', handleKeydown)
  document.removeEventListener('pointerdown', outsideAccount)
  window.removeEventListener('binaryscan:reading-focus', handleReadingFocus)
  mobileMediaQuery?.removeEventListener('change', syncNarrowLayout)
})
</script>

<template>
  <div class="app-shell" :class="{ 'app-shell--collapsed': collapsed, 'app-shell--reading': readingFocus }">
    <a class="skip-link" href="#main-content">跳到主要内容</a>
    <button ref="mobileMenuButton" class="mobile-menu" type="button" aria-label="打开主导航" aria-controls="primary-sidebar" :aria-expanded="mobileOpen" @click="openMobileNavigation"><Menu :size="20" aria-hidden="true" /></button>
    <div v-if="mobileOpen" class="sidebar-scrim" aria-hidden="true" @click="closeMobileNavigation(true)" />
    <aside id="primary-sidebar" class="sidebar" :class="{ 'sidebar--mobile-open': mobileOpen }" :aria-hidden="drawerHidden" :inert="drawerHidden">
      <div class="brand" :aria-label="PRODUCT_NAME">
        <span class="brand-mark" aria-hidden="true"><Binary :size="22" /></span>
        <div v-show="!collapsed" class="brand-copy"><strong>{{ PRODUCT_SHORT_NAME }}</strong><span :title="PRODUCT_DESCRIPTION">{{ PRODUCT_DESCRIPTION }}</span></div>
        <button ref="mobileCloseButton" class="mobile-close" type="button" aria-label="关闭主导航" @click="closeMobileNavigation(true)"><X :size="18" aria-hidden="true" /></button>
      </div>
      <div v-if="canCreateTask" class="create-task-area">
        <el-tooltip content="新建任务" placement="right" :disabled="!collapsed" :show-after="0" :hide-after="0" effect="light">
          <button class="create-task" type="button" aria-label="新建任务" @click="launchFromNavigation"><Plus :size="19" aria-hidden="true" /><span v-show="!collapsed">新建任务</span></button>
        </el-tooltip>
      </div>
      <nav class="primary-nav" aria-label="主导航">
        <section v-for="group in navigationGroups" :key="group.label" class="nav-group" :aria-label="group.label">
          <h2 v-show="!collapsed" class="nav-group__label">{{ group.label }}</h2>
          <el-tooltip v-for="item in group.items" :key="item.to" :content="item.label" placement="right" :disabled="!collapsed" :show-after="0" :hide-after="0" effect="light">
            <RouterLink :to="item.to" class="nav-item" :class="{ 'nav-item--active': isActive(item.to) }" :aria-current="isActive(item.to) ? 'page' : undefined" :aria-label="item.label" @click="closeMobileNavigation()"><component :is="item.icon" :size="19" aria-hidden="true" /><span v-show="!collapsed">{{ item.label }}</span></RouterLink>
          </el-tooltip>
        </section>
      </nav>
      <div class="sidebar-bottom">
        <div ref="accountRoot" class="account-root">
          <div v-if="accountOpen" id="sidebar-account-menu" ref="accountMenu" class="account-menu" role="menu" aria-label="账号操作" @keydown="accountMenuKeys">
            <div class="account-menu__identity"><strong>{{ displayName }}</strong><span>{{ roleLabel }}</span></div>
            <RouterLink :to="{ name: 'change-password' }" role="menuitem" :aria-current="route.name === 'change-password' ? 'page' : undefined" @click="navigatePassword"><KeyRound :size="16" aria-hidden="true" />修改密码<ChevronRight :size="13" class="account-menu__arrow" aria-hidden="true" /></RouterLink>
            <button role="menuitem" type="button" :disabled="loggingOut" class="account-menu__logout" @click="handleLogout"><LogOut :size="16" aria-hidden="true" />{{ loggingOut ? '正在退出…' : '退出登录' }}</button>
          </div>
          <el-tooltip :content="`${displayName} · 账号菜单`" placement="right" :disabled="!collapsed || accountOpen" :show-after="0" :hide-after="0" effect="light">
            <button ref="accountButton" class="account" type="button" aria-label="打开账号菜单" aria-haspopup="menu" aria-controls="sidebar-account-menu" :aria-expanded="accountOpen" @click="toggleAccountMenu" @keydown="accountButtonKeys"><span class="account-avatar" aria-hidden="true">{{ displayName.slice(0, 1).toUpperCase() }}</span><span v-show="!collapsed" class="account-copy"><strong>{{ displayName }}</strong><small>{{ roleLabel }}</small></span><ChevronsUpDown v-show="!collapsed" :size="15" class="account-chevron" aria-hidden="true" /></button>
          </el-tooltip>
        </div>
        <el-tooltip :content="collapsed ? '展开导航' : '收起导航'" placement="right" :show-after="0" :hide-after="0" effect="light">
          <button class="collapse-command" type="button" :aria-label="collapsed ? '展开导航' : '收起导航'" aria-controls="primary-sidebar" :aria-expanded="!collapsed" @click="toggleCollapsed"><ChevronRight v-if="collapsed" :size="18" aria-hidden="true" /><ChevronLeft v-else :size="18" aria-hidden="true" /></button>
        </el-tooltip>
      </div>
    </aside>
    <main id="main-content" class="main-area" tabindex="-1" :aria-hidden="mobileOpen && narrowLayout" :inert="mobileOpen && narrowLayout">
      <header class="topbar"><span class="topbar-caption">{{ PRODUCT_NAME }}</span><LogoutErrorAlert v-if="logoutError" :message="logoutError" @dismiss="logoutError = ''" /></header>
      <div class="content"><RouterView /></div>
    </main>
  </div>
</template>

<style scoped>
.skip-link { position: fixed; z-index: 3000; top: 8px; left: 12px; padding: 8px 12px; border: 1px solid var(--line-strong); border-radius: var(--radius-sm); color: var(--ink-950); background: var(--surface); box-shadow: var(--shadow-panel); font-size: 12px; transform: translateY(-160%); }
.skip-link:focus { transform: translateY(0); }
.app-shell { --sidebar-width: 224px; min-height: 100vh; padding-left: var(--sidebar-width); background: var(--surface-muted); transition: padding-left 180ms ease; }
.app-shell--collapsed { --sidebar-width: 68px; }
.sidebar { position: fixed; inset: 0 auto 0 0; z-index: 30; display: flex; width: var(--sidebar-width); flex-direction: column; border-right: 1px solid var(--line); background: var(--surface); color: var(--ink-700); transition: width 180ms ease, transform 180ms ease; }
.brand { display: flex; min-height: 66px; flex-shrink: 0; align-items: center; gap: 10px; margin: 14px 14px 0; padding: 8px 0; }
.brand-mark { display: grid; width: 36px; height: 36px; flex: 0 0 36px; place-items: center; border-radius: 10px; color: var(--surface); background: var(--primary); box-shadow: 0 3px 8px rgb(37 99 235 / 12%); }
.brand-copy { min-width: 0; }.brand-copy strong, .brand-copy span { display: block; }.brand-copy strong { color: var(--primary-hover); font-size: 19px; letter-spacing: .03em; }.brand-copy span { overflow: hidden; margin-top: 3px; color: var(--ink-600); font-size: 11px; line-height: 1.6; text-overflow: ellipsis; white-space: nowrap; }
.create-task-area { padding: 12px 14px 8px; }.create-task { display: flex; align-items: center; justify-content: center; gap: 9px; width: 100%; min-height: 40px; border: 1px solid var(--primary); border-radius: 9px; background: var(--primary); color: white; font: inherit; font-size: 13px; font-weight: 600; cursor: pointer; box-shadow: 0 3px 8px rgb(37 99 235 / 12%); transition: background 150ms ease, box-shadow 150ms ease; }.create-task:hover { background: var(--primary-hover); border-color: var(--primary-hover); box-shadow: 0 4px 12px rgb(37 99 235 / 20%); }.create-task svg { flex-shrink: 0; }
.primary-nav { display: flex; min-height: 0; flex: 1; flex-direction: column; gap: 20px; padding: 14px 10px 20px; overflow-y: auto; }.nav-group { display: grid; gap: 5px; }.nav-group__label { margin: 0 12px 4px; color: var(--ink-500); font-size: 10px; font-weight: 500; letter-spacing: .08em; }
.nav-item { position: relative; display: flex; min-height: 42px; align-items: center; gap: 12px; padding: 0 14px; border: 1px solid transparent; border-radius: 8px; color: var(--ink-600); background: transparent; font-size: 13px; font-weight: 500; white-space: nowrap; transition: color 150ms ease, background 150ms ease; }.nav-item > svg { flex-shrink: 0; }.nav-item > span { min-width: 0; overflow: hidden; text-overflow: ellipsis; }.nav-item:hover { color: var(--primary); background: var(--surface-muted); }.nav-item--active, .nav-item--active:hover { color: var(--primary); background: var(--primary-soft); font-weight: 600; }.nav-item--active::before { position: absolute; inset: 10px auto 10px 0; width: 3px; border-radius: 0 3px 3px 0; background: var(--primary); content: ''; }
.sidebar-bottom { flex-shrink: 0; margin-top: auto; padding: 10px; border-top: 1px solid var(--line); }.account-root { position: relative; }.account { display: flex; width: 100%; min-height: 56px; align-items: center; gap: 9px; padding: 8px; border: 1px solid transparent; border-radius: 10px; background: transparent; color: var(--ink-700); text-align: left; font: inherit; cursor: pointer; }.account:hover, .account[aria-expanded='true'] { background: var(--surface-muted); border-color: var(--line); }.account-avatar { display: grid; width: 32px; height: 32px; flex: 0 0 32px; place-items: center; border: 1px solid var(--primary-border); border-radius: 10px; color: var(--primary); background: var(--primary-soft); font-size: 12px; font-weight: 700; }.account-copy { min-width: 0; flex: 1; }.account-copy strong, .account-copy small { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }.account-copy strong { color: var(--ink-800); font-size: 12px; font-weight: 600; }.account-copy small { margin-top: 3px; color: var(--ink-500); font-size: 10px; }.account-chevron { flex-shrink: 0; color: var(--ink-500); }
.account-menu { position: absolute; z-index: 50; bottom: calc(100% + 8px); left: 0; right: 0; min-width: 204px; padding: 6px; border: 1px solid var(--line); border-radius: 12px; background: var(--surface); box-shadow: 0 8px 32px rgb(15 23 42 / 14%); }.account-menu__identity { display: grid; gap: 4px; padding: 10px 10px 12px; margin-bottom: 4px; border-bottom: 1px solid var(--line); }.account-menu__identity strong { overflow: hidden; color: var(--ink-800); font-size: 12px; text-overflow: ellipsis; white-space: nowrap; }.account-menu__identity span { color: var(--ink-500); font-size: 11px; }.account-menu a, .account-menu button { display: flex; width: 100%; min-height: 38px; align-items: center; gap: 9px; padding: 8px 10px; border: 0; border-radius: 7px; color: var(--ink-700); background: transparent; font: inherit; font-size: 12px; text-decoration: none; cursor: pointer; }.account-menu a:hover, .account-menu button:hover { color: var(--primary); background: var(--primary-soft); }.account-menu__arrow { margin-left: auto; }.account-menu .account-menu__logout:hover { color: var(--danger); background: var(--danger-soft); }.account-menu button:disabled { opacity: .5; cursor: wait; }
.collapse-command, .mobile-menu, .mobile-close { border: 0; color: inherit; background: transparent; cursor: pointer; }.collapse-command { display: grid; width: 30px; height: 30px; place-items: center; margin: 4px 0 0 auto; border: 1px solid var(--line); border-radius: 7px; color: var(--ink-500); background: var(--surface); }.collapse-command:hover { color: var(--primary); border-color: var(--primary-border); background: var(--primary-soft); }
.app-shell--collapsed .collapse-command { margin-inline: auto; }
.sidebar :is(a, button):focus-visible { outline: 2px solid var(--primary); outline-offset: 2px; }
.app-shell--collapsed .brand { min-height: 60px; margin: 10px 0 0; justify-content: center; }.app-shell--collapsed .create-task-area { padding: 12px 10px 6px; }.app-shell--collapsed .create-task { min-height: 42px; }.app-shell--collapsed .primary-nav { gap: 17px; padding-inline: 10px; }.app-shell--collapsed .nav-group + .nav-group { padding-top: 12px; border-top: 1px solid var(--line); }.app-shell--collapsed .nav-item { justify-content: center; padding: 0; }.app-shell--collapsed .sidebar-bottom { padding-inline: 10px; }.app-shell--collapsed .account { min-height: 48px; justify-content: center; padding: 6px 0; }.app-shell--collapsed .account-menu { bottom: 0; left: calc(100% + 10px); right: auto; width: 220px; }
.main-area { min-width: 0; min-height: 100vh; }.topbar { display: flex; min-height: 64px; align-items: center; justify-content: space-between; gap: 16px; padding: 10px 32px; border-bottom: 1px solid var(--line); background: var(--surface); }.topbar-caption { min-width: 0; overflow: hidden; color: var(--ink-600); font-size: 13px; text-overflow: ellipsis; white-space: nowrap; }.content { min-width: 0; padding: 26px 28px 40px; }.mobile-menu, .mobile-close { display: none; }
@media (max-width: 1100px) { .content { padding-inline: 20px; }.topbar { padding-inline: 20px; } }
@media (max-width: 840px) {
  .app-shell, .app-shell--collapsed { --sidebar-width: 0px; padding-left: 0; }.sidebar { width: min(280px, 86vw); box-shadow: 14px 0 40px rgb(30 58 138 / 12%); transform: translateX(-100%); }.sidebar--mobile-open { transform: translateX(0); }.sidebar .brand { min-height: 66px; margin: 12px 16px 0; }.sidebar .account-menu { left: 0; right: 0; width: auto; min-width: 0; bottom: calc(100% + 8px); }.sidebar .collapse-command { display: none; }.mobile-menu { position: fixed; z-index: 20; top: 14px; left: 12px; display: grid; width: 36px; height: 36px; place-items: center; border: 1px solid var(--line); border-radius: 10px; color: var(--ink-700); background: var(--surface); box-shadow: var(--shadow-sm); }.mobile-close { display: grid; width: 28px; height: 34px; flex: 0 0 28px; margin-left: auto; place-items: center; color: var(--ink-500); }.sidebar-scrim { position: fixed; z-index: 25; inset: 0; background: rgb(30 41 59 / 34%); }.topbar { padding-left: 62px; }.content { padding: 20px 14px 30px; }
}
@media (max-width: 520px) { .topbar { padding-right: 16px; }.topbar-caption { font-size: 11px; } }
@media (prefers-reduced-motion: reduce) { .app-shell, .sidebar, .nav-item, .create-task { transition: none; } }
</style>
