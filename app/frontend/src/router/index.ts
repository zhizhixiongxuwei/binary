import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'

import type { UserRole } from '@/api/types'
import { passwordRouteRedirect } from '@/router/guards'
import { useSessionStore } from '@/stores/session'

declare module 'vue-router' {
  interface RouteMeta {
    // 路由元数据只负责前端导航体验；真正的访问控制仍由后端接口鉴权兜底。
    public?: boolean
    roles?: UserRole[]
  }
}

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/LoginView.vue'),
    meta: { public: true },
  },
  {
    path: '/',
    component: () => import('@/layouts/AppShell.vue'),
    children: [
      {
        path: '',
        name: 'overview',
        component: () => import('@/views/OverviewView.vue'),
      },
      {
        path: 'tasks',
        name: 'tasks',
        component: () => import('@/views/TasksView.vue'),
      },
      {
        path: 'archives',
        name: 'archive-imports',
        component: () => import('@/views/ArchiveImportsView.vue'),
      },
      {
        path: 'change-password',
        name: 'change-password',
        component: () => import('@/views/ChangePasswordView.vue'),
      },
      {
        path: 'tasks/new',
        name: 'task-create',
        component: () => import('@/views/CreateTaskView.vue'),
        meta: { roles: ['administrator', 'operator'] },
      },
      {
        path: 'tasks/:id',
        name: 'task-detail',
        component: () => import('@/views/TaskDetailView.vue'),
      },
      {
        path: 'system',
        name: 'system',
        component: () => import('@/views/SystemView.vue'),
        meta: { roles: ['administrator'] },
      },
    ],
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: () => import('@/views/NotFoundView.vue'),
    meta: { public: true },
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior: () => ({ top: 0 }),
})

router.beforeEach(async (to) => {
  const session = useSessionStore()
  // 首次进入应用时先恢复 Cookie 会话。restore 内部会合并并发请求，避免多个
  // 懒加载页面同时导航时重复调用 /me；网络故障也不能被误判成“未登录”。
  try {
    await session.restore()
  } catch {
    if (to.meta.public) return true
    return { name: 'login', query: { redirect: to.fullPath, reason: 'session' } }
  }

  // 强制修改初始密码的约束优先于 public/roles 判断，确保已登录用户不能通过
  // 手工输入 URL 绕过口令更新流程。
  const passwordRedirect = passwordRouteRedirect(session.user, to.name)
  if (passwordRedirect) return { name: passwordRedirect }

  if (to.meta.public) {
    if (session.isAuthenticated && to.name === 'login') return { name: 'overview' }
    return true
  }

  if (!session.isAuthenticated) {
    // 保留完整目标地址，登录成功后可回到原任务详情及其源码定位查询参数。
    return { name: 'login', query: { redirect: to.fullPath } }
  }

  if (to.meta.roles && !session.hasRole(to.meta.roles)) {
    return { name: 'overview' }
  }

  return true
})

export default router
