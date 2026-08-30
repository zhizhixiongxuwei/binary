import { defineStore } from 'pinia'
import { computed, shallowRef } from 'vue'

import { api, ApiError } from '@/api/client'
import type { ChangePasswordInput, CurrentUser, LoginInput, UserRole } from '@/api/types'

export const useSessionStore = defineStore('session', () => {
  // 用户对象只会整体替换，不需要深层响应式；shallowRef 可避免把权限模型包装成代理。
  const user = shallowRef<CurrentUser | null>(null)
  const restored = shallowRef(false)
  const restoring = shallowRef(false)
  let restoreRequest: Promise<void> | null = null

  const isAuthenticated = computed(() => user.value !== null)

  async function restore(): Promise<void> {
    if (restored.value) return
    // 路由守卫和页面组件可能同时请求恢复会话，复用同一个 Promise 保证单次飞行。
    if (restoreRequest) return restoreRequest

    restoreRequest = (async () => {
      restoring.value = true
      try {
        user.value = await api.getMe()
        restored.value = true
      } catch (error) {
        // 401 是可确认的匿名状态；超时、5xx 等故障必须继续抛出，不能把服务异常
        // 静默降级成退出登录，否则会造成错误的跳转和用户状态丢失。
        if (!(error instanceof ApiError && error.status === 401)) throw error
        user.value = null
        restored.value = true
      } finally {
        restoring.value = false
      }
    })()

    try {
      await restoreRequest
    } finally {
      restoreRequest = null
    }
  }

  async function login(input: LoginInput): Promise<void> {
    user.value = await api.login(input)
    restored.value = true
  }

  async function logout(): Promise<void> {
    try {
      await api.logout()
      user.value = null
      restored.value = true
    } catch (error) {
      // 服务端会话已经失效时，退出操作在客户端仍视为成功，从而保持幂等。
      if (error instanceof ApiError && error.status === 401) {
        user.value = null
        restored.value = true
        return
      }
      throw error
    }
  }

  async function changePassword(input: ChangePasswordInput): Promise<void> {
    user.value = await api.changePassword(input)
    restored.value = true
  }

  function hasRole(roles: UserRole[]): boolean {
    return user.value !== null && roles.includes(user.value.role)
  }

  return {
    user,
    restored,
    restoring,
    isAuthenticated,
    restore,
    login,
    logout,
    changePassword,
    hasRole,
  }
})
