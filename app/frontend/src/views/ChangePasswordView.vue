<script setup lang="ts">
import { shallowRef } from 'vue'
import { useRouter } from 'vue-router'

import { ApiError } from '@/api/client'
import type { ChangePasswordInput } from '@/api/types'
import ChangePasswordForm from '@/components/auth/ChangePasswordForm.vue'
import PageHeader from '@/components/common/PageHeader.vue'
import { useSessionStore } from '@/stores/session'

const router = useRouter()
const session = useSessionStore()
const loading = shallowRef(false)
const errorMessage = shallowRef('')

async function handleSubmit(input: ChangePasswordInput): Promise<void> {
  if (loading.value) return
  loading.value = true
  errorMessage.value = ''
  try {
    await session.changePassword(input)
    await router.replace({ name: 'login', query: { reason: 'password-changed' } })
  } catch (error) {
    if (error instanceof ApiError && error.code === 'invalid_current_password') {
      errorMessage.value = '当前密码不正确，请重新输入'
    } else if (error instanceof ApiError && error.code === 'invalid_password_change') {
      errorMessage.value = '新密码须为 8–72 字节，请检查后重试'
    } else {
      errorMessage.value = error instanceof ApiError ? error.message : '密码修改失败，请稍后重试'
    }
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="password-view">
    <PageHeader
      title="修改密码"
      :description="session.user?.must_change_password ? '首次登录，请先修改初始密码。' : '更新当前账户的登录密码。'"
    >
      <template v-if="!session.user?.must_change_password" #actions>
        <el-button :disabled="loading" @click="router.push({ name: 'overview' })">返回概览</el-button>
      </template>
    </PageHeader>
    <section class="password-panel surface-panel">
      <header class="password-panel__header">
        <span>当前账户：<strong>{{ session.user?.username }}</strong></span>
      </header>
      <p class="password-notice">修改成功后，所有登录会话将失效，请使用新密码重新登录。</p>
      <ChangePasswordForm
        :loading="loading"
        :error-message="errorMessage"
        @submit="handleSubmit"
      />
    </section>
  </div>
</template>

<style scoped>
.password-view {
  width: min(100%, 520px);
  margin: 0 auto;
}

.password-panel__header {
  display: flex;
  min-height: 46px;
  align-items: center;
  padding: 0 24px;
  border-bottom: 1px solid var(--line);
  color: var(--ink-600);
  font-size: 12px;
}

.password-notice {
  margin: 20px 24px 0;
  color: var(--ink-600);
  font-size: 13px;
  line-height: 1.7;
}
</style>
