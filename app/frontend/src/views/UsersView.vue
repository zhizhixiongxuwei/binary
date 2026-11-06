<script setup lang="ts">
import { onMounted } from 'vue'

import { isDemoMode } from '@/api/runtime'
import type {
  CreateAdminUserInput,
  ResetAdminUserPasswordInput,
  UpdateAdminUserInput,
} from '@/api/types'
import PageHeader from '@/components/common/PageHeader.vue'
import PreviewNotice from '@/components/common/PreviewNotice.vue'
import UserManagementPanel from '@/components/system/maintenance/UserManagementPanel.vue'
import { useAdminUsers } from '@/composables/useAdminUsers'
import { useSessionStore } from '@/stores/session'

const session = useSessionStore()
const users = useAdminUsers()

async function createUser(input: CreateAdminUserInput): Promise<void> {
  await users.create(input)
}

async function updateUser(userId: string, input: UpdateAdminUserInput): Promise<void> {
  await users.update(userId, input)
}

async function resetUserPassword(userId: string, input: ResetAdminUserPasswordInput): Promise<void> {
  await users.resetPassword(userId, input)
}

onMounted(() => {
  void users.load()
})
</script>

<template>
  <div class="page-view">
    <PageHeader
      title="用户与角色"
      eyebrow="USERS / ACCESS"
      description="管理本地账户、角色权限与临时密码。"
    />
    <div class="users-workspace">
      <PreviewNotice
        v-if="isDemoMode"
        description="用户列表为固定示例；账户创建、修改和密码重置均不会执行。"
      />
      <UserManagementPanel
        :users="users.users.value"
        :loading="users.loading.value"
        :loading-more="users.loadingMore.value"
        :error-message="users.errorMessage.value"
        :operation-error="users.operationError.value"
        :pending-user-id="users.pendingUserId.value"
        :operation-succeeded-id="users.operationSucceededId.value"
        :has-more="Boolean(users.nextCursor.value)"
        :current-user-id="session.user?.id ?? ''"
        :current-role="session.user?.role ?? 'reader'"
        @retry="users.load"
        @search="users.search"
        @load-more="users.load({ append: true })"
        @create="createUser"
        @update="updateUser"
        @reset-password="resetUserPassword"
        @dismiss-operation-error="users.clearOperationError"
      />
    </div>
  </div>
</template>

<style scoped>
.users-workspace {
  display: grid;
  min-width: 0;
  gap: 14px;
}
</style>
