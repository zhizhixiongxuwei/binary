<script setup lang="ts">
import { LockKeyhole, User } from 'lucide-vue-next'
import { computed, reactive } from 'vue'

import type { LoginInput } from '@/api/types'
import LoginRateLimitAlert from '@/components/auth/LoginRateLimitAlert.vue'

const props = defineProps<{
  loading: boolean
  errorMessage?: string
  retryAfterSeconds?: number
}>()

const emit = defineEmits<{
  submit: [value: LoginInput]
}>()

const form = reactive<LoginInput>({
  username: '',
  password: '',
})
const isRateLimited = computed(
  () =>
    Number.isSafeInteger(props.retryAfterSeconds) &&
    (props.retryAfterSeconds ?? 0) > 0,
)
const canSubmit = computed(
  () =>
    !props.loading &&
    !isRateLimited.value &&
    Boolean(form.username.trim()) &&
    Boolean(form.password),
)

function submit(): void {
  if (!canSubmit.value) return
  emit('submit', {
    username: form.username.trim(),
    password: form.password,
  })
}
</script>

<template>
  <form class="login-form" @submit.prevent="submit">
    <label class="field-label" for="username">用户名</label>
    <el-input
      id="username"
      v-model="form.username"
      size="large"
      autocomplete="username"
      placeholder="请输入用户名"
      :prefix-icon="User"
    />

    <label class="field-label field-label--spaced" for="password">密码</label>
    <el-input
      id="password"
      v-model="form.password"
      size="large"
      type="password"
      show-password
      autocomplete="current-password"
      placeholder="请输入密码"
      :prefix-icon="LockKeyhole"
    />

    <div class="login-feedback">
      <LoginRateLimitAlert
        v-if="isRateLimited"
        :remaining-seconds="retryAfterSeconds ?? 1"
      />
      <div v-else-if="errorMessage" class="login-error" role="alert">
        {{ errorMessage }}
      </div>
      <div v-else class="login-feedback__placeholder" aria-hidden="true" />
    </div>

    <el-button
      class="login-command"
      type="primary"
      size="large"
      native-type="submit"
      :loading="loading"
      :disabled="!canSubmit"
      :aria-describedby="isRateLimited ? 'login-rate-limit-status' : undefined"
    >
      登录
    </el-button>
  </form>
</template>

<style scoped>
.login-form {
  margin-top: 26px;
}

.field-label {
  display: block;
  margin-bottom: 10px;
  color: var(--ink-700);
  font-size: 13px;
  font-weight: 500;
}

.field-label--spaced {
  margin-top: 22px;
}

.login-form :deep(.el-input__wrapper) {
  min-height: 48px;
  padding: 1px 15px;
  border-radius: 10px;
  background: var(--surface-raised);
  box-shadow: 0 0 0 1px var(--line-strong) inset;
}

.login-form :deep(.el-input__wrapper:hover) {
  box-shadow: 0 0 0 1px var(--primary-border) inset;
}

.login-form :deep(.el-input__wrapper.is-focus) {
  background: var(--surface);
  box-shadow: 0 0 0 1px var(--primary) inset, 0 0 0 3px var(--primary-soft);
}

.login-form :deep(.el-input__prefix) {
  margin-right: 4px;
  color: var(--ink-400);
}

.login-form :deep(.el-input__inner) {
  font-size: 13px;
}

.login-feedback {
  margin-top: 15px;
  min-height: 44px;
}

.login-feedback__placeholder {
  min-height: 44px;
}

.login-error {
  min-height: 44px;
  padding: 10px 12px;
  border: 1px solid var(--danger-border);
  border-radius: var(--radius-sm);
  display: flex;
  align-items: center;
  color: var(--danger);
  background: var(--danger-soft);
  font-size: 12px;
  line-height: 1.5;
}

.login-command {
  width: 100%;
  min-height: 48px;
  margin-top: 10px;
  border-radius: 10px;
  font-size: 15px;
  font-weight: 500;
  letter-spacing: 0.1em;
}
</style>
