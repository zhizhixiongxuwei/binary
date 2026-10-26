<script setup lang="ts">
import { LockKeyhole, ShieldCheck } from 'lucide-vue-next'
import { computed, reactive } from 'vue'

import type { ChangePasswordInput } from '@/api/types'
import {
  type PasswordChangeErrors,
  validatePasswordChange,
} from '@/utils/password'

const props = defineProps<{
  loading: boolean
  errorMessage?: string
}>()

const emit = defineEmits<{
  submit: [value: ChangePasswordInput]
}>()

const form = reactive({
  currentPassword: '',
  newPassword: '',
  confirmation: '',
})
const errors = reactive<PasswordChangeErrors>({})
const canSubmit = computed(
  () =>
    !props.loading &&
    Boolean(form.currentPassword) &&
    Boolean(form.newPassword) &&
    Boolean(form.confirmation),
)

function clearErrors(): void {
  delete errors.currentPassword
  delete errors.newPassword
  delete errors.confirmation
}

function submit(): void {
  if (props.loading) return
  clearErrors()
  Object.assign(errors, validatePasswordChange(form))
  if (Object.keys(errors).length) return

  emit('submit', {
    current_password: form.currentPassword,
    new_password: form.newPassword,
  })
}
</script>

<template>
  <form class="password-form" @submit.prevent="submit">
    <label class="field-label" for="current-password">当前密码</label>
    <el-input
      id="current-password"
      v-model="form.currentPassword"
      size="large"
      type="password"
      show-password
      autocomplete="current-password"
      :disabled="loading"
      :prefix-icon="LockKeyhole"
      :class="{ 'field-input--error': errors.currentPassword }"
      @input="delete errors.currentPassword"
    />
    <span v-if="errors.currentPassword" class="field-error" role="alert">
      {{ errors.currentPassword }}
    </span>

    <label class="field-label field-label--spaced" for="new-password">新密码</label>
    <el-input
      id="new-password"
      v-model="form.newPassword"
      size="large"
      type="password"
      show-password
      autocomplete="new-password"
      :disabled="loading"
      aria-describedby="new-password-hint"
      :prefix-icon="ShieldCheck"
      :class="{ 'field-input--error': errors.newPassword }"
      @input="delete errors.newPassword"
    />
    <p id="new-password-hint" class="field-hint">新密码须为 8–72 字节，且不能与当前密码相同。</p>
    <span v-if="errors.newPassword" class="field-error" role="alert">
      {{ errors.newPassword }}
    </span>

    <label class="field-label field-label--spaced" for="confirm-password">确认新密码</label>
    <el-input
      id="confirm-password"
      v-model="form.confirmation"
      size="large"
      type="password"
      show-password
      autocomplete="new-password"
      :disabled="loading"
      :prefix-icon="ShieldCheck"
      :class="{ 'field-input--error': errors.confirmation }"
      @input="delete errors.confirmation"
    />
    <span v-if="errors.confirmation" class="field-error" role="alert">
      {{ errors.confirmation }}
    </span>

    <div v-if="errorMessage" class="submit-error" role="alert">{{ errorMessage }}</div>

    <el-button
      class="submit-command"
      type="primary"
      size="large"
      native-type="submit"
      :loading="loading"
      :disabled="!canSubmit"
    >
      确认修改
    </el-button>
  </form>
</template>

<style scoped>
.password-form {
  padding: 24px;
}

.field-label {
  display: block;
  margin-bottom: 8px;
  color: var(--ink-800);
  font-size: 12px;
  font-weight: 700;
}

.field-label--spaced {
  margin-top: 18px;
}

.field-error {
  display: block;
  margin-top: 6px;
  color: var(--danger);
  font-size: 12px;
}

.field-hint {
  margin: 8px 0 0;
  color: var(--ink-500);
  font-size: 12px;
  line-height: 1.6;
}

.field-input--error :deep(.el-input__wrapper) {
  box-shadow: 0 0 0 1px var(--danger) inset;
}

.submit-error {
  margin-top: 16px;
  padding: 10px 12px;
  border-left: 3px solid var(--danger);
  color: var(--danger);
  background: var(--danger-soft);
  font-size: 12px;
}

.submit-command {
  width: 100%;
  margin-top: 22px;
}
</style>
