<script setup lang="ts">
import { Binary, CheckCircle2, Database, HardDrive } from 'lucide-vue-next'
import { shallowRef } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { ApiError } from '@/api/client'
import { isDemoMode } from '@/api/runtime'
import type { LoginInput } from '@/api/types'
import loginIllustration from '@/assets/login-illustration.svg'
import LoginForm from '@/components/auth/LoginForm.vue'
import { useLoginRateLimit } from '@/composables/useLoginRateLimit'
import { PRODUCT_DESCRIPTION, PRODUCT_NAME, PRODUCT_SHORT_NAME } from '@/config/branding'
import { useSessionStore } from '@/stores/session'

const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const loading = shallowRef(false)
const errorMessage = shallowRef('')
const {
  remainingSeconds,
  isRateLimited,
  start: startRateLimit,
} = useLoginRateLimit()

function isRateLimitError(error: unknown): error is ApiError {
  return (
    error instanceof ApiError &&
    error.status === 429 &&
    error.code === 'login_rate_limited'
  )
}

function safeLoginErrorMessage(error: unknown): string {
  if (
    error instanceof ApiError &&
    (error.status === 401 ||
      error.code?.toLocaleLowerCase('en-US') === 'invalid_credentials')
  ) {
    return '用户名或密码错误'
  }
  return error instanceof ApiError ? error.message : '登录服务暂不可用'
}

async function handleLogin(input: LoginInput): Promise<void> {
  if (loading.value || isRateLimited.value) return
  loading.value = true
  errorMessage.value = ''
  try {
    await session.login(input)
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
    await router.replace(redirect)
  } catch (error) {
    if (isRateLimitError(error)) {
      startRateLimit(error.retryAfterSeconds)
      errorMessage.value = ''
    } else {
      errorMessage.value = safeLoginErrorMessage(error)
    }
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <main class="login-page">
    <section class="identity-panel" aria-label="系统标识">
      <div class="identity-content">
        <div class="identity-heading">
          <span class="identity-kicker">二进制 · 归档 · 镜像</span>
          <h1>让代码分析更清晰</h1>
          <p class="identity-subtitle">专注二进制代码静态分析，高效管理每一次检测</p>
        </div>
        <img class="identity-illustration" :src="loginIllustration" alt="" aria-hidden="true" />
        <div class="identity-meta">
          <span><CheckCircle2 :size="16" aria-hidden="true" />离线部署</span>
          <span><HardDrive :size="16" aria-hidden="true" />文件仓库</span>
          <span><Database :size="16" aria-hidden="true" />漏洞库</span>
        </div>
      </div>
    </section>

    <section class="login-panel" aria-labelledby="login-title">
      <div class="login-box">
        <div class="login-brand" :aria-label="PRODUCT_NAME">
          <span class="login-brand-mark" aria-hidden="true"><Binary :size="27" /></span>
          <div class="login-brand-copy">
            <strong>{{ PRODUCT_SHORT_NAME }}</strong>
            <span>{{ PRODUCT_DESCRIPTION }}</span>
          </div>
        </div>
        <div class="login-heading">
          <h2 id="login-title">欢迎登录</h2>
          <p>登录账号，开始您的分析工作</p>
        </div>
        <p v-if="isDemoMode" class="demo-login-note">
          使用 demo-reader 或 demo-operator 可预览对应权限，其他非空用户名使用管理员权限。
        </p>
        <p v-if="route.query.reason === 'password-changed'" class="password-changed-note" role="status">
          <CheckCircle2 :size="17" aria-hidden="true" />
          <span>密码已修改，请使用新密码重新登录。</span>
        </p>
        <LoginForm
          :loading="loading"
          :error-message="errorMessage"
          :retry-after-seconds="remainingSeconds"
          @submit="handleLogin"
        />
        <footer class="login-footer">
          <span class="status-dot" aria-hidden="true" />
          <span>本地分析工作台</span>
          <span class="login-footer-divider" aria-hidden="true" />
          <span>内网部署</span>
        </footer>
      </div>
    </section>
  </main>
</template>

<style scoped>
.password-changed-note {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin: 0 0 20px;
  padding: 12px 14px;
  border: 1px solid var(--success-border);
  border-radius: var(--radius-sm);
  color: var(--success);
  background: var(--success-soft);
  font-size: 13px;
  line-height: 1.6;
}

.password-changed-note > svg {
  flex-shrink: 0;
  margin-top: 2px;
}

.login-page {
  display: grid;
  min-height: 100vh;
  grid-template-columns: minmax(0, 1.12fr) minmax(420px, 0.88fr);
  padding: 48px max(5vw, 32px);
  background: #f1f6fe;
}

.identity-panel {
  display: flex;
  min-width: 0;
  align-items: center;
  justify-content: center;
}

.identity-content {
  width: min(640px, 100%);
  padding-right: 26px;
}

.identity-heading {
  padding-left: 58px;
}

.identity-kicker {
  display: inline-flex;
  align-items: center;
  min-height: 30px;
  padding: 4px 12px;
  border: 1px solid #dbe7fb;
  border-radius: 20px;
  color: var(--primary);
  background: #e8f0fd;
  font-size: 12px;
  letter-spacing: 0.06em;
}

.identity-content h1 {
  margin: 20px 0 0;
  color: #224373;
  font-size: clamp(30px, 2.5vw, 38px);
  font-weight: 650;
  line-height: 1.35;
  letter-spacing: 0.03em;
}

.identity-subtitle {
  margin: 14px 0 0;
  color: #6e85a5;
  font-size: 14px;
  line-height: 1.7;
}

.identity-illustration {
  display: block;
  width: 100%;
  height: auto;
  margin: 10px auto 0;
  user-select: none;
}

.identity-meta {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 32px;
  margin-top: 2px;
  color: #6882a7;
  font-size: 12px;
}

.identity-meta span {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  white-space: nowrap;
}

.identity-meta svg {
  color: #658cd0;
}

.login-panel {
  display: flex;
  min-width: 0;
  align-items: center;
  justify-content: center;
}

.login-box {
  width: min(448px, 100%);
  padding: 40px 40px 26px;
  border: 1px solid #e7eef9;
  border-radius: 24px;
  background: var(--surface);
  box-shadow: 0 16px 56px rgb(60 93 148 / 8%);
}

.login-brand {
  display: flex;
  align-items: center;
  gap: 13px;
  padding-bottom: 28px;
  border-bottom: 1px solid var(--line);
}

.login-brand-mark {
  display: grid;
  width: 50px;
  height: 50px;
  flex: 0 0 50px;
  place-items: center;
  border-radius: 14px;
  color: var(--surface);
  background: var(--primary);
  box-shadow: 0 5px 14px rgb(37 99 235 / 16%);
}

.login-brand-copy {
  min-width: 0;
}

.login-brand-copy strong,
.login-brand-copy span {
  display: block;
}

.login-brand-copy strong {
  color: var(--ink-950);
  font-size: 22px;
  line-height: 1.35;
  letter-spacing: 0.05em;
}

.login-brand-copy span {
  margin-top: 5px;
  color: var(--ink-600);
  font-size: 11px;
  line-height: 1.65;
}

.login-heading {
  margin-top: 28px;
}

.login-heading h2 {
  margin: 0;
  color: var(--ink-950);
  font-size: 25px;
  font-weight: 600;
  line-height: 1.4;
}

.login-heading p {
  margin: 8px 0 0;
  color: var(--ink-500);
  font-size: 13px;
  line-height: 1.6;
}

.demo-login-note {
  margin: 18px 0 -10px;
  padding: 10px 12px;
  border: 1px solid var(--warning-border);
  border-radius: var(--radius-sm);
  color: var(--warning);
  background: var(--warning-soft);
  font-size: 11px;
  line-height: 1.65;
}

.login-footer {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 7px;
  margin-top: 26px;
  padding-top: 22px;
  border-top: 1px solid var(--line);
  color: var(--ink-500);
  font-size: 11px;
}

.login-footer-divider {
  width: 1px;
  height: 10px;
  margin: 0 4px;
  background: var(--line-strong);
}

.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--primary);
}

@media (max-width: 1100px) {
  .login-page {
    grid-template-columns: minmax(0, 1fr) minmax(380px, 0.95fr);
    padding: 36px 32px;
  }

  .identity-content {
    padding-right: 12px;
  }

  .identity-heading {
    padding-left: 28px;
  }

  .identity-content h1 {
    font-size: 29px;
  }

  .identity-subtitle {
    max-width: 270px;
    font-size: 13px;
  }

  .identity-meta {
    gap: 18px;
  }

  .login-box {
    padding-right: 32px;
    padding-left: 32px;
  }
}

@media (max-width: 820px) {
  .login-page {
    grid-template-columns: 1fr;
    align-content: center;
    gap: 28px;
    padding: 36px 24px;
  }

  .identity-content {
    padding: 0;
  }

  .identity-heading {
    padding: 0;
    text-align: center;
  }

  .identity-content h1 {
    margin-top: 12px;
    font-size: 28px;
  }

  .identity-subtitle {
    max-width: none;
    margin-top: 8px;
  }

  .identity-illustration,
  .identity-meta {
    display: none;
  }
}

@media (max-width: 440px) {
  .login-page {
    gap: 24px;
    padding: 28px 16px;
  }

  .identity-kicker {
    min-height: 26px;
    font-size: 10px;
  }

  .identity-content h1 {
    font-size: 25px;
  }

  .identity-subtitle {
    font-size: 11px;
  }

  .login-box {
    padding: 28px 24px 22px;
    border-radius: 20px;
  }

  .login-brand {
    padding-bottom: 22px;
  }

  .login-brand-mark {
    width: 44px;
    height: 44px;
    flex-basis: 44px;
    border-radius: 12px;
  }

  .login-brand-copy strong {
    font-size: 20px;
  }

  .login-brand-copy span {
    font-size: 10px;
  }

  .login-heading {
    margin-top: 22px;
  }

  .login-heading h2 {
    font-size: 23px;
  }
}
</style>
