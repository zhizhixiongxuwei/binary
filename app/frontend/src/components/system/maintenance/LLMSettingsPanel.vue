<script setup lang="ts">
import { computed, onMounted, reactive, shallowRef } from 'vue'
import { CheckCircle2, RefreshCw, Save, Wifi } from 'lucide-vue-next'

import { getLLMSettings, llmErrorMessage, saveLLMSettings, testLLMConnection } from '@/api/llm'
import type { LLMSettings, UpdateLLMSettings } from '@/api/llmTypes'
import { isDemoMode } from '@/api/runtime'

const loading = shallowRef(false)
const saving = shallowRef(false)
const testing = shallowRef(false)
const error = shallowRef('')
const feedback = shallowRef('')
const loaded = shallowRef<LLMSettings>()
const apiKey = shallowRef('')
const clearApiKey = shallowRef(false)
const form = reactive({ enabled: false, provider: 'deepseek', baseUrl: 'https://api.deepseek.com', model: 'deepseek-flash', maxInputChars: 60000, timeoutSeconds: 120, maxConcurrent: 2, maxOutputTokens: 4096 })
const busy = computed(() => loading.value || saving.value || testing.value)
const dirty = computed(() => Boolean(loaded.value) && (apiKey.value !== '' || clearApiKey.value || Object.entries(form).some(([key, value]) => value !== loaded.value?.[key as keyof LLMSettings])))

function apply(settings: LLMSettings): void {
  loaded.value = settings
  const { configured: _configured, apiKeyMasked: _masked, ...values } = settings
  Object.assign(form, values, { maxOutputTokens: settings.maxOutputTokens ?? 4096 })
  // Keep the masked response out of the editable secret field.
  apiKey.value = ''
  clearApiKey.value = false
}

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try { apply(await getLLMSettings()) } catch (caught) { error.value = llmErrorMessage(caught) }
  finally { loading.value = false }
}

async function save(): Promise<void> {
  if (busy.value) return
  error.value = ''; feedback.value = ''
  if (!form.baseUrl.trim() || !form.model.trim()) { error.value = '请填写模型接口地址和模型名称'; return }
  saving.value = true
  try {
    const input: UpdateLLMSettings = { ...form, baseUrl: form.baseUrl.trim(), model: form.model.trim(), clearApiKey: clearApiKey.value }
    if (apiKey.value !== '' && !clearApiKey.value) input.apiKey = apiKey.value
    apply(await saveLLMSettings(input))
    feedback.value = '模型设置已保存'
  } catch (caught) { error.value = llmErrorMessage(caught) }
  finally { saving.value = false }
}

async function test(): Promise<void> {
  if (busy.value || dirty.value) return
  testing.value = true; error.value = ''; feedback.value = ''
  try {
    const result = await testLLMConnection()
    if (result.ok === false) throw new Error(result.message || '连接测试失败')
    feedback.value = result.message || '连接成功，模型接口可以使用'
  } catch (caught) { error.value = llmErrorMessage(caught) }
  finally { testing.value = false }
}

onMounted(() => { void load() })
</script>

<template>
  <section class="llm-settings surface-panel" aria-labelledby="llm-settings-title">
    <header class="settings-heading">
      <div><h2 id="llm-settings-title">大模型设置</h2><p>配置反编译源码解释使用的模型服务。</p></div>
      <el-button :icon="RefreshCw" :loading="loading" :disabled="saving || testing" @click="load">刷新</el-button>
    </header>
    <p v-if="isDemoMode" class="settings-note">当前为界面预览，设置只在本页内存中生效，不会连接外部服务。</p>
    <p v-else class="settings-note">API Key 保存于服务端。解释前会展示文件、行号和发送范围。离线部署可关闭此功能，或使用内网兼容服务。</p>
    <p v-if="error" class="settings-error" role="alert">{{ error }}</p>
    <p v-if="feedback" class="settings-success" role="status"><CheckCircle2 :size="16" />{{ feedback }}</p>
    <form v-if="loaded" class="settings-form" @submit.prevent="save">
      <div class="enabled-row"><label for="llm-enabled">启用代码解释</label><el-switch id="llm-enabled" v-model="form.enabled" :disabled="busy" /><span>{{ loaded.configured ? '已配置 API Key' : '尚未配置 API Key' }}</span></div>
      <div class="settings-grid">
        <div class="settings-field"><label for="llm-provider">提供商</label><el-select id="llm-provider" v-model="form.provider" :disabled="busy" aria-label="提供商"><el-option label="DeepSeek" value="deepseek" /><el-option label="OpenAI 兼容 / 内网服务" value="openai-compatible" /></el-select></div>
        <div class="settings-field"><label for="llm-model">模型名称</label><el-input id="llm-model" v-model="form.model" :disabled="busy" placeholder="deepseek-flash" maxlength="128" /></div>
        <div class="settings-field settings-field--wide"><label for="llm-base-url">接口地址</label><el-input id="llm-base-url" v-model="form.baseUrl" :disabled="busy" placeholder="https://api.deepseek.com" maxlength="2048" /><small>填写服务根地址或 /v1 地址。内网服务可使用可达的 HTTP/HTTPS 地址。</small></div>
        <div class="settings-field settings-field--wide"><label for="llm-api-key">API Key</label><el-input id="llm-api-key" v-model="apiKey" type="password" show-password autocomplete="off" :disabled="busy || clearApiKey" :placeholder="loaded.configured ? '已配置；留空保留现有 Key' : '请输入 API Key'" @input="clearApiKey = false" /><small v-if="loaded.configured">当前 Key：{{ loaded.apiKeyMasked || '••••••••' }}</small><el-checkbox v-model="clearApiKey" :disabled="busy || !loaded.configured">清除已保存的 Key</el-checkbox></div>
        <div class="settings-field"><label for="llm-max-input">单次最大发送字符数</label><el-input-number id="llm-max-input" v-model="form.maxInputChars" :min="256" :max="200000" :step="1000" :disabled="busy" /></div>
        <div class="settings-field"><label for="llm-timeout">响应超时（秒）</label><el-input-number id="llm-timeout" v-model="form.timeoutSeconds" :min="5" :max="600" :disabled="busy" /></div>
        <div class="settings-field"><label for="llm-concurrency">最大并发数</label><el-input-number id="llm-concurrency" v-model="form.maxConcurrent" :min="1" :max="8" :disabled="busy" /></div>
        <div class="settings-field"><label for="llm-max-output">最大输出 Token 数</label><el-input-number id="llm-max-output" v-model="form.maxOutputTokens" :min="128" :max="16384" :step="256" :disabled="busy" /></div>
      </div>
      <footer class="settings-actions"><el-button type="primary" native-type="submit" :icon="Save" :loading="saving" :disabled="loading || testing">保存设置</el-button><el-button :icon="Wifi" :loading="testing" :disabled="busy || dirty || !loaded.configured" @click="test">测试连接</el-button><span v-if="dirty">修改后请先保存，再测试连接。</span><span v-else>测试连接只发送固定测试语句，不发送源码。</span></footer>
    </form>
    <div v-else-if="loading" class="settings-loading" role="status">正在读取模型设置…</div>
    <el-button v-else @click="load">重试</el-button>
  </section>
</template>

<style scoped>
.llm-settings { padding: 24px; }
.settings-heading { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
h2 { margin: 0; color: var(--ink-900); font-size: 18px; }
.settings-heading p, .settings-note, .settings-actions > span, small { color: var(--ink-600); font-size: 12px; line-height: 1.7; }
.settings-heading p { margin: 6px 0 0; }
.settings-note { margin: 20px 0; padding: 12px 14px; border-radius: 8px; background: var(--primary-soft); }
.settings-error, .settings-success { display: flex; gap: 8px; padding: 12px; border-radius: 8px; font-size: 13px; }
.settings-error { color: var(--danger); background: var(--danger-soft); }
.settings-success { color: var(--success); background: var(--success-soft); }
.enabled-row { display: flex; align-items: center; flex-wrap: wrap; gap: 14px; margin-bottom: 24px; }
.enabled-row > span { color: var(--ink-500); font-size: 12px; }
.settings-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 22px; }
.settings-field { display: flex; min-width: 0; flex-direction: column; align-items: stretch; gap: 8px; }
.settings-field--wide { grid-column: 1 / -1; }
.settings-field label, .enabled-row label { color: var(--ink-800); font-size: 13px; font-weight: 600; }
.settings-field :deep(.el-input-number) { width: 100%; }
.settings-actions { display: flex; align-items: center; flex-wrap: wrap; gap: 12px; margin-top: 28px; padding-top: 22px; border-top: 1px solid var(--line); }
.settings-actions :deep(.el-button + .el-button) { margin-left: 0; }
.settings-loading { padding: 28px; color: var(--ink-500); }
@media (max-width: 640px) { .llm-settings { padding: 16px; } .settings-grid { grid-template-columns: minmax(0, 1fr); } }
</style>
