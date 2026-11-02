<script setup lang="ts">
import { computed, onScopeDispose, shallowRef, watch } from 'vue'
import { ChevronRight, Search, Square, Workflow } from 'lucide-vue-next'
import { generateProjectInsight, getSavedProjectArchitecture, type FunctionMatch, type InsightKind, type ProjectInsight } from '@/api/insights'
import { getLLMStatus, llmErrorMessage } from '@/api/llm'
import { isDemoMode } from '@/api/runtime'
import type { DecompileSourceFile } from '@/api/types'
import { useSessionStore } from '@/stores/session'
import ArchitectureDiagram from './ArchitectureDiagram.vue'

const props = defineProps<{ taskId: string; projectId: string; mode: 'architecture' | 'search'; files: readonly DecompileSourceFile[]; loading: boolean }>()
const emit = defineEmits<{ openFile: [fileId: string]; openMatch: [match: FunctionMatch] }>()
const session = useSessionStore()
const architecture = shallowRef<ProjectInsight | null>(null)
const searchResult = shallowRef<ProjectInsight | null>(null)
const busyKind = shallowRef<InsightKind | null>(null)
const error = shallowRef('')
const errorKind = shallowRef<InsightKind | null>(null)
const query = shallowRef('')
const canGenerate = computed(() => session.hasRole(['administrator', 'operator']))
const hasFiles = computed(() => props.files.length > 0)
const busy = computed(() => busyKind.value === props.mode)
const visibleError = computed(() => errorKind.value === props.mode ? error.value : '')
const suggestions = ['找到执行数据库查询的函数', '查找网络请求与通信代码', '定位文件读取和写入逻辑', '寻找鉴权与密码校验函数']
let controller: AbortController | null = null
let cacheController: AbortController | null = null
let generation = 0

function stop(): void {
  controller?.abort()
  controller = null
  generation++
  busyKind.value = null
}
async function generate(kind: InsightKind, text = ''): Promise<void> {
  if (!canGenerate.value || !props.projectId || !hasFiles.value || props.loading || busyKind.value || (kind === 'search' && !text.trim())) return
  const currentGeneration = ++generation
  const active = new AbortController()
  controller = active
  busyKind.value = kind
  error.value = ''
  errorKind.value = kind
  try {
    if (!isDemoMode) {
      const status = await getLLMStatus()
      if (!status.enabled || !status.configured) throw new Error('请先在系统维护 → 大模型设置中启用并配置模型服务。')
    }
    if (active.signal.aborted) return
    const result = await generateProjectInsight(props.taskId, props.projectId, kind, text.trim(), active.signal, kind === 'architecture' && Boolean(architecture.value))
    if (currentGeneration !== generation) return
    if (kind === 'architecture') architecture.value = result
    else searchResult.value = result
  } catch (caught) {
    if (currentGeneration === generation && !active.signal.aborted) error.value = llmErrorMessage(caught)
  } finally {
    if (currentGeneration === generation) { busyKind.value = null; controller = null }
  }
}
function suggest(text: string): void { query.value = text; void generate('search', text) }
watch(() => [props.taskId, props.projectId], async () => {
  stop(); cacheController?.abort(); architecture.value = null; searchResult.value = null; query.value = ''; error.value = ''
  if (!props.taskId || !props.projectId || isDemoMode) return
  const currentGeneration = generation
  const active = new AbortController()
  cacheController = active
  try {
    const saved = await getSavedProjectArchitecture(props.taskId, props.projectId, active.signal)
    if (!active.signal.aborted && currentGeneration === generation && saved) architecture.value = saved
  } catch (caught) {
    if (!active.signal.aborted && currentGeneration === generation) error.value = llmErrorMessage(caught)
  }
}, { immediate: true })
onScopeDispose(() => { stop(); cacheController?.abort() })
</script>

<template>
  <div class="insight-page">
    <template v-if="mode === 'architecture'">
      <header class="insight-hero"><div><span class="insight-eyebrow">SYSTEM MAP / 系统全景</span><h2>理解代码的整体脉络</h2><p>提炼职责模块、调用关系与执行主线，让反编译代码形成一张全景图。</p></div><el-button type="primary" :icon="Workflow" :loading="busy" :disabled="!canGenerate || !projectId || !hasFiles || loading || Boolean(busyKind)" @click="generate('architecture')">{{ architecture ? '重新生成架构' : '生成架构图' }}</el-button></header>
      <div v-if="!architecture && !busy" class="insight-empty"><div class="insight-preview" aria-hidden="true"><span>入口与接口</span><b>→</b><span>核心逻辑</span><b>→</b><span>数据与依赖</span></div><h3>从代码到结构，看清模块如何协作</h3><p>点击“生成架构图”，模型将读取当前项目的源码片段，组织为少量宏观模块与关系。</p><small>结构示意 · 生成后展示真实分析结果</small></div>
    </template>
    <template v-else>
      <header class="insight-hero"><div><span class="insight-eyebrow">SEMANTIC DISCOVERY / 语义探索</span><h2>用一句话找到目标函数</h2><p>描述你想找的行为，查看匹配函数、相关理由与可跳转的源码位置。</p></div></header>
      <form class="semantic-search" @submit.prevent="generate('search', query)"><Search :size="20" /><input v-model="query" maxlength="500" aria-label="自然语言检索函数" placeholder="例如：找到存在数据库查询操作的函数" :disabled="busy" /><el-button type="primary" native-type="submit" :loading="busy" :disabled="!canGenerate || !query.trim() || !projectId || !hasFiles || loading || Boolean(busyKind)">搜索函数</el-button></form>
      <div class="search-suggestions"><span>试试这样问</span><button v-for="suggestion in suggestions" :key="suggestion" type="button" :disabled="!canGenerate || !hasFiles || Boolean(busyKind)" @click="suggest(suggestion)">{{ suggestion }} <span>↗</span></button></div>
      <div v-if="!searchResult && !busy" class="search-empty"><Search :size="28" /><strong>从行为出发，定位实现它的代码</strong><span>检索不要求知道函数名，也支持描述业务逻辑。</span></div>
    </template>
    <p v-if="!canGenerate" class="insight-note">请联系操作员或管理员生成 AI 分析。</p>
    <p v-else-if="!loading && !hasFiles" class="insight-note">当前源码项目没有可分析的文件，请切换项目或等待反编译完成。</p>
    <p v-if="visibleError" class="insight-error" role="alert">{{ visibleError }} <RouterLink v-if="session.user?.role === 'administrator'" :to="{ name: 'system' }">大模型设置</RouterLink></p>
    <div v-if="busy" class="insight-loading" role="status"><span class="loading-orbit" /><div><strong>{{ mode === 'architecture' ? '正在构建代码架构' : '正在检索相关函数' }}</strong><p>抽取源码片段 → 理解代码职责 → {{ mode === 'architecture' ? '组织模块与关系' : '匹配意图与源码位置' }}</p></div><button type="button" @click="stop"><Square :size="13" />停止</button></div>
    <p v-else-if="busyKind" class="insight-note">另一个分析正在生成中，可切换视图查看进度。</p>
    <template v-if="mode === 'architecture' && architecture">
      <p class="insight-coverage"><span v-if="isDemoMode" class="demo-badge">界面预览</span>{{ architecture.model }} · {{ new Date(architecture.createdAt).toLocaleString('zh-CN') }} · 已索引 {{ architecture.coverage.indexedFiles ?? architecture.coverage.totalFiles }} 个文件 · 源码抽样 {{ architecture.coverage.sampledFiles }} 个<span v-if="architecture.coverage.truncated"> · 架构为宏观推断</span></p>
      <ArchitectureDiagram :insight="architecture" :files="files" @open-file="emit('openFile', $event)" />
    </template>
    <template v-if="mode === 'search' && searchResult">
      <div class="search-result-heading"><div><span class="insight-eyebrow">SEARCH RESULTS</span><h3>检索结果 <span>{{ searchResult.result.matches.length }}</span></h3><p>“{{ searchResult.query }}”</p><p>{{ searchResult.result.summary }}</p></div><small><span v-if="isDemoMode" class="demo-badge">界面预览</span>{{ searchResult.model }} · 已索引 {{ searchResult.coverage.indexedFiles ?? searchResult.coverage.totalFiles }} 个文件 · 模型复核 {{ searchResult.coverage.sampledFiles }} 个候选文件<span v-if="searchResult.coverage.truncated"> · 仅复核高相关候选</span></small></div>
      <div v-if="searchResult.result.matches.length" class="match-list"><button v-for="(match, index) in searchResult.result.matches" :key="match.fileId + ':' + match.startLine" type="button" class="match-card" @click="emit('openMatch', match)"><span class="match-index">{{ String(index + 1).padStart(2, '0') }}</span><span class="match-content"><strong>{{ match.name }}</strong><span>{{ match.reason }}</span><code v-if="match.evidence">{{ match.evidence }}</code><small>{{ match.path }} · L{{ match.startLine }}–L{{ match.endLine }}</small></span><ChevronRight :size="18" /></button></div>
      <p v-else class="insight-empty-result">已分析片段中没有匹配函数。可以换一种描述，或先查看源码确认范围。</p>
    </template>
    <footer class="insight-footer">{{ isDemoMode ? '界面预览使用固定示例结果，不会调用模型服务。正式环境使用“大模型设置”中配置的服务。' : '架构图依据全项目索引聚合概览及部分源码样本；函数检索覆盖全量索引，再由“大模型设置”中的模型复核高相关候选。' }}</footer>
  </div>
</template>

<style scoped>
.insight-page { max-width:1400px; margin:auto; padding:28px clamp(18px,3vw,40px) 35px; }.insight-hero { display:flex; align-items:center; justify-content:space-between; gap:15px; margin-bottom:25px; }.insight-eyebrow { color:var(--primary); font-size:10px; letter-spacing:1.5px; font-weight:700; }.insight-hero h2 { margin:9px 0; color:var(--ink-950); font-size:24px; }.insight-hero p { margin:0; color:var(--ink-500); font-size:12px; line-height:1.7; }.insight-coverage { font-size:11px; color:var(--ink-500); margin:18px 0; }.insight-error { padding:12px; border-radius:9px; color:var(--danger); background:var(--danger-soft); font-size:12px; }.insight-error a { margin-left:9px; color:var(--primary); }.insight-note { padding:10px 0; color:var(--ink-600); font-size:12px; }.insight-loading { display:flex; align-items:center; gap:18px; padding:25px; margin:15px 0; border:1px solid var(--primary-border); border-radius:12px; background:var(--primary-soft); color:var(--primary); font-size:13px; }.insight-loading p { margin:8px 0 0; color:var(--ink-500); font-size:11px; }.insight-loading button { margin-left:auto; display:flex; align-items:center; gap:4px; border:0; color:var(--ink-600); background:none; cursor:pointer; }.loading-orbit { width:25px; height:25px; border:2px solid var(--primary-border); border-top-color:var(--primary); border-radius:50%; animation:orbit 1.2s linear infinite; flex-shrink:0; }@keyframes orbit { to { transform:rotate(360deg); } }
.demo-badge { display:inline-flex; margin-right:8px; padding:3px 7px; border-radius:4px; background:var(--primary-soft); color:var(--primary); font-size:10px; font-weight:700; }
.insight-empty { min-height:315px; display:flex; flex-direction:column; justify-content:center; align-items:center; padding:25px; border:1px dashed var(--line-strong); border-radius:15px; text-align:center; background:linear-gradient(150deg,#f8fbff,#fff); }.insight-preview { display:flex; align-items:center; gap:15px; padding:20px; }.insight-preview > span { padding:17px 16px; border:1px solid var(--primary-border); border-radius:10px; color:var(--primary); background:white; font-size:12px; box-shadow:var(--shadow-sm); }.insight-preview b { color:var(--ink-400); font-weight:400; }.insight-empty h3 { font-size:16px; color:var(--ink-950); margin:15px 0 5px; }.insight-empty p { max-width:470px; line-height:1.8; color:var(--ink-500); font-size:12px; }.insight-empty > small { color:var(--ink-400); font-size:10px; }
.semantic-search { display:flex; align-items:center; gap:12px; padding:8px 9px 8px 16px; border:1px solid var(--primary-border); border-radius:12px; box-shadow:0 4px 18px #2563eb0d; }.semantic-search > svg { color:var(--primary); flex-shrink:0; }.semantic-search input { flex:1; min-width:0; border:0; outline:0; color:var(--ink-800); background:transparent; font:inherit; font-size:14px; }.semantic-search:focus-within { outline:2px solid var(--primary-border); }.search-suggestions { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin:14px 0 29px; }.search-suggestions > span { color:var(--ink-400); font-size:11px; margin-right:5px; }.search-suggestions button { border:1px solid var(--line); border-radius:6px; background:var(--surface-raised); padding:7px 9px; color:var(--ink-600); font-size:11px; cursor:pointer; }.search-suggestions button:hover { border-color:var(--primary-border); color:var(--primary); }.search-suggestions button span { color:var(--primary); }.search-suggestions button:disabled { opacity:.5; cursor:default; }.search-result-heading { display:flex; justify-content:space-between; gap:15px; align-items:end; padding-bottom:15px; margin-top:25px; border-bottom:1px solid var(--line); }.search-result-heading h3 { margin:7px 0; color:var(--ink-950); font-size:18px; }.search-result-heading h3 span { color:var(--primary); }.search-result-heading p { margin:5px 0 0; color:var(--ink-600); font-size:12px; line-height:1.7; overflow-wrap:anywhere; }.search-result-heading small { color:var(--ink-400); font-size:10px; flex-shrink:0; }
.match-list { display:grid; grid-template-columns:repeat(auto-fill,minmax(min(330px,100%),1fr)); gap:12px; margin-top:17px; }.match-card { display:flex; gap:13px; min-width:0; padding:17px; border:1px solid var(--line); border-radius:12px; background:var(--surface); text-align:left; cursor:pointer; box-shadow:var(--shadow-sm); }.match-card:hover { border-color:var(--primary); box-shadow:var(--shadow-panel); }.match-index { color:var(--primary); font-size:11px; font-weight:700; }.match-content { display:flex; flex:1; flex-direction:column; gap:8px; min-width:0; }.match-content strong { color:var(--ink-950); font-size:13px; overflow-wrap:anywhere; }.match-content > span { color:var(--ink-600); font-size:12px; line-height:1.6; }.match-content code { padding:8px; border-radius:6px; background:var(--surface-raised); color:var(--ink-600); font-size:10px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }.match-content small { color:var(--primary); overflow-wrap:anywhere; }.match-card > svg { color:var(--ink-400); flex-shrink:0; }.insight-empty-result,.search-empty { color:var(--ink-500); font-size:12px; text-align:center; padding:40px; }.search-empty { min-height:230px; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:14px; border:1px dashed var(--line-strong); border-radius:12px; }.search-empty svg { color:var(--primary); }.search-empty strong { color:var(--ink-800); font-size:14px; }.insight-footer { margin-top:24px; padding-top:16px; border-top:1px solid var(--line); color:var(--ink-400); font-size:10px; line-height:1.8; }
@media(max-width:700px) { .insight-hero { flex-direction:column; align-items:flex-start; }.insight-preview { gap:5px; padding:10px 0; }.insight-preview > span { padding:12px 7px; font-size:10px; }.search-result-heading { flex-direction:column; align-items:flex-start; }.semantic-search input { font-size:12px; } }
@media(prefers-reduced-motion:reduce) { .loading-orbit { animation:none; } }
</style>
