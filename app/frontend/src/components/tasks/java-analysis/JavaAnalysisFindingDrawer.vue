<script setup lang="ts">
import { Code2, ExternalLink, FileCode2, MapPin, ShieldAlert } from 'lucide-vue-next'
import { computed, onBeforeUnmount, onMounted, shallowRef } from 'vue'

import type { JavaAnalysisFinding, JavaBytecodeLocation, JavaNullnessTraceStep, SourceNavigationTarget } from '@/api/types'
import { javaFindingSourceTarget } from '@/components/tasks/results/sourceNavigation'
import { javaFindingMessage } from '@/utils/analyzerMessages'

const props = defineProps<{
  finding: JavaAnalysisFinding | undefined
}>()

const emit = defineEmits<{
  close: []
  openSource: [target: SourceNavigationTarget]
}>()

const MAX_DRAWER_WIDTH = 620
const VIEWPORT_WIDTH_RATIO = 0.92
const drawerSize = shallowRef(MAX_DRAWER_WIDTH)

function updateDrawerSize(): void {
  const viewportWidth =
    document.documentElement.clientWidth || globalThis.innerWidth || MAX_DRAWER_WIDTH
  drawerSize.value = Math.max(
    1,
    Math.min(MAX_DRAWER_WIDTH, Math.floor(viewportWidth * VIEWPORT_WIDTH_RATIO)),
  )
}

onMounted(() => {
  updateDrawerSize()
  globalThis.addEventListener('resize', updateDrawerSize, { passive: true })
})

onBeforeUnmount(() => {
  globalThis.removeEventListener('resize', updateDrawerSize)
})

function handleVisibility(visible: boolean): void {
  if (!visible) emit('close')
}

function locationLabel(finding: JavaAnalysisFinding): string {
  const value = finding.location
  return value ? `${value.start_line}:${value.start_column} - ${value.end_line}:${value.end_column}` : '—'
}

function bytecodeLocationLabel(location: JavaBytecodeLocation): string {
  const { original_line, bytecode_offset } = location
  const parts = []
  if (original_line !== undefined) parts.push(`原始源码第 ${original_line} 行`)
  if (bytecode_offset !== undefined) parts.push(`字节码偏移 ${bytecode_offset}`)
  return parts.join(' · ') || '以类和方法定位'
}

interface SnippetLine {
  key: number
  label: string
  labelTitle: string
  text: string
  hit: boolean
}

const snippetLines = computed<readonly SnippetLine[]>(() => {
  const finding = props.finding
  const location = finding?.location
  if (!finding?.snippet || !location) return []

  const snippetStartLine = finding.snippet_start_line
  if (!snippetStartLine) return []

  return finding.snippet.split(/\r\n|\n|\r/).map((text, index) => {
    const sourceLine = snippetStartLine + index
    return {
      key: sourceLine,
      label: String(sourceLine),
      labelTitle: `源码第 ${sourceLine} 行`,
      text,
      hit:
        sourceLine >= location.start_line &&
        sourceLine <= location.end_line,
    }
  })
})
const sourceTarget = computed(() =>
  props.finding ? javaFindingSourceTarget(props.finding) : undefined,
)

const traceLabels: Record<string, string> = { 'nullable-source': '可空来源', 'return-source': '返回值来源', return: '返回传递', argument: '参数传递', branch: '分支条件', sink: '解引用' }
const securityLabels: Record<string, string> = { source: '输入来源', propagation: '数据传递', call: '方法调用', return: '返回传递', validation: '校验条件', execution: '危险执行点', 'class-definition': '动态类定义', registration: '组件注册', trigger: '分支触发条件', authentication: '认证成功分支', configuration: '配置来源', binding: '源码用途', codec: '编解码器构造', 'codec-use': '编解码器使用', deserialization: '反序列化', 'raw-sql': '原始 SQL 片段', 'sql-template': 'SQL 模板', 'sql-execution': 'SQL 执行' }
function openTrace(step: JavaNullnessTraceStep): void {
  const projectId = props.finding?.source_project_id || props.finding?.file.result_id
  if (!projectId) return
  emit('openSource', { projectId, path: step.path, startLine: step.line, endLine: step.line, startColumn: step.column, endColumn: step.column })
}
function openSource(): void {
  if (sourceTarget.value) emit('openSource', sourceTarget.value)
}
</script>

<template>
  <el-drawer
    :model-value="finding !== undefined"
    :title="finding?.location ? 'Java 源码检测详情' : 'Java 字节码检测详情'"
    :size="drawerSize"
    append-to-body
    @update:model-value="handleVisibility"
  >
    <article v-if="finding" class="finding-detail">
      <header class="finding-detail__header">
        <span class="severity" :class="`severity--${finding.severity.toLowerCase()}`">
          {{ finding.severity }}
        </span>
        <code>{{ finding.cwe }}</code>
        <code>{{ finding.rule_id }}</code>
        <code v-if="finding.location && finding.bytecode">双引擎命中</code>
        <code v-if="finding.bytecode">SpotBugs {{ finding.bytecode.tool_version }}</code>
        <code v-if="finding.bytecode">{{ finding.bytecode.pattern }}</code>
      </header>

      <section>
        <h3><ShieldAlert :size="15" aria-hidden="true" />检测结论</h3>
        <p>{{ javaFindingMessage(finding.rule_id, finding.message) }}</p>
      </section>

      <dl>
        <div>
          <dt><FileCode2 :size="13" aria-hidden="true" />文件</dt>
          <dd>
            <strong>{{ finding.file.logical_path }}</strong>
            <code>{{ finding.file.binary_name }}</code>
          </dd>
        </div>
        <div>
          <dt><Code2 :size="13" aria-hidden="true" />类型 / 方法</dt>
          <dd>
            <strong>{{ finding.callable.type_name }}</strong>
            <code>{{ finding.callable.kind }} {{ finding.callable.name }}</code>
            <code v-if="finding.callable.signature">{{ finding.callable.signature }}</code>
          </dd>
        </div>
        <div v-if="finding.location">
          <dt><MapPin :size="13" aria-hidden="true" />源码位置</dt>
          <dd><code>{{ locationLabel(finding) }}</code></dd>
        </div>
        <div v-else-if="finding.decompiled_location">
          <dt><MapPin :size="13" aria-hidden="true" />反编译位置</dt>
          <dd><code>{{ finding.decompiled_location.path }}:{{ finding.decompiled_location.line }}</code></dd>
        </div>
        <div v-if="finding.bytecode">
          <dt><MapPin :size="13" aria-hidden="true" />字节码位置</dt>
          <dd><code>{{ bytecodeLocationLabel(finding.bytecode) }}</code></dd>
        </div>
      </dl>

      <section v-if="finding.nullness_trace?.length" class="nullness-trace">
        <h3>空值传播路径 · {{ finding.nullness_certainty === 'definite' ? '确定为空' : '条件性风险' }}</h3>
        <ol>
          <li v-for="(step, index) in finding.nullness_trace" :key="index">
            <strong>{{ traceLabels[step.kind] ?? step.kind }}</strong>：{{ step.message }}
            <button type="button" @click="openTrace(step)">{{ step.path }}:{{ step.line }}:{{ step.column }}</button>
          </li>
        </ol>
        <small v-if="finding.nullness_model_version">模型 {{ finding.nullness_model_version }} · 位置为反编译源码位置</small>
      </section>

      <section v-if="finding.security_trace?.length" class="nullness-trace">
        <h3>安全行为证据 · {{ finding.security_certainty === 'configuration-risk' ? '配置风险待核验' : '条件性风险' }}</h3>
        <p v-if="finding.security_runtime_override === 'unknown'">打包配置的运行时覆盖情况尚未确认，密钥值已脱敏。</p>
        <ol>
          <li v-for="(step, index) in finding.security_trace" :key="index">
            <strong>{{ securityLabels[step.kind] ?? step.kind }}</strong>：{{ step.message }}
            <button type="button" @click="openTrace(step)">{{ step.path }}:{{ step.line }}:{{ step.column }}</button>
          </li>
        </ol>
        <p v-if="finding.security_entry_verified === false && finding.security_certainty !== 'configuration-risk'">此路径的 HTTP 入口可达性仍需复核。</p>
        <small>证据描述可疑能力或配置风险，尚未证明恶意植入或完整可利用链。</small>
      </section>
      <section v-if="finding.security_binding_locations?.length" class="nullness-trace">
        <h3>关联源码用途</h3>
        <ol><li v-for="(step,index) in finding.security_binding_locations" :key="index">{{ step.message }}<button type="button" @click="openTrace(step)">{{ step.path }}:{{ step.line }}</button></li></ol>
      </section>
      <section v-if="finding.location" class="snippet-section">
        <div class="snippet-heading">
          <h3><Code2 :size="15" aria-hidden="true" />检测片段</h3>
          <span class="snippet-hit-location">
            <MapPin :size="12" aria-hidden="true" />
            命中 <code>{{ locationLabel(finding) }}</code>
          </span>
        </div>
        <div
          v-if="snippetLines.length > 0"
          class="snippet-code"
          role="region"
          tabindex="0"
          aria-label="Java 源码检测片段"
        >
          <div
            v-for="line in snippetLines"
            :key="line.key"
            class="snippet-line"
            :class="{ 'snippet-line--hit': line.hit }"
            :aria-current="line.hit ? 'location' : false"
          >
            <span class="snippet-gutter" :title="line.labelTitle">{{ line.label }}</span>
            <code>{{ line.text }}</code>
          </div>
        </div>
        <p v-else class="snippet-empty">该发现没有保存源码片段。</p>
      </section>

      <el-button
        v-if="finding.location || finding.decompiled_location"
        type="primary"
        plain
        :disabled="!sourceTarget"
        @click="openSource"
      >
        <ExternalLink :size="14" aria-hidden="true" />
        打开 Java 源码
      </el-button>
    </article>
  </el-drawer>
</template>

<style scoped>
.nullness-trace ol { padding-left: 22px; }
.nullness-trace li { margin-bottom: 12px; overflow-wrap: anywhere; }
.nullness-trace button { display: block; border: 0; padding: 4px 0; color: var(--primary); background: transparent; cursor: pointer; text-align: left; }

.finding-detail { display: grid; gap: 18px; color: var(--ink-600); }
.finding-detail__header { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding-bottom: 12px; border-bottom: 1px solid var(--line); }
.finding-detail__header code { color: var(--ink-800); font-size: 12px; }
.finding-detail section { display: grid; gap: 8px; }
.finding-detail h3 { display: flex; align-items: center; gap: 7px; margin: 0; color: var(--ink-800); font-size: 13px; }
.finding-detail p { margin: 0; line-height: 1.7; font-size: 12px; }
.finding-detail dl { margin: 0; border: 1px solid var(--line); border-radius: var(--radius-sm); }
.finding-detail dl div { display: grid; grid-template-columns: 105px minmax(0, 1fr); gap: 12px; padding: 10px 12px; border-bottom: 1px solid var(--line); }
.finding-detail dl div:last-child { border-bottom: 0; }
.finding-detail dt { display: flex; align-items: center; gap: 6px; font-size: 11px; }
.finding-detail dd { display: grid; min-width: 0; gap: 3px; margin: 0; color: var(--ink-800); font-size: 12px; }
.finding-detail dd code { overflow-wrap: anywhere; }
.snippet-heading { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; }
.snippet-hit-location { display: inline-flex; align-items: center; gap: 5px; color: var(--ink-500); font-size: 11px; }
.snippet-hit-location code { color: var(--ink-800); font-size: 11px; }
.snippet-code { max-height: 340px; overflow: auto; border: 1px solid var(--line); border-radius: var(--radius-sm); color: var(--ink-800); background: var(--surface); font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace; font-size: 12px; line-height: 1.65; }
.snippet-line { display: grid; min-width: max-content; grid-template-columns: 48px minmax(0, 1fr); }
.snippet-line code { display: block; min-height: 1.65em; padding: 2px 14px; color: inherit; white-space: pre; }
.snippet-line--hit { background: var(--primary-soft); box-shadow: inset 3px 0 var(--primary); }
.snippet-line--hit code { color: var(--primary-active); }
.snippet-gutter { display: block; padding: 2px 9px; border-right: 1px solid var(--line); color: var(--ink-400); text-align: right; user-select: none; }
.snippet-line--hit .snippet-gutter { color: var(--primary-active); }
.snippet-empty { margin: 0; padding: 14px; border: 1px solid var(--line); border-radius: var(--radius-sm); color: var(--ink-600); background: var(--surface); font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace; font-size: 12px; }
.severity { display: inline-flex; min-height: 23px; align-items: center; padding: 2px 7px; border: 1px solid var(--line-strong); border-radius: var(--radius-sm); font-size: 11px; font-weight: 800; }
.severity--critical { border-color: var(--danger-border); color: var(--danger); background: var(--danger-soft); }
.severity--high { border-color: var(--orange-border); color: var(--orange); background: var(--orange-soft); }
.severity--medium { border-color: var(--warning-border); color: var(--warning); background: var(--warning-soft); }
.severity--low { border-color: var(--primary-border); color: var(--primary); background: var(--primary-soft); }
</style>
