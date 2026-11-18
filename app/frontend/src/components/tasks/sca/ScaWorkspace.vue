<script setup lang="ts">
import { computed, onMounted, onScopeDispose, ref, watch } from 'vue'
import {
  scaApi,
  type Inventory,
  type ScaRun,
  type Occurrence,
  type EnvironmentVersion,
  type ComponentInstance,
  type EnvironmentConfig,
  type Fact,
} from '@/api/sca'
import type { TaskResultState } from '@/components/tasks/taskResultTypes'

const props = defineProps<{
  taskId: string
  mode?: string
  inputType?: string
  userRole: string | null
}>()
const emit = defineEmits<{ stateChange: [state: TaskResultState] }>()
const writable = computed(
  () => props.userRole === 'operator' || props.userRole === 'administrator',
)
const inventories = ref<Inventory[]>([]),
  runs = ref<ScaRun[]>([]),
  items = ref<Occurrence[]>([]),
  environments = ref<EnvironmentVersion[]>([]),
  components = ref<ComponentInstance[]>([])
const summary = ref({
    total: 0,
    open: 0,
    ignored: 0,
    unknown: 0,
    uniqueVulnerabilities: 0,
  }),
  loading = ref(false),
  working = ref(false),
  error = ref(''),
  status = ref('open'),
  severity = ref(''),
  reachability = ref(''),
  source = ref(''),
  environmentFilter = ref(''),
  attackFilter = ref('')
const environmentId = ref(''),
  cursor = ref(''),
  hasMore = ref(false),
  componentOffset = ref(0),
  moreComponents = ref(false),
  selected = ref<Occurrence | null>(null),
  history = ref<unknown[]>([]),
  drawer = ref(false),
  active = ref('vulnerabilities')
const selectedEnvironment = computed(() =>
  environments.value.find((e) => e.id === environmentId.value),
)
const inventory = computed(() => inventories.value[0])
const scaRun = computed(() =>
  runs.value.find(
    (r) => r.kind === 'sca_scan' && ['complete', 'partial'].includes(r.status),
  ),
)
const scanInventory = computed(
  () =>
    scaRun.value?.inventoryId ||
    inventories.value.find((i) => i.runId === scaRun.value?.id)?.id,
)
const running = computed(() =>
  runs.value.some((r) => ['queued', 'running'].includes(r.status)),
)
function currentAssessment(row: Occurrence) {
  const scope = row.dispositions.find(
    (d) => d.environmentVersionId === environmentId.value,
  )
  if (scope && scope.validity !== 'valid') return undefined
  return row.assessments.find(
    (a) =>
      a.environmentVersionId === environmentId.value &&
      Date.parse(a.validUntil) > Date.now(),
  )
}
const latest = computed(() =>
  selected.value ? currentAssessment(selected.value) : undefined,
)
const selectedScope = computed(() =>
  selected.value?.dispositions.find(
    (d) => d.profileId === selectedEnvironment.value?.profileId,
  ),
)
const mode = ref<'suggest' | 'automatic'>('suggest'),
  validHours = ref(24),
  dimensions = ref(['reachability', 'environment', 'attack'])
const envDialog = ref(false),
  editing = ref<EnvironmentVersion | undefined>(),
  envName = ref('生产环境'),
  jdk = ref(17),
  application = ref<'java' | 'spring' | 'war'>(
    props.inputType === 'war' ? 'war' : 'java',
  ),
  entries = ref(''),
  external = ref('')
const facts = ref<
  {
    key: string
    value: string
    verified: boolean
    evidence: string
    expiresAt?: string
  }[]
>([])
const dispositionDialog = ref(false),
  newStatus = ref<'open' | 'ignored'>('open'),
  reason = ref(''),
  holdHours = ref(24),
  linkTask = ref(''),
  linkResult = ref(''),
  capability = ref('')
const collectionTasks = ref(''),
  identityMappings = ref('{}')
let alive = true,
  refreshing = false,
  refreshPending = false,
  timer: ReturnType<typeof setInterval> | undefined
const labels: Record<string, string> = {
  reachable: '可达',
  not_reachable: '模型范围内不可达',
  unknown: '未知',
  not_analyzed: '未分析',
  applicable: '适用',
  not_applicable: '不适用',
  satisfied: '条件满足',
  not_satisfied: '条件不满足',
  open: '待处置',
  ignored: '已忽略',
  manual: '人工',
  policy: '自动策略',
  complete: '完成',
  partial: '部分完成',
  queued: '排队',
  running: '运行中',
  failed: '失败',
  valid: '有效',
  stale: '已失效',
}
const label = (value: string | undefined) =>
  value ? (labels[value] ?? value) : '未分析'
function message(e: unknown) {
  return e instanceof Error ? e.message : '请求失败，请重试。'
}
function query() {
  return Object.fromEntries(
    Object.entries({
      status: status.value,
      severity: severity.value,
      reachability: reachability.value,
      source: source.value,
      environment: environmentFilter.value,
      attack: attackFilter.value,
      environmentProfileId: selectedEnvironment.value?.profileId ?? '',
    }).filter(([, v]) => v),
  )
}
async function refresh() {
  if (refreshing) {
    refreshPending = true
    return
  }
  refreshing = true
  loading.value = items.value.length === 0 && inventories.value.length === 0
  try {
    const [o, v, e] = await Promise.all([
      scaApi.overview(props.taskId),
      scaApi.occurrences(props.taskId, query()),
      scaApi.environments(),
    ])
    if (!alive) return
    inventories.value = o.inventories
    runs.value = o.runs
    items.value = v.items
    summary.value = v.summary
    cursor.value = v.nextCursor
    hasMore.value = v.hasMore
    const oldProfile = selectedEnvironment.value?.profileId
    environments.value = e
    if (!environmentId.value && e[0]) {
      const scope = v.items.flatMap((item) => item.dispositions)[0]
      environmentId.value =
        e.find((env) => env.profileId === scope?.profileId)?.id ?? e[0].id
    }
    if (environmentId.value && !e.some((x) => x.id === environmentId.value)) {
      environmentId.value =
        e.find((x) => x.profileId === oldProfile)?.id ?? e[0]?.id ?? ''
    }
    error.value = ''
    emit('stateChange', { status: 'ready' })
    if (selected.value) {
      selected.value = await scaApi.detail(props.taskId, selected.value.id)
    }
  } catch (e) {
    error.value = message(e)
    emit('stateChange', {
      status: 'error',
      title: '组件分析读取失败',
      description: error.value,
    })
  } finally {
    loading.value = false
    refreshing = false
    if (refreshPending && alive) {
      refreshPending = false
      void refresh()
    }
  }
}
async function more() {
  try {
    const p = await scaApi.occurrences(props.taskId, {
      ...query(),
      cursor: cursor.value,
    })
    items.value.push(...p.items)
    cursor.value = p.nextCursor
    hasMore.value = p.hasMore
  } catch (e) {
    error.value = message(e)
  }
}
async function act(fn: () => Promise<unknown>) {
  if (working.value) return
  working.value = true
  try {
    await fn()
    await refresh()
  } catch (e) {
    error.value = message(e)
  } finally {
    working.value = false
  }
}
async function loadComponents(reset = true) {
  if (!inventory.value) return
  try {
    const p = await scaApi.components(
      props.taskId,
      inventory.value.id,
      reset ? 0 : componentOffset.value,
    )
    components.value = reset ? p.items : [...components.value, ...p.items]
    componentOffset.value = p.nextOffset
    moreComponents.value = p.hasMore
  } catch (e) {
    error.value = message(e)
  }
}
async function select(row: Occurrence) {
  try {
    selected.value = await scaApi.detail(props.taskId, row.id)
    history.value = await scaApi.history(props.taskId, row.id)
    drawer.value = true
  } catch (e) {
    error.value = message(e)
  }
}
function editEnvironment(existing?: EnvironmentVersion) {
  editing.value = existing
  const c = existing?.config
  envName.value = c?.name ?? '生产环境'
  jdk.value = c?.javaRelease ?? 17
  application.value =
    c?.applicationType ?? (props.inputType === 'war' ? 'war' : 'java')
  entries.value = c?.entryPoints.join('\n') ?? ''
  external.value = c?.externalDependencies.join('\n') ?? ''
  facts.value = c
    ? Object.entries(c.facts).map(([key, v]) => ({
        key,
        value: v.value,
        verified: v.verified,
        evidence: v.evidence,
        ...(v.expiresAt ? { expiresAt: v.expiresAt } : {}),
      }))
    : []
  envDialog.value = true
}
async function saveEnvironment() {
  const values: Record<string, Fact> = {}
  for (const f of facts.value) {
    if (!f.key.trim()) continue
    if (values[f.key]) {
      error.value = '环境条件名称不能重复'
      return
    }
    values[f.key] = {
      value: f.value,
      verified: f.verified,
      evidence: f.evidence,
      ...(f.expiresAt ? { expiresAt: f.expiresAt } : {}),
    }
  }
  const config: EnvironmentConfig = {
    name: envName.value,
    javaRelease: jdk.value,
    applicationType: application.value,
    entryPoints: entries.value
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean),
    externalDependencies: external.value
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean),
    facts: values,
  }
  await act(async () => {
    const v = await scaApi.saveEnvironment(config, editing.value)
    environmentId.value = v.id
    envDialog.value = false
  })
}
async function analyze() {
  if (!scaRun.value || !scanInventory.value || !environmentId.value) return
  await act(() =>
    scaApi.analyze(
      props.taskId,
      scaRun.value!.id,
      scanInventory.value!,
      environmentId.value,
      {
        mode: mode.value,
        validHours: validHours.value,
        reachability: dimensions.value.includes('reachability'),
        environment: dimensions.value.includes('environment'),
        attack: dimensions.value.includes('attack'),
      },
    ),
  )
}
function disposition(next: 'open' | 'ignored') {
  newStatus.value = next
  reason.value = ''
  holdHours.value = 24
  dispositionDialog.value = true
}
async function change() {
  if (!selected.value || !selectedEnvironment.value) return
  const expires = new Date(Date.now() + holdHours.value * 3600000).toISOString()
  await act(async () => {
    await scaApi.change(props.taskId, selected.value!.id, {
      environmentVersionId: environmentId.value,
      status: newStatus.value,
      expectedRevision: selectedScope.value?.revision ?? 0,
      reason: reason.value,
      expiresAt: newStatus.value === 'ignored' ? expires : null,
      overrideUntil: newStatus.value === 'open' ? expires : null,
    })
    dispositionDialog.value = false
    history.value = await scaApi.history(props.taskId, selected.value!.id)
  })
}
async function link() {
  await act(async () => {
    linkResult.value = JSON.stringify(
      await scaApi.link(props.taskId, linkTask.value),
      null,
      2,
    )
  })
}
async function collectSWID() {
  await act(async () => {
    const mappings: unknown = JSON.parse(identityMappings.value)
    if (
      !mappings ||
      typeof mappings !== 'object' ||
      Array.isArray(mappings) ||
      Object.values(mappings).some((v) => typeof v !== 'string')
    )
      throw new Error('身份映射必须是 tagId 到 PURL 的 JSON 对象')
    await scaApi.swidCollection(
      props.taskId,
      [
        ...new Set([
          props.taskId,
          ...collectionTasks.value
            .split('\n')
            .map((s) => s.trim())
            .filter(Boolean),
        ]),
      ],
      mappings as Record<string, string>,
    )
  })
}
watch(environmentId, () => {
  void refresh()
})
onMounted(() => {
  void refresh()
  void scaApi
    .capabilities()
    .then((c) => {
      capability.value = JSON.stringify(c.rules, null, 2)
    })
    .catch((e) => {
      error.value = message(e)
    })
  timer = setInterval(() => {
    if (!working.value) void refresh()
  }, 5000)
})
onScopeDispose(() => {
  alive = false
  if (timer) clearInterval(timer)
})
</script>

<template>
  <section class="sca-workspace" v-loading="loading">
    <header class="sca-toolbar">
      <div>
        <h2>
          {{
            mode === 'automatic' ? '组件漏洞与自动处置' : '组件漏洞与影响分析'
          }}
        </h2>
        <p>原始漏洞持续保留，三维结论依据所选目标环境。未知不会自动忽略。</p>
      </div>
      <div class="sca-actions">
        <el-button @click="refresh">刷新</el-button
        ><el-button
          v-if="writable"
          :loading="working"
          :disabled="running"
          @click="act(() => scaApi.scan(taskId))"
          >重新扫描</el-button
        >
      </div>
    </header>
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      show-icon
      :closable="false"
    />
    <div class="sca-metrics">
      <article>
        <span>原始漏洞实例</span><strong>{{ summary.total }}</strong
        ><small>{{ summary.uniqueVulnerabilities }} 个去重漏洞</small>
      </article>
      <article>
        <span>待处置</span><strong>{{ summary.open }}</strong>
      </article>
      <article>
        <span>已忽略</span><strong>{{ summary.ignored }}</strong>
      </article>
      <article>
        <span>含未知结论</span><strong>{{ summary.unknown }}</strong
        ><small>可与待处置重叠</small>
      </article>
    </div>
    <div class="sca-run" role="status">
      <el-tag v-if="running" type="warning">分析执行中</el-tag
      ><template v-if="runs[0]"
        >最近阶段：{{ runs[0].kind }} · {{ label(runs[0].status) }}
        <span v-if="runs[0].quality === 'partial'">（部分覆盖）</span
        ><span v-if="runs[0].error" class="sca-error">{{
          runs[0].error
        }}</span></template
      ><span v-else>扫描尚未生成结果。</span>
    </div>
    <el-tabs
      v-model="active"
      @tab-change="active === 'components' && loadComponents()"
    >
      <el-tab-pane label="漏洞与三维分析" name="vulnerabilities">
        <div class="sca-settings">
          <div class="sca-settings__row">
            <strong>虚拟分析设置 / 目标环境</strong
            ><el-select
              v-model="environmentId"
              placeholder="选择目标环境"
              style="width: 220px"
              ><el-option
                v-for="e in environments"
                :key="e.id"
                :value="e.id"
                :label="`${e.config.name} · Java ${e.config.javaRelease} · v${e.revision}`" /></el-select
            ><el-button v-if="writable" @click="editEnvironment()"
              >新建环境</el-button
            ><el-button
              v-if="writable && selectedEnvironment"
              @click="editEnvironment(selectedEnvironment)"
              >编辑新版本</el-button
            >
          </div>
          <p>
            环境兼容性在此指漏洞触发环境是否适用。保存画像不会验证生产环境；需要可靠证据才能排除触发条件。
          </p>
          <div class="sca-settings__row">
            <el-checkbox-group v-model="dimensions"
              ><el-checkbox value="reachability">漏洞可达性</el-checkbox
              ><el-checkbox value="environment">环境兼容性</el-checkbox
              ><el-checkbox value="attack"
                >漏洞攻击向量</el-checkbox
              ></el-checkbox-group
            ><el-radio-group v-model="mode"
              ><el-radio value="suggest">仅分析并建议</el-radio
              ><el-radio value="automatic"
                >满足证据门槛时自动忽略</el-radio
              ></el-radio-group
            ><label
              >有效期（小时）
              <el-input-number
                v-model="validHours"
                :min="1"
                :max="2160" /></label
            ><el-button
              v-if="writable"
              type="primary"
              :loading="working"
              :disabled="!scaRun || !scanInventory || !environmentId || running"
              @click="analyze"
              >开始三维分析</el-button
            >
          </div>
          <p v-if="props.mode === 'sbom'">
            仅清单输入可分析明确的环境/攻击条件；缺少二进制时，方法级可达性显示未知。
          </p>
        </div>
        <p>
          三维结论按所选环境显示；处置状态汇总所有已纳入的环境。新环境需先发起分析，才会纳入该漏洞的处置范围。
        </p>
        <div class="sca-filters">
          <el-select v-model="status" style="width: 130px" @change="refresh"
            ><el-option value="open" label="待处置" /><el-option
              value="ignored"
              label="已忽略" /><el-option
              value=""
              label="全部状态" /></el-select
          ><el-select
            v-model="severity"
            clearable
            placeholder="严重性"
            style="width: 120px"
            @change="refresh"
            ><el-option
              v-for="s in ['critical', 'high', 'medium', 'low', 'info']"
              :key="s"
              :value="s"
              :label="s" /></el-select
          ><el-select
            v-model="reachability"
            clearable
            placeholder="可达性"
            style="width: 160px"
            @change="refresh"
            ><el-option
              v-for="s in [
                'reachable',
                'not_reachable',
                'unknown',
                'not_analyzed',
              ]"
              :key="s"
              :value="s"
              :label="label(s)" /></el-select
          ><el-select
            v-model="environmentFilter"
            clearable
            placeholder="环境适用性"
            style="width: 150px"
            @change="refresh"
            ><el-option
              v-for="s in ['applicable', 'not_applicable', 'unknown']"
              :key="s"
              :value="s"
              :label="label(s)" /></el-select
          ><el-select
            v-model="attackFilter"
            clearable
            placeholder="攻击条件"
            style="width: 150px"
            @change="refresh"
            ><el-option
              v-for="s in ['satisfied', 'not_satisfied', 'unknown']"
              :key="s"
              :value="s"
              :label="label(s)" /></el-select
          ><el-select
            v-model="source"
            clearable
            placeholder="处置来源"
            style="width: 140px"
            @change="refresh"
            ><el-option value="policy" label="自动策略" /><el-option
              value="manual"
              label="人工"
          /></el-select>
        </div>
        <el-table
          :data="items"
          row-key="id"
          @row-click="select"
          empty-text="当前筛选无结果；请结合扫描状态、组件识别质量和分析覆盖查看。"
          ><el-table-column label="漏洞 / 组件" min-width="240"
            ><template #default="{ row }"
              ><strong>{{ row.vulnerability.id }}</strong>
              <div>
                {{ row.vulnerability.component.name }}
                {{ row.vulnerability.component.version }}
              </div>
              <small>{{
                row.vulnerability.component.path ||
                row.vulnerability.component.sourceRef
              }}</small></template
            ></el-table-column
          ><el-table-column label="严重性" width="95"
            ><template #default="{ row }">{{
              row.vulnerability.severity
            }}</template></el-table-column
          ><el-table-column label="可达性" width="145"
            ><template #default="{ row }">{{
              label(currentAssessment(row)?.reachability)
            }}</template></el-table-column
          ><el-table-column label="环境适用性" width="120"
            ><template #default="{ row }">{{
              label(currentAssessment(row)?.environment)
            }}</template></el-table-column
          ><el-table-column label="攻击条件" width="120"
            ><template #default="{ row }">{{
              label(currentAssessment(row)?.attack)
            }}</template></el-table-column
          ><el-table-column label="汇总状态" width="110"
            ><template #default="{ row }"
              ><el-tag :type="row.status === 'ignored' ? 'info' : 'warning'">{{
                label(row.status)
              }}</el-tag></template
            ></el-table-column
          ></el-table
        >
        <el-button v-if="hasMore" @click="more">加载更多漏洞</el-button>
      </el-tab-pane>
      <el-tab-pane label="组件与清单质量" name="components"
        ><template v-if="inventory"
          ><p>
            {{ inventory.document.standard }}
            {{ inventory.document.specVersion }} ·
            {{ inventory.componentCount }} 个组件 ·
            {{ inventory.dependencyCount }} 条关系 ·
            {{ label(inventory.document.quality) }}
          </p>
          <el-alert
            v-for="(d, i) in inventory.document.diagnostics.slice(0, 30)"
            :key="i"
            :title="`${d.code}：${d.message}${d.ref ? ' · ' + d.ref : ''}`"
            type="warning"
            :closable="false"
          /><el-table :data="components"
            ><el-table-column
              prop="name"
              label="组件"
              min-width="160" /><el-table-column
              prop="version"
              label="版本"
              width="120" /><el-table-column
              prop="purl"
              label="包标识"
              min-width="240" /><el-table-column
              prop="path"
              label="实例路径"
              min-width="240" /><el-table-column
              prop="quality"
              label="识别质量"
              width="120" /></el-table
          ><el-button v-if="moreComponents" @click="loadComponents(false)"
            >加载更多组件</el-button
          >
          <div class="sca-settings" v-if="writable">
            <label>关联另一 SBOM 任务进行身份对照</label
            ><el-input
              v-model="linkTask"
              placeholder="SBOM 任务 ID"
            /><el-button :disabled="!linkTask" @click="link"
              >关联并核对</el-button
            >
            <pre v-if="linkResult">{{ linkResult }}</pre>
            <template v-if="inventory.document.standard === 'SWID'">
              <h4>显式 SWID 标签集合</h4>
              <p>
                先分别上传标签，再填写其他标签的任务
                ID（每行一个）。仅解析这些本地成员及其关联。
              </p>
              <el-input
                v-model="collectionTasks"
                type="textarea"
                :rows="3"
                placeholder="其他 SWID 单标签任务 ID"
              />
              <p>
                可选身份映射：JSON 对象，键为 tagId，值为完整
                PURL。映射作为人工声明保留。
              </p>
              <el-input v-model="identityMappings" type="textarea" :rows="3" />
              <el-button
                :loading="working"
                :disabled="running"
                @click="collectSWID"
                >构建集合并扫描</el-button
              >
            </template>
          </div></template
        ><el-empty v-else description="清单库存尚未生成，请查看扫描阶段。"
      /></el-tab-pane>
      <el-tab-pane label="分析覆盖与规则" name="coverage"
        ><p>
          仅已审校的规则支持确定判定；规则外漏洞仍完整报告。调用图中的反射、未解析依赖、未覆盖运行库或资源限制会保留未知。
        </p>
        <pre>{{ capability }}</pre>
      </el-tab-pane>
    </el-tabs>
    <el-drawer v-model="drawer" title="漏洞证据与处置" size="min(800px,95vw)"
      ><template v-if="selected"
        ><h3>
          {{ selected.vulnerability.id }} · {{ selected.vulnerability.title }}
        </h3>
        <p>{{ selected.vulnerability.description }}</p>
        <p>
          组件：{{
            selected.vulnerability.component.purl ||
            selected.vulnerability.component.name
          }}
        </p>
        <p>路径：{{ selected.vulnerability.component.path }}</p>
        <p>
          修复版本：{{
            selected.vulnerability.fixedVersion || '暂无明确修复版本'
          }}
        </p>
        <h4>原始 CVSS 与来源</h4>
        <pre>{{
          JSON.stringify(
            {
              cvss: selected.vulnerability.cvss,
              dataSource: selected.vulnerability.dataSource,
            },
            null,
            2,
          )
        }}</pre>
        <div class="sca-settings__row">
          <el-select
            v-model="environmentId"
            placeholder="查看环境"
            style="width: 240px"
            ><el-option
              v-for="e in environments"
              :key="e.id"
              :value="e.id"
              :label="e.config.name" /></el-select
          ><el-button
            v-if="writable"
            :disabled="!selectedEnvironment"
            @click="disposition('ignored')"
            >人工忽略</el-button
          ><el-button
            v-if="writable"
            :disabled="!selectedEnvironment"
            @click="disposition('open')"
            >恢复待处置</el-button
          >
        </div>
        <p v-if="selectedScope">
          {{ label(selectedScope.status) }} ·
          {{ label(selectedScope.source) }} ·
          {{ label(selectedScope.validity) }} · {{ selectedScope.reason }}
        </p>
        <template v-if="latest"
          ><h4>当前所选环境的分析</h4>
          <p>
            {{ label(latest.reachability) }} / {{ label(latest.environment) }} /
            {{ label(latest.attack) }}
          </p>
          <p>依据：{{ latest.reason }} · 有效至 {{ latest.validUntil }}</p>
          <h4>调用路径</h4>
          <pre>{{
            latest.code.path.join('\n→ ') || '未产生可证明的调用路径。'
          }}</pre>
          <h4>条件证据与覆盖缺口</h4>
          <pre>{{
            [...latest.evidence, ...latest.code.diagnostics].join('\n') ||
            '无额外诊断'
          }}</pre>
          <p>规则版本：{{ latest.knowledgeDigest }}</p></template
        ><el-alert
          v-else
          title="所选环境尚无分析结果。缺少结果不能作为忽略依据。"
          type="info"
          :closable="false"
        /><el-collapse
          ><el-collapse-item title="分析与处置历史">
            <pre>{{
              JSON.stringify(
                { assessments: selected.assessments, events: history },
                null,
                2,
              )
            }}</pre>
          </el-collapse-item></el-collapse
        ></template
      ></el-drawer
    >
    <el-dialog
      v-model="envDialog"
      :title="editing ? '创建环境新版本' : '新建目标环境'"
      width="min(900px,95vw)"
      ><el-alert
        v-if="error"
        :title="error"
        type="error"
        :closable="false"
      /><el-form label-position="top"
        ><el-form-item label="环境名称"
          ><el-input v-model="envName" maxlength="255"
        /></el-form-item>
        <div class="sca-settings__row">
          <el-form-item label="目标 Java"
            ><el-select v-model="jdk" style="width: 150px"
              ><el-option
                v-for="j in [8, 11, 17, 21]"
                :key="j"
                :value="j"
                :label="`Java ${j}`" /></el-select></el-form-item
          ><el-form-item label="应用入口模型"
            ><el-select v-model="application" style="width: 220px"
              ><el-option
                value="java"
                label="Java / main 与显式入口" /><el-option
                value="spring"
                label="Spring / 保守公共入口" /><el-option
                value="war"
                label="WAR / 保守生命周期入口" /></el-select
          ></el-form-item>
        </div>
        <el-form-item
          label="补充入口（每行一个：包名/类名#方法名(参数描述符)返回描述符）"
          ><el-input
            v-model="entries"
            type="textarea"
            :rows="3" /></el-form-item
        ><el-form-item label="外部依赖任务 ID（已上传的 JAR/WAR，每行一个）"
          ><el-input v-model="external" type="textarea" :rows="2"
        /></el-form-item>
        <p>
          配置事实默认为未验证。只有与对应规则匹配、附有可核查依据且仍有效的事实，才能用于自动排除。
        </p>
        <div v-for="(f, i) in facts" :key="i" class="sca-fact">
          <el-input
            v-model="f.key"
            placeholder="条件名称，如 log4j.contextLookupPattern"
          /><el-input
            v-model="f.value"
            placeholder="值：true / false / 实际值"
          /><el-checkbox v-model="f.verified">有验证证据</el-checkbox
          ><el-input
            v-model="f.evidence"
            type="textarea"
            placeholder="证据来源、范围及确认时间"
          /><el-input
            v-model="f.expiresAt"
            placeholder="证据有效至（可选，如 2026-12-01T00:00:00+08:00）"
          />
          <el-button text type="danger" @click="facts.splice(i, 1)"
            >删除</el-button
          >
        </div>
        <el-button
          @click="
            facts.push({ key: '', value: '', verified: false, evidence: '' })
          "
          >添加环境或攻击条件</el-button
        ></el-form
      ><template #footer
        ><el-button @click="envDialog = false">取消</el-button
        ><el-button type="primary" :loading="working" @click="saveEnvironment"
          >保存不可变新版本</el-button
        ></template
      ></el-dialog
    >
    <el-dialog
      v-model="dispositionDialog"
      :title="newStatus === 'ignored' ? '人工忽略漏洞' : '恢复待处置'"
      width="500px"
      ><p>
        {{
          newStatus === 'ignored'
            ? '该操作是风险处置，不等于已证明不受影响。'
            : '有效期内保留待处置，自动策略不会立即再次忽略。'
        }}
      </p>
      <el-input
        v-model="reason"
        type="textarea"
        :rows="4"
        maxlength="1024"
        placeholder="请填写处置理由"
      />
      <p>
        有效期（小时）
        <el-input-number v-model="holdHours" :min="1" :max="2160" />
      </p>
      <template #footer
        ><el-button @click="dispositionDialog = false">取消</el-button
        ><el-button
          type="primary"
          :disabled="!reason.trim()"
          :loading="working"
          @click="change"
          >确认{{ newStatus === 'ignored' ? '忽略' : '恢复' }}</el-button
        ></template
      ></el-dialog
    >
  </section>
</template>

<style scoped>
.sca-workspace {
  padding: 18px;
  min-width: 0;
}
.sca-toolbar,
.sca-settings__row,
.sca-actions,
.sca-filters {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.sca-toolbar {
  justify-content: space-between;
}
.sca-toolbar h2 {
  font-size: 19px;
  margin: 0;
}
.sca-toolbar p,
.sca-settings p {
  color: var(--text-muted);
  font-size: 13px;
}
.sca-metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
  margin: 20px 0;
}
.sca-metrics article {
  border: 1px solid var(--line);
  padding: 16px;
  border-radius: 8px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.sca-metrics strong {
  font-size: 30px;
}
.sca-metrics span,
.sca-metrics small {
  color: var(--text-muted);
}
.sca-settings {
  background: var(--surface-raised);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 16px;
  margin: 12px 0;
}
.sca-run {
  font-size: 13px;
  margin-bottom: 12px;
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.sca-error {
  color: var(--danger);
}
.sca-filters {
  margin: 14px 0;
}
.sca-fact {
  display: grid;
  grid-template-columns: 2fr 1fr auto;
  gap: 8px;
  padding: 10px 0;
  border-bottom: 1px solid var(--line);
}
.sca-fact .el-textarea {
  grid-column: 1/3;
}
pre {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: var(--surface-raised);
  padding: 12px;
  border-radius: 6px;
  font-size: 12px;
  max-height: 440px;
  overflow: auto;
}
small {
  color: var(--text-muted);
  overflow-wrap: anywhere;
}
h4 {
  margin: 20px 0 8px;
}
@media (max-width: 800px) {
  .sca-metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .sca-fact {
    grid-template-columns: 1fr;
  }
  .sca-fact .el-textarea {
    grid-column: auto;
  }
  .sca-workspace {
    padding: 10px;
  }
}
</style>
