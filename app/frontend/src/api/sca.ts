import { fetchLiveResponse } from '@/api/live/client'
import { createIdempotencyKey } from '@/utils/idempotency'

export interface ComponentInstance {
  id: string
  sourceRef: string
  name: string
  group?: string
  version: string
  purl?: string
  path: string
  quality: string
  sha256?: string
}
export interface Inventory {
  id: string
  runId: string
  componentCount: number
  dependencyCount: number
  createdAt: string
  document: {
    standard: string
    encoding: string
    specVersion: string
    quality: string
    fingerprint: string
    diagnostics: { code: string; message: string; ref?: string }[]
  }
}
export interface ScaRun {
  id: string
  kind: string
  status: string
  quality: string
  error: string
  inventoryId: string
}
export interface Fact {
  value: string
  verified: boolean
  evidence: string
  expiresAt?: string
}
export interface EnvironmentConfig {
  name: string
  javaRelease: number
  applicationType: 'java' | 'spring' | 'war'
  entryPoints: string[]
  externalDependencies: string[]
  facts: Record<string, Fact>
}
export interface EnvironmentVersion {
  id: string
  profileId: string
  revision: number
  fingerprint: string
  config: EnvironmentConfig
}
export interface Policy {
  mode: 'suggest' | 'automatic'
  validHours: number
  reachability: boolean
  environment: boolean
  attack: boolean
}
export interface Assessment {
  id: string
  runId: string
  environmentVersionId: string
  profileId: string
  reachability: string
  environment: string
  attack: string
  excluded: boolean
  reason: string
  evidence: string[]
  validUntil: string
  knowledgeDigest: string
  code: {
    state: string
    path: string[]
    diagnostics: string[]
    complete: boolean
    engineVersion: string
    viewDigest: string
  }
}
export interface Disposition {
  profileId: string
  environmentVersionId: string
  status: 'open' | 'ignored'
  source: 'manual' | 'policy'
  revision: number
  reason: string
  validity: string
  expiresAt?: string
  overrideUntil?: string
}
export interface Occurrence {
  id: string
  taskId: string
  status: 'open' | 'ignored'
  vulnerability: {
    id: string
    componentId: string
    component: ComponentInstance
    severity: string
    title: string
    description: string
    fixedVersion: string
    primaryUrl: string
    cvss?: unknown
    dataSource?: unknown
  }
  assessments: Assessment[]
  dispositions: Disposition[]
}
export interface ScaSummary {
  total: number
  open: number
  ignored: number
  unknown: number
  uniqueVulnerabilities: number
}
type Obj = Record<string, unknown>
function object(v: unknown): Obj {
  if (!v || typeof v !== 'object' || Array.isArray(v))
    throw new Error('组件分析接口返回了无效数据')
  return v as Obj
}
function text(v: unknown): string {
  if (typeof v !== 'string') throw new Error('组件分析接口缺少文本字段')
  return v
}
function number(v: unknown): number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0)
    throw new Error('组件分析接口计数无效')
  return v
}
function boolean(v: unknown): boolean {
  if (typeof v !== 'boolean') throw new Error('组件分析接口状态无效')
  return v
}
function list(v: unknown): unknown[] {
  if (v === null) return []
  if (!Array.isArray(v)) throw new Error('组件分析接口列表无效')
  return v
}
function strings(v: unknown): string[] {
  return list(v).map(text)
}
function enumText(v: unknown, allowed: readonly string[]): string {
  const s = text(v)
  if (!allowed.includes(s)) throw new Error('组件分析接口枚举无效')
  return s
}
export function parseComponent(v: unknown): ComponentInstance {
  const r = object(v)
  return {
    id: text(r.id),
    sourceRef: text(r.sourceRef),
    name: text(r.name),
    version: text(r.version),
    path: text(r.path),
    quality: text(r.quality),
    ...(r.group ? { group: text(r.group) } : {}),
    ...(r.purl ? { purl: text(r.purl) } : {}),
    ...(r.sha256 ? { sha256: text(r.sha256) } : {}),
  }
}
function parseAssessment(v: unknown): Assessment {
  const a = object(v),
    code = object(a.code)
  return {
    id: text(a.id),
    runId: text(a.runId),
    environmentVersionId: text(a.environmentVersionId),
    profileId: text(a.profileId),
    reachability: enumText(a.reachability, [
      'reachable',
      'not_reachable',
      'unknown',
      'not_analyzed',
    ]),
    environment: enumText(a.environment, [
      'applicable',
      'not_applicable',
      'unknown',
      'not_analyzed',
    ]),
    attack: enumText(a.attack, [
      'satisfied',
      'not_satisfied',
      'unknown',
      'not_analyzed',
    ]),
    excluded: boolean(a.excluded),
    reason: text(a.reason),
    evidence: strings(a.evidence),
    validUntil: text(a.validUntil),
    knowledgeDigest: text(a.knowledgeDigest),
    code: {
      state: text(code.state),
      path: strings(code.path),
      diagnostics: strings(code.diagnostics),
      complete: boolean(code.complete),
      engineVersion: text(code.engineVersion),
      viewDigest: text(code.viewDigest),
    },
  }
}
export function parseOccurrence(v: unknown): Occurrence {
  const r = object(v),
    vuln = object(r.vulnerability)
  return {
    id: text(r.id),
    taskId: text(r.taskId),
    status: enumText(r.status, ['open', 'ignored']) as Occurrence['status'],
    vulnerability: {
      id: text(vuln.id),
      componentId: text(vuln.componentId),
      component: parseComponent(vuln.component),
      severity: text(vuln.severity),
      title: text(vuln.title),
      description: text(vuln.description),
      fixedVersion: text(vuln.fixedVersion),
      primaryUrl: text(vuln.primaryUrl),
      cvss: vuln.cvss,
      dataSource: vuln.dataSource,
    },
    assessments: list(r.assessments).map(parseAssessment),
    dispositions: list(r.dispositions).map((v) => {
      const d = object(v)
      return {
        profileId: text(d.profileId),
        environmentVersionId: text(d.environmentVersionId),
        status: enumText(d.status, [
          'open',
          'ignored',
        ]) as Disposition['status'],
        source: enumText(d.source, [
          'manual',
          'policy',
        ]) as Disposition['source'],
        revision: number(d.revision),
        reason: text(d.reason),
        validity: text(d.validity),
        ...(d.expiresAt ? { expiresAt: text(d.expiresAt) } : {}),
        ...(d.overrideUntil ? { overrideUntil: text(d.overrideUntil) } : {}),
      }
    }),
  }
}
function parseEnvironment(v: unknown): EnvironmentVersion {
  const e = object(v),
    c = object(e.config),
    facts = object(c.facts ?? {})
  const parsed: Record<string, Fact> = {}
  for (const [key, value] of Object.entries(facts)) {
    const f = object(value)
    parsed[key] = {
      value: text(f.value),
      verified: boolean(f.verified),
      evidence: text(f.evidence),
      ...(f.expiresAt ? { expiresAt: text(f.expiresAt) } : {}),
    }
  }
  return {
    id: text(e.id),
    profileId: text(e.profileId),
    revision: number(e.revision),
    fingerprint: text(e.fingerprint),
    config: {
      name: text(c.name),
      javaRelease: number(c.javaRelease),
      applicationType: enumText(c.applicationType, [
        'java',
        'spring',
        'war',
      ]) as EnvironmentConfig['applicationType'],
      entryPoints: strings(c.entryPoints),
      externalDependencies: strings(c.externalDependencies),
      facts: parsed,
    },
  }
}
async function request(
  path: string,
  method = 'GET',
  body?: unknown,
  key?: string,
): Promise<Obj> {
  const response = await fetchLiveResponse(path, {
    method,
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    ...(method !== 'GET'
      ? { headers: { 'Idempotency-Key': key ?? createIdempotencyKey() } }
      : {}),
  })
  const data: unknown = await response.json()
  if (!response.ok) {
    const code =
      typeof object(data).error === 'string' ? String(object(data).error) : ''
    throw new Error(
      response.status === 409
        ? '数据版本已变化，请刷新后重新操作。'
        : response.status === 403
          ? '当前账号没有执行此操作的权限。'
          : code === 'restore_override_expiry_required'
            ? '请选择恢复后保留待处置的有效期。'
            : `操作失败：${code || response.status}`,
    )
  }
  return object(data)
}
const taskPath = (id: string) => `/tasks/${encodeURIComponent(id)}`
export const scaApi = {
  async overview(taskId: string) {
    const r = await request(taskPath(taskId) + '/inventories')
    const inventories: Inventory[] = list(r.items).map((v) => {
      const i = object(v),
        d = object(i.document)
      return {
        id: text(i.id),
        runId: text(i.runId),
        componentCount: number(i.componentCount),
        dependencyCount: number(i.dependencyCount),
        createdAt: text(i.createdAt),
        document: {
          standard: text(d.standard),
          encoding: text(d.encoding),
          specVersion: text(d.specVersion),
          quality: text(d.quality),
          fingerprint: text(d.fingerprint),
          diagnostics: list(d.diagnostics).map((v) => {
            const x = object(v)
            return {
              code: text(x.code),
              message: text(x.message),
              ...(x.ref ? { ref: text(x.ref) } : {}),
            }
          }),
        },
      }
    })
    const runs: ScaRun[] = list(r.runs).map((v) => {
      const x = object(v)
      return {
        id: text(x.id),
        kind: text(x.kind),
        status: text(x.status),
        quality: text(x.quality),
        error: text(x.error),
        inventoryId: text(x.inventoryId),
      }
    })
    return { inventories, runs }
  },
  async occurrences(taskId: string, query: Record<string, string> = {}) {
    const r = await request(
        taskPath(taskId) +
          '/vulnerability-occurrences?' +
          new URLSearchParams(query),
      ),
      s = object(r.summary)
    return {
      items: list(r.items).map(parseOccurrence),
      hasMore: boolean(r.hasMore),
      nextCursor: text(r.nextCursor),
      summary: {
        total: number(s.total),
        open: number(s.open),
        ignored: number(s.ignored),
        unknown: number(s.unknown),
        uniqueVulnerabilities: number(s.uniqueVulnerabilities),
      },
    }
  },
  async detail(taskId: string, id: string) {
    return parseOccurrence(
      (
        await request(
          taskPath(taskId) +
            '/vulnerability-occurrences/' +
            encodeURIComponent(id),
        )
      ).item,
    )
  },
  async components(taskId: string, inventoryId: string, offset = 0) {
    const r = await request(
      taskPath(taskId) +
        `/inventories/${encodeURIComponent(inventoryId)}/components?offset=${offset}`,
    )
    return {
      items: list(r.items).map(parseComponent),
      total: number(r.total),
      hasMore: boolean(r.hasMore),
      nextOffset: number(r.nextOffset),
    }
  },
  async environments() {
    return list((await request('/environment-profiles')).items).map(
      parseEnvironment,
    )
  },
  async saveEnvironment(
    config: EnvironmentConfig,
    previous?: EnvironmentVersion,
  ) {
    const p = previous
      ? '/environment-profiles/' + encodeURIComponent(previous.profileId)
      : '/environment-profiles'
    const r = await request(p, previous ? 'PATCH' : 'POST', {
      config,
      expectedRevision: previous?.revision ?? 0,
    })
    return parseEnvironment(r.item)
  },
  async scan(taskId: string) {
    return request(taskPath(taskId) + '/sca-scans', 'POST', {})
  },
  async analyze(
    taskId: string,
    scaRunId: string,
    inventoryId: string,
    environmentVersionId: string,
    policy: Policy,
  ) {
    const p = object(
      (await request(taskPath(taskId) + '/analysis-policies', 'POST', policy))
        .item,
    )
    return request(taskPath(taskId) + '/impact-analyses', 'POST', {
      scaRunId,
      inventoryId,
      environmentVersionId,
      policyId: text(p.id),
    })
  },
  async change(
    taskId: string,
    id: string,
    body: {
      environmentVersionId: string
      status: 'open' | 'ignored'
      expectedRevision: number
      reason: string
      expiresAt: string | null
      overrideUntil: string | null
    },
  ) {
    return request(
      taskPath(taskId) +
        '/vulnerability-occurrences/' +
        encodeURIComponent(id) +
        '/disposition',
      'POST',
      body,
    )
  },
  async history(taskId: string, id: string) {
    return list(
      (
        await request(
          taskPath(taskId) +
            '/vulnerability-occurrences/' +
            encodeURIComponent(id) +
            '/history',
        )
      ).items,
    )
  },
  async link(taskId: string, sbomTaskId: string) {
    return request(taskPath(taskId) + '/sbom-links', 'POST', { sbomTaskId })
  },
  async capabilities() {
    return request('/analysis-capabilities')
  },
  async swidCollection(
    taskId: string,
    taskIds: string[],
    mappings: Record<string, string>,
  ) {
    const members = await Promise.all(
      taskIds.map(async (id) => {
        const overview = await this.overview(id)
        const inv = overview.inventories.find(
          (i) =>
            i.document.standard === 'SWID' && i.document.encoding === 'xml',
        )
        if (!inv) throw new Error('集合成员需要已完成解析的单个 SWID 标签任务')
        const components = await this.components(id, inv.id)
        return {
          taskId: id,
          inventoryId: inv.id,
          fingerprint: inv.document.fingerprint,
          logicalPath: components.items[0]?.path || `${id}.swidtag`,
        }
      }),
    )
    return request(taskPath(taskId) + '/swid-collections', 'POST', {
      swidMembers: members,
      identityMappings: mappings,
    })
  },
}
