import { createSSRApp, h, type Component } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { describe, expect, it, vi } from 'vitest'

import type { DatabaseBundleStatus, SystemStatus } from '@/api/types'

vi.mock('@/api/client', () => ({ api: {}, ApiError: class ApiError extends Error {} }))

import SystemStatusPanel from '@/components/system/SystemStatusPanel.vue'
import AnalyzerStatusPanel from './AnalyzerStatusPanel.vue'

const analyzer: NonNullable<SystemStatus['analyzers']>[number] = {
  name: 'Ghidra', version: '12.1.3', expected_version: '12.1.3', status: 'available',
  freshness: 'fresh', verification: 'probe', required_worker_kinds: [], ready_worker_kinds: [],
  ready_workers: 1, runtime_name: 'native-decompiler', runtime_version: '',
  last_checked_at: '2026-11-03T06:00:00Z',
}

const baseStatus: SystemStatus = {
  version: 'test-build', service_status: 'degraded', active_tasks: 0, queued_tasks: 0,
  repository_used_bytes: null, repository_total_bytes: null,
}

async function renderPanel(component: Component, status: SystemStatus): Promise<string> {
  const app = createSSRApp({ render: () => h(component, { status, managed: true, loading: false, errorMessage: '' }) })
  app.component('el-button', { render: () => h('button') })
  return renderToString(app)
}

describe('system maintenance probe presentation', () => {
  it('keeps expired successful probes and unknown probes out of the available state', async () => {
    const status: SystemStatus = {
      ...baseStatus,
      analyzers: [
        { ...analyzer, freshness: 'stale' },
        { ...analyzer, name: 'Trivy', status: 'unknown', freshness: 'missing', version: '' },
      ],
    }
    const tools = await renderPanel(AnalyzerStatusPanel, status)
    expect(tools).toContain('探测已过期')
    expect(tools).toContain('未收到探测')
    expect(tools).not.toContain('state-label--available')
    expect(tools).toContain('实际处理结果以任务执行记录为准')
    const runtime = await renderPanel(SystemStatusPanel, status)
    expect(runtime).toContain('analyzer-state--stale')
    expect(runtime).toContain('analyzer-state--unknown')
    expect(runtime).not.toContain('analyzer-state--available')
  })

  it('reports absent database telemetry as unknown without claiming the databases are missing', async () => {
    const html = await renderPanel(AnalyzerStatusPanel, { ...baseStatus, trivy_database_bundle: null })
    expect(html).toContain('尚未收到离线数据库探测报告')
    expect(html).toContain('当前无法确认双库状态')
    expect(html).not.toContain('未安装')
    expect(html).not.toContain('未导入')
    expect(html).not.toContain('disabled')
  })

  it('shows the two real database metadata records and their errors without a synthetic checksum', async () => {
    const bundle: DatabaseBundleStatus = {
      id: 'scanner-report', version: '', trivy_db_version: '2', trivy_java_db_version: '1',
      status: 'unavailable', freshness: 'fresh', generated_at: '',
      registered_at: '2026-11-03T06:00:00Z', last_checked_at: '2026-11-03T05:59:59Z',
      age_days: 1, stale_after_days: 30,
      databases: [
        {
          name: 'trivy-db', status: 'available', path: '/opt/trivy-cache/db/trivy.db',
          schema_version: 2, size_bytes: 2048, updated_at: '2026-11-02T00:00:00Z',
          next_update: '2026-11-04T00:00:00Z', downloaded_at: '2026-11-02T01:00:00Z', error: '',
        },
        {
          name: 'trivy-java-db', status: 'unavailable', path: '/opt/trivy-cache/java-db/trivy-java.db',
          schema_version: 1, size_bytes: 1024, updated_at: null, next_update: null, downloaded_at: null,
          error: 'metadata.json is unreadable',
        },
      ],
    }
    const html = await renderPanel(AnalyzerStatusPanel, { ...baseStatus, trivy_database_bundle: bundle })
    expect(html).toContain('主漏洞库')
    expect(html).toContain('Java 漏洞库')
    expect(html).toContain('Schema 2')
    expect(html).toContain('Schema 1')
    expect(html).toContain('2 KB')
    expect(html).toContain('更新时间')
    expect(html).toContain('/opt/trivy-cache/java-db/trivy-java.db')
    expect(html).toContain('metadata.json is unreadable')
    expect(html).not.toContain('sha256')
    expect(html).not.toContain('disabled')
  })

  it('hides unobserved repository capacity while preserving a measured empty repository', async () => {
    const unknown = await renderPanel(SystemStatusPanel, baseStatus)
    expect(unknown).toContain('容量未观测')
    expect(unknown).not.toContain('repository-meter')
    expect(unknown).not.toContain('0 B')
    expect(unknown).toContain('未收到探测')
    const measured = await renderPanel(SystemStatusPanel, {
      ...baseStatus, repository_used_bytes: 0, repository_total_bytes: 1024,
    })
    expect(measured).toContain('0 B / 1 KB')
    expect(measured).toContain('repository-meter')
  })

  it('uses business labels by default and retains raw probe identity only in collapsed diagnostics', async () => {
    const raw = { ...analyzer, name: 'jvm-decompiler',
      version: 'vineflower-1.11+cfr-0.152+jadx-1.5',
      detail: 'Java 启动、Vineflower 版本清单及 CFR / JADX 版本命令通过；未运行完整反编译' }
    const status = { ...baseStatus, analyzers: [raw] }
    const before = JSON.stringify(status)
    for (const component of [AnalyzerStatusPanel, SystemStatusPanel]) {
      const html = await renderPanel(component, status)
      const regularView = html.replace(/<details\b[\s\S]*?<\/details>/g, '')
      expect(regularView).toContain('Java / Android 反编译引擎')
      expect(regularView).not.toMatch(/trivy|ghidra|vineflower|cfr|jadx|pycdc/i)
      expect(html).toContain(raw.version)
      expect(html).toContain(raw.detail)
      expect(html).toContain('技术诊断（原始组件信息）')
      expect(html).not.toMatch(/<details[^>]*\bopen\b/)
    }
    expect(JSON.stringify(status)).toBe(before)
  })
})
