import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { describe, expect, it } from 'vitest'

import type { AuditLog } from '@/api/types'
import AuditLogLivePanel from './AuditLogLivePanel.vue'

const entry: AuditLog = {
  id: 'audit-42', actor: null, action: 'task.delete', outcome: 'failure',
  object_type: 'task', object_id: 'task-42', request_id: 'request-42', metadata: null,
  created_at: '2026-11-03T06:00:00Z',
}

const defaults = { logs: [entry], loading: false, loadingMore: false, errorMessage: '',
  hasMore: true, exporting: false, exportError: '', exportFeedback: '', loadMoreError: '' }

async function renderPanel(overrides: Partial<typeof defaults>): Promise<string> {
  const app = createSSRApp({ render: () => h(AuditLogLivePanel, { ...defaults, ...overrides }) })
  app.component('el-button', { render: () => h('button') })
  return renderToString(app)
}

describe('audit feedback and pagination controls', () => {
  it('keeps the loaded events visible with a retry action when an older page fails', async () => {
    const html = await renderPanel({ loadMoreError: '无法读取更早事件' })
    expect(html).toContain('audit-42')
    expect(html).toContain('outcome-label--failure')
    expect(html).toContain('无法读取更早事件')
    expect(html).toContain('重试加载更早事件')
  })

  it('shows export errors before any stale success message and disables a pending export', async () => {
    const html = await renderPanel({ exporting: true, exportError: '导出请求失败', exportFeedback: 'earlier-download-started' })
    expect(html).toContain('导出请求失败')
    expect(html).not.toContain('earlier-download-started')
    expect(html).toContain('正在导出…')
    expect(html).toMatch(/<button[^>]*disabled[^>]*title="按当前填写的筛选条件导出全部匹配记录"/)
  })

  it('hides previous pagination actions while a replacement query is loading', async () => {
    const html = await renderPanel({ loading: true })
    expect(html).not.toContain('加载更早事件')
    expect(html).not.toContain('已到达当前查询末尾')
  })
})
