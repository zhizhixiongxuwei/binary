import type { DecompileResult, DecompileSourceFileContent } from '@/api/types'
import type { ProjectInsight } from '@/api/insights'
import { DEMO_TASK_IDS } from './fixtures'

export const DEMO_PROJECT_ID = 'demo-field-console-project'
const createdAt = '2026-07-28T17:20:09+08:00'

export const DEMO_DECOMPILE_PROJECT: DecompileResult = {
  id: DEMO_PROJECT_ID,
  file_node_id: 'demo-field-console-dex',
  symbol_key: 'project:field-console',
  symbol_kind: 'module',
  display_name: 'field-console.apk · 示例源码',
  group_name: 'com.field.console',
  location: 'classes.dex',
  signature: '示例项目，供界面预览',
  detail: '三份演示代码展示架构、函数解读与自然语言检索入口。',
  language: 'java',
  engine_name: '界面预览样例',
  engine_version: '1.0',
  status: 'complete',
  size_bytes: 2048,
  diagnostics: null,
  created_at: createdAt,
  completed_at: createdAt,
}

function source(id: string, logicalPath: string, lines: string[]): DecompileSourceFileContent {
  const content = lines.join('\n')
  return { id, projectId: DEMO_PROJECT_ID, logicalPath, language: 'java', sizeBytes: new TextEncoder().encode(content).length, lineCount: lines.length, sha256: '0'.repeat(64), content }
}

export const DEMO_SOURCE_FILES = [
  source('demo-entry', 'com/field/console/ConsoleActivity.java', [
    'package com.field.console;',
    '',
    'public class ConsoleActivity {',
    '    private final SyncService syncService = new SyncService();',
    '',
    '    public void onCreate() {',
    '        refreshDashboard();',
    '    }',
    '',
    '    public void refreshDashboard() {',
    '        syncService.loadRecentRecords();',
    '        syncService.sendPendingUpdates();',
    '    }',
    '}',
  ]),
  source('demo-service', 'com/field/console/SyncService.java', [
    'package com.field.console;',
    '',
    'public class SyncService {',
    '    private final RecordStore store = new RecordStore();',
    '',
    '    public void loadRecentRecords() {',
    '        store.queryRecentRecords();',
    '    }',
    '',
    '    public void sendPendingUpdates() {',
    '        String payload = store.queryPendingUpdates();',
    '        HttpClient.post("/api/sync", payload);',
    '    }',
    '}',
  ]),
  source('demo-store', 'com/field/console/RecordStore.java', [
    'package com.field.console;',
    '',
    'public class RecordStore {',
    '    private final SQLiteDatabase database = openDatabase();',
    '',
    '    public Cursor queryRecentRecords() {',
    '        return database.rawQuery("SELECT * FROM records ORDER BY updated_at DESC", null);',
    '    }',
    '',
    '    public String queryPendingUpdates() {',
    '        Cursor cursor = database.rawQuery("SELECT * FROM records WHERE synced = 0", null);',
    '        return encode(cursor);',
    '    }',
    '}',
  ]),
] as const

export function demoProjectInsight(taskId: string, projectId: string, kind: 'architecture' | 'search', query: string): ProjectInsight | null {
  if (taskId !== DEMO_TASK_IDS.apk || projectId !== DEMO_PROJECT_ID) return null
  const coverage = { totalFiles: 3, sampledFiles: 3, inputChars: DEMO_SOURCE_FILES.reduce((sum, file) => sum + file.content.length, 0), truncated: false }
  const shared = { kind, query, coverage, model: '固定演示结果', createdAt }
  if (kind === 'architecture') return {
    ...shared,
    result: {
      summary: '这是一个演示性移动终端项目：界面触发记录刷新，同步服务协调本地查询与远程提交，数据存取集中在 SQLite 层。模块与调用关系仅展示宏观组合逻辑。',
      nodes: [
        { id: 'entry', label: '交互入口', role: 'entry', description: '承接界面生命周期与用户触发的刷新操作。', fileIds: ['demo-entry'] },
        { id: 'sync', label: '同步编排', role: 'core', description: '组织本地记录读取、待同步数据组装和提交。', fileIds: ['demo-service'] },
        { id: 'store', label: '本地记录', role: 'data', description: '集中执行 SQLite 查询，提供最近记录和待同步数据。', fileIds: ['demo-store'] },
        { id: 'remote', label: '远端服务', role: 'external', description: '通过 HTTP 接收客户端提交的更新。', fileIds: [] },
      ],
      edges: [
        { from: 'entry', to: 'sync', label: '触发刷新' },
        { from: 'sync', to: 'store', label: '读取记录' },
        { from: 'sync', to: 'remote', label: '提交更新' },
      ],
      flow: ['界面发起刷新', '同步服务读取本地记录', '查询待同步数据', '向远端接口提交更新'],
      matches: [],
    },
  }
  const network = /网络|通信|http|接口|请求|上传|发送|同步/i.test(query)
  const database = /数据库|查询|sql|记录|sqlite|存储|读取/i.test(query)
  const unsupported = /文件|鉴权|密码|权限|写入/i.test(query)
  const matches = unsupported ? [] : network && !database ? [
    { fileId: 'demo-service', path: 'com/field/console/SyncService.java', name: 'sendPendingUpdates()', startLine: 10, endLine: 13, reason: '通过 HTTP POST 将待同步数据发送到远端。', evidence: 'HttpClient.post("/api/sync", payload)' },
    { fileId: 'demo-entry', path: 'com/field/console/ConsoleActivity.java', name: 'refreshDashboard()', startLine: 10, endLine: 13, reason: '触发同步服务发送更新，是上层调用入口。', evidence: 'syncService.sendPendingUpdates()' },
  ] : database ? [
    { fileId: 'demo-store', path: 'com/field/console/RecordStore.java', name: 'queryRecentRecords()', startLine: 6, endLine: 8, reason: '直接执行 SQLite rawQuery，读取最近记录。', evidence: 'database.rawQuery("SELECT * FROM records ORDER BY updated_at DESC", null)' },
    { fileId: 'demo-store', path: 'com/field/console/RecordStore.java', name: 'queryPendingUpdates()', startLine: 10, endLine: 13, reason: '通过 SQL 查询尚未同步的记录。', evidence: 'database.rawQuery("SELECT * FROM records WHERE synced = 0", null)' },
    { fileId: 'demo-service', path: 'com/field/console/SyncService.java', name: 'loadRecentRecords()', startLine: 6, endLine: 8, reason: '调用数据层查询函数，是数据库读取的上层入口。', evidence: 'store.queryRecentRecords()' },
  ] : []
  return {
    ...shared,
    result: {
      summary: matches.length ? '示例检索在演示源码中找到相关函数及其上层调用位置。' : '这份演示源码中没有与当前描述匹配的函数。',
      nodes: [], edges: [], flow: [],
      matches,
    },
  }
}
