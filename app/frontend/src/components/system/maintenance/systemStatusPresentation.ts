import type { SystemStatus } from '@/api/types'

export interface ProbeHealthPresentation {
  label: string
  tone: 'available' | 'unavailable' | 'unknown' | 'stale'
}

export function analyzerProbeDescription(analyzer: NonNullable<SystemStatus['analyzers']>[number]): string {
  if (analyzer.freshness === 'stale') return '就绪检查已过期，请等待执行服务重新上报。'
  if (analyzer.freshness === 'missing') return '尚未收到就绪检查报告，暂无法确认可用性。'
  if (analyzer.status === 'unknown') return '尚无有效检查结果，暂无法确认可用性。'
  if (analyzer.status !== 'available') {
    if (analyzer.detail?.includes('版本') && analyzer.detail.includes('不一致')) return '实际组件版本与部署配置不一致，请检查部署配置。'
    if (analyzer.detail?.includes('离线数据库')) return '引擎可启动，但离线漏洞库检查未通过。'
    if (analyzer.detail?.includes('规则目录')) return '检测规则目录检查未通过，暂不可选择检测规则。'
    return '引擎或运行环境检查未通过，请查看技术诊断。'
  }
  if (!analyzer.version) return '引擎就绪检查通过，版本信息暂不可获取。'
  if (analyzer.detail?.includes('双库文件及元数据已检查')) return '引擎启动正常，主漏洞库与 Java 漏洞库检查通过。'
  return '引擎与运行环境检查通过。'
}

export function analyzerProbeHealth(status: string, freshness?: string): ProbeHealthPresentation {
  if (freshness === 'stale') return { label: '探测已过期', tone: 'stale' }
  if (freshness === 'missing') return { label: '未收到探测', tone: 'unknown' }
  if (status === 'available') return { label: '可用', tone: 'available' }
  if (status === 'unavailable') return { label: '不可用', tone: 'unavailable' }
  return { label: '状态未知', tone: 'unknown' }
}

export function databaseBundleHealth(status: string, freshness?: string): ProbeHealthPresentation {
  if (freshness === 'stale') return { label: '探测已过期', tone: 'stale' }
  if (freshness === 'missing') return { label: '未收到探测', tone: 'unknown' }
  if (status === 'active') return { label: '可用', tone: 'available' }
  if (status === 'stale') return { label: '数据已过旧', tone: 'stale' }
  if (status === 'unavailable') return { label: '不可用', tone: 'unavailable' }
  return { label: '状态未知', tone: 'unknown' }
}
