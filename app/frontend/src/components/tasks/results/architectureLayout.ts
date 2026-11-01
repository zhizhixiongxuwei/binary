import type { ArchitectureNode, ArchitectureEdge, ModuleRole } from '@/api/insights'

export const roleLabels: Record<ModuleRole, string> = { entry: '程序入口', core: '核心处理', data: '数据与存储', external: '外部依赖' }
const roles: ModuleRole[] = ['entry', 'core', 'data', 'external']
export function architectureLayout(nodes: readonly ArchitectureNode[], edges: readonly ArchitectureEdge[]) {
  const columns = roles.filter(role => nodes.some(node => node.role === role))
  const height = Math.max(340, ...columns.map(role => nodes.filter(node => node.role === role).length * 144 + 100))
  const width = Math.max(840, columns.length * 260 + 40)
  const positioned = nodes.map(node => {
    const column = columns.indexOf(node.role)
    const peers = nodes.filter(item => item.role === node.role)
    const row = peers.findIndex(item => item.id === node.id)
    return { ...node, x: 36 + column * ((width - 72) / Math.max(1, columns.length)), y: 82 + row * 144 }
  })
  const paths = edges.flatMap((edge, index) => {
    const from = positioned.find(node => node.id === edge.from)
    const to = positioned.find(node => node.id === edge.to)
    if (!from || !to) return []
    const forward = to.x > from.x
    const sameColumn = from.x === to.x
    const x1 = from.x + (sameColumn || forward ? 230 : 0)
    const x2 = to.x + (sameColumn || !forward ? 230 : 0)
    const y1 = from.y + 48
    const y2 = to.y + 48
    const bend = sameColumn ? x1 + 32 + index % 3 * 12 : (x1 + x2) / 2
    const d = `M ${x1} ${y1} C ${bend} ${y1}, ${bend} ${y2}, ${x2} ${y2}`
    return [{ ...edge, d, labelX: sameColumn ? bend + 3 : (x1 + x2) / 2, labelY: (y1 + y2) / 2 - 9 }]
  })
  return { nodes: positioned, paths, columns, width, height }
}
