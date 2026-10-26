import type { DecompileResult, DecompileSourceFile } from '@/api/types'

export type ProjectCapabilityFilter = 'all' | 'source' | 'bytecode' | 'issues'
interface TreeNodeBase { key: string; name: string; path: string; parentKey: string | null }
export interface SourceDirectoryNode extends TreeNodeBase { kind: 'directory'; children: SourceTreeNode[]; fileCount: number }
export interface SourceFileNode extends TreeNodeBase { kind: 'file'; file: DecompileSourceFile }
export type SourceTreeNode = SourceDirectoryNode | SourceFileNode
export interface SourceTree { roots: SourceTreeNode[]; byKey: Map<string, SourceTreeNode>; byFileId: Map<string, SourceFileNode> }
export interface SourceTreeRow { node: SourceTreeNode; depth: number; expanded: boolean }
export interface SourceTreeFilter { keys: Set<string>; directories: Set<string>; fileCount: number }

export function normalizedSourcePath(value: string): string { return value.replace(/\\/g, '/').split('/').filter(Boolean).join('/') }
export function directoryKey(path: string): string { return `directory:${normalizedSourcePath(path)}` }

/** IDs retain file identity; folder paths are structural UI keys, never API IDs. */
export function buildSourceTree(files: readonly DecompileSourceFile[]): SourceTree {
  const tree: SourceTree = { roots: [], byKey: new Map(), byFileId: new Map() }
  for (const file of files) {
    const parts = normalizedSourcePath(file.logicalPath).split('/')
    let parent: SourceDirectoryNode | undefined
    for (let index = 0; index < parts.length - 1; index++) {
      const path = parts.slice(0, index + 1).join('/')
      const key = directoryKey(path)
      let directory = tree.byKey.get(key) as SourceDirectoryNode | undefined
      if (!directory) {
        directory = { kind: 'directory', key, name: parts[index] || path, path, parentKey: parent?.key ?? null, children: [], fileCount: 0 }
        tree.byKey.set(key, directory)
        ;(parent?.children ?? tree.roots).push(directory)
      }
      directory.fileCount++
      parent = directory
    }
    const node: SourceFileNode = { kind: 'file', key: `file:${file.id}`, name: parts[parts.length - 1] || file.logicalPath, path: normalizedSourcePath(file.logicalPath), parentKey: parent?.key ?? null, file }
    ;(parent?.children ?? tree.roots).push(node)
    tree.byKey.set(node.key, node)
    tree.byFileId.set(file.id, node)
  }
  const groups = [tree.roots]
  while (groups.length) {
    const nodes = groups.pop()!
    nodes.sort((a, b) => (a.kind === b.kind ? 0 : a.kind === 'directory' ? -1 : 1) || a.name.localeCompare(b.name, 'zh-CN', { numeric: true, sensitivity: 'base' }) || a.key.localeCompare(b.key))
    for (const node of nodes) if (node.kind === 'directory') groups.push(node.children)
  }
  return tree
}

export function ancestorDirectoryKeys(tree: SourceTree, key: string): string[] {
  const result: string[] = []
  let node = tree.byKey.get(key)
  while (node?.parentKey) {
    result.unshift(node.parentKey)
    node = tree.byKey.get(node.parentKey)
  }
  return result
}

/** Search all files, including files beyond the current rendered window. */
export function filterSourceTree(tree: SourceTree, query: string): SourceTreeFilter | undefined {
  const normalized = query.trim().toLocaleLowerCase('zh-CN')
  if (!normalized) return undefined
  const result: SourceTreeFilter = { keys: new Set(), directories: new Set(), fileCount: 0 }
  for (const node of tree.byFileId.values()) {
    if (![node.path, node.file.language, node.file.sha256].join(' ').toLocaleLowerCase('zh-CN').includes(normalized)) continue
    result.keys.add(node.key)
    result.fileCount++
    for (const key of ancestorDirectoryKeys(tree, node.key)) { result.keys.add(key); result.directories.add(key) }
  }
  return result
}

export function flattenSourceTree(tree: SourceTree, expanded: ReadonlySet<string>, filter?: SourceTreeFilter): SourceTreeRow[] {
  const result: SourceTreeRow[] = []
  const stack = tree.roots.slice().reverse().map(node => ({ node, depth: 0 }))
  while (stack.length) {
    const { node, depth } = stack.pop()!
    if (filter && !filter.keys.has(node.key)) continue
    const isExpanded = node.kind === 'directory' && expanded.has(node.key)
    result.push({ node, depth, expanded: isExpanded })
    if (node.kind === 'directory' && isExpanded) {
      for (let index = node.children.length - 1; index >= 0; index--) stack.push({ node: node.children[index]!, depth: depth + 1 })
    }
  }
  return result
}

export function treeKeyboardDestination(rows: readonly SourceTreeRow[], currentKey: string, key: string): string | undefined {
  const index = rows.findIndex(row => row.node.key === currentKey)
  const row = rows[index]
  if (!row) return rows[0]?.node.key
  if (key === 'ArrowDown') return rows[Math.min(index + 1, rows.length - 1)]?.node.key
  if (key === 'ArrowUp') return rows[Math.max(index - 1, 0)]?.node.key
  if (key === 'Home') return rows[0]?.node.key
  if (key === 'End') return rows[rows.length - 1]?.node.key
  if (key === 'ArrowRight' && row.node.kind === 'directory' && row.expanded && rows[index + 1]?.node.parentKey === currentKey) return rows[index + 1]?.node.key
  if (key === 'ArrowLeft' && (row.node.kind === 'file' || !row.expanded)) return row.node.parentKey ?? undefined
  return undefined
}

export function matchesProjectCapability(project: DecompileResult, filter: ProjectCapabilityFilter): boolean {
  if (filter === 'source') return project.status === 'complete' || project.status === 'partial'
  if (filter === 'bytecode') return project.status === 'bytecode_only'
  if (filter === 'issues') return ['unsupported', 'failed', 'cancelled'].includes(project.status)
  return true
}

export function matchesProjectQuery(project: DecompileResult, query: string): boolean {
  const normalized = query.trim().toLocaleLowerCase('zh-CN')
  return !normalized || [project.display_name, project.location, project.group_name, project.signature, project.detail, project.language, project.engine_name, project.symbol_key].join(' ').toLocaleLowerCase('zh-CN').includes(normalized)
}
