import { describe, expect, it } from 'vitest'
import type { DecompileResult, DecompileSourceFile } from '@/api/types'
import { ancestorDirectoryKeys, buildSourceTree, directoryKey, filterSourceTree, flattenSourceTree, matchesProjectCapability, matchesProjectQuery, treeKeyboardDestination } from './sourceExplorer'

const file = (id: string, logicalPath: string): DecompileSourceFile => ({ id, projectId: 'project', logicalPath, language: 'c', sizeBytes: 20, lineCount: 2, sha256: 'abc' })

describe('source explorer structure', () => {
  it('builds real folders, preserves identical basenames by identity and sorts folders before natural file names', () => {
    const tree = buildSourceTree([file('a', 'z\\shared.c'), file('b', 'a/shared.c'), file('c', 'main10.c'), file('d', 'main2.c')])
    expect(tree.roots.map(node => node.name)).toEqual(['a', 'z', 'main2.c', 'main10.c'])
    expect(tree.byFileId.get('a')?.path).toBe('z/shared.c')
    expect(tree.byFileId.get('b')?.path).toBe('a/shared.c')
    expect(ancestorDirectoryKeys(tree, 'file:a')).toEqual(['directory:z'])
    expect(flattenSourceTree(tree, new Set(['directory:a'])).map(row => row.node.key)).toEqual(['directory:a', 'file:b', 'directory:z', 'file:d', 'file:c'])
  })

  it('searches beyond a 500-row window and exposes every matching ancestor without changing manual expansion', () => {
    const tree = buildSourceTree(Array.from({ length: 900 }, (_, index) => file(String(index), `src/nested/unit${index}.c`)))
    const manual = new Set(['directory:src'])
    const matches = filterSourceTree(tree, 'unit899')!
    const searched = flattenSourceTree(tree, matches.directories, matches)
    expect(matches.fileCount).toBe(1)
    expect(searched.map(row => row.node.key)).toEqual(['directory:src', 'directory:src/nested', 'file:899'])
    expect(flattenSourceTree(tree, manual).map(row => row.node.key)).toEqual(['directory:src', 'directory:src/nested'])
    expect(filterSourceTree(tree, 'missing')?.fileCount).toBe(0)
  })

  it('locates ancestors safely even for object-prototype-like folder names', () => {
    const tree = buildSourceTree([file('f', '__proto__/constructor/a.c')])
    expect(ancestorDirectoryKeys(tree, 'file:f')).toEqual(['directory:__proto__', 'directory:__proto__/constructor'])
    expect(directoryKey('src\\nested/')).toBe('directory:src/nested')
    expect(ancestorDirectoryKeys(tree, 'missing')).toEqual([])
  })

  it('supports tree navigation across visible files and collapsed/expanded folders', () => {
    const tree = buildSourceTree([file('a', 'src/a.c'), file('b', 'b.c')])
    const rows = flattenSourceTree(tree, new Set(['directory:src']))
    expect(treeKeyboardDestination(rows, 'directory:src', 'ArrowRight')).toBe('file:a')
    expect(treeKeyboardDestination(rows, 'file:a', 'ArrowLeft')).toBe('directory:src')
    expect(treeKeyboardDestination(rows, 'directory:src', 'ArrowDown')).toBe('file:a')
    expect(treeKeyboardDestination(rows, 'file:a', 'End')).toBe('file:b')
    expect(treeKeyboardDestination(rows, 'file:a', 'Home')).toBe('directory:src')
    expect(treeKeyboardDestination(flattenSourceTree(tree, new Set()), 'directory:src', 'ArrowRight')).toBeUndefined()
  })
})

describe('project selector boundaries', () => {
  const project = { status: 'partial', display_name: '模块', location: 'lib/sample.so', language: 'C', engine_name: 'Ghidra', group_name: '', signature: '', detail: '', symbol_key: '' } as DecompileResult
  it('retains source, bytecode and exceptional capability filters and searches project metadata separately', () => {
    expect(matchesProjectCapability(project, 'source')).toBe(true)
    expect(matchesProjectCapability(project, 'bytecode')).toBe(false)
    expect(matchesProjectCapability({ ...project, status: 'bytecode_only' }, 'bytecode')).toBe(true)
    expect(matchesProjectCapability({ ...project, status: 'failed' }, 'issues')).toBe(true)
    expect(matchesProjectQuery(project, 'SAMPLE.SO')).toBe(true)
    expect(matchesProjectQuery(project, 'ghidra')).toBe(true)
    expect(matchesProjectQuery(project, 'absent.c')).toBe(false)
  })
})
