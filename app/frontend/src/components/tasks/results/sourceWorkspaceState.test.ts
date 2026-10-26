import { describe, expect, it } from 'vitest'
import { adjacentSourceTab, rememberSourceTab, sourceTabKey, sourceWorkbenchLayout, type SourceTab } from './sourceWorkspaceState'

const a: SourceTab = { projectId: 'p1', fileId: 'a', path: 'src/main.c', projectName: 'First' }
const b: SourceTab = { ...a, fileId: 'b', path: 'lib/main.c' }
describe('source workbench state', () => {
  it('keeps open order and updates metadata without duplicating a file', () => {
    expect(rememberSourceTab([a, b], { ...a, path: 'new.c' })).toEqual([{ ...a, path: 'new.c' }, b])
    const otherProject = { ...a, projectId: 'p2' }
    expect(sourceTabKey(a)).not.toBe(sourceTabKey(otherProject))
    expect(rememberSourceTab([a, b], otherProject)).toHaveLength(3)
  })
  it('chooses an adjacent surviving file when closing the active tab', () => {
    expect(adjacentSourceTab([a, b], sourceTabKey(a))).toEqual(b)
    expect(adjacentSourceTab([a, b], sourceTabKey(b))).toEqual(a)
    expect(adjacentSourceTab([a], sourceTabKey(a))).toBeUndefined()
  })
  it('only docks AI when code can keep at least 420 pixels', () => {
    const wide = sourceWorkbenchLayout(1400, true, true, 260, 480)
    expect(wide.docked).toBe(true)
    expect(1400 - wide.directoryWidth - 16 - wide.aiWidth).toBeGreaterThanOrEqual(420)
    expect(sourceWorkbenchLayout(900, true, true, 260, 480).docked).toBe(false)
    expect(sourceWorkbenchLayout(900, false, true, 260, 480).docked).toBe(true)
    expect(sourceWorkbenchLayout(500, false, true, 260, 480).compact).toBe(true)
  })
})
