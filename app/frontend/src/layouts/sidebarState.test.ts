import { describe, expect, it } from 'vitest'
import { readSidebarPreference, resolveSidebarCollapsed, sidebarPathIsActive } from './sidebarState'

describe('sidebar presentation state', () => {
  it('accepts only the explicit stored collapsed preference', () => {
    expect(readSidebarPreference('1')).toBe(true)
    for (const value of [null, '', '0', 'true', 'invalid']) expect(readSidebarPreference(value)).toBe(false)
  })
  it('temporarily collapses for reading without changing the saved preference', () => {
    expect(resolveSidebarCollapsed(false, false, false)).toBe(false)
    expect(resolveSidebarCollapsed(false, false, true)).toBe(true)
    expect(resolveSidebarCollapsed(false, false, false)).toBe(false)
    expect(resolveSidebarCollapsed(true, false, false)).toBe(true)
  })
  it('allows a temporary user override in reading mode and restores on exit', () => {
    expect(resolveSidebarCollapsed(true, false, true, false)).toBe(false)
    expect(resolveSidebarCollapsed(true, false, false, false)).toBe(true)
  })
  it('keeps full navigation labels in a narrow drawer for every desktop state', () => {
    expect(resolveSidebarCollapsed(true, true, false)).toBe(false)
    expect(resolveSidebarCollapsed(false, true, true)).toBe(false)
  })
  it('highlights a section only on its exact path or descendants', () => {
    expect(sidebarPathIsActive('/tasks/123', '/tasks')).toBe(true)
    expect(sidebarPathIsActive('/tasks-other', '/tasks')).toBe(false)
    expect(sidebarPathIsActive('/tasks', '/')).toBe(false)
  })
})
