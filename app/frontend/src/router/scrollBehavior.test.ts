import { describe, expect, it } from 'vitest'
import type { RouteLocationNormalized } from 'vue-router'
import { scrollBehavior } from './scrollBehavior'

function route(name: string, id = '', query: Record<string, string> = {}) {
  return { name, params: { id }, query } as unknown as RouteLocationNormalized
}

describe('document scroll policy', () => {
  it('preserves the document position when selecting a different source in the same task', () => {
    expect(scrollBehavior(route('task-detail', 'a', { sourceFile: 'second' }), route('task-detail', 'a', { sourceFile: 'first' }), null)).toBe(false)
  })
  it('restores browser history position before applying the same-task policy', () => {
    const saved = { left: 12, top: 640 }
    expect(scrollBehavior(route('task-detail', 'a'), route('task-detail', 'a'), saved)).toBe(saved)
  })
  it('starts at the top for another task or another page', () => {
    expect(scrollBehavior(route('task-detail', 'b'), route('task-detail', 'a'), null)).toEqual({ top: 0 })
    expect(scrollBehavior(route('tasks'), route('task-detail', 'a'), null)).toEqual({ top: 0 })
    expect(scrollBehavior(route('task-detail', 'a'), route('tasks'), null)).toEqual({ top: 0 })
  })
})
