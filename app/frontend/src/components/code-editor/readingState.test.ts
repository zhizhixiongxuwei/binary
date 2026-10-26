import { describe, expect, it } from 'vitest'
import { clampDirectoryWidth, createTargetRevealGuard, formatCodeCopy, ViewStateCache } from './readingState'

describe('source view state cache', () => {
  it('isolates identical file names by task/project/file URI', () => {
    const cache = new ViewStateCache<{ scrollTop: number; folded: number[] }>()
    cache.set('binaryscan-source:///a/p/file', { scrollTop: 400, folded: [4] })
    cache.set('binaryscan-source:///b/p/file', { scrollTop: 80, folded: [] })
    expect(cache.get('binaryscan-source:///a/p/file')).toEqual({ scrollTop: 400, folded: [4] })
    expect(cache.get('binaryscan-source:///b/p/file')?.scrollTop).toBe(80)
  })
  it('evicts least recently used entries and replaces existing state without growing', () => {
    const cache = new ViewStateCache<number>(2)
    cache.set('a', 1); cache.set('b', 2)
    expect(cache.get('a')).toBe(1)
    cache.set('c', 3)
    expect(cache.get('b')).toBeUndefined()
    cache.set('a', 4)
    expect(cache.size).toBe(2)
    expect(cache.get('a')).toBe(4)
  })
})

describe('reading controls', () => {
  it('reapplies a repeated explicit navigation but does not jump again on a content refresh', () => {
    const guard = createTargetRevealGuard()
    const location = 'binaryscan-source:///a/p/file:40:1:42:8'
    expect(guard.accept(location)).toBe(true)
    // A source/layout synchronization must preserve a reader's subsequent scroll.
    expect(guard.accept(location)).toBe(false)
    // Clicking the same finding again is a new request, even at identical coordinates.
    guard.reset()
    expect(guard.accept(location)).toBe(true)
    expect(guard.accept(location)).toBe(false)
  })
  it('bounds persisted and dragged directory widths while reserving room for code', () => {
    expect(clampDirectoryWidth(800, 1000)).toBe(520)
    expect(clampDirectoryWidth(480, 720)).toBe(352)
    expect(clampDirectoryWidth(-20, 1000)).toBe(180)
    expect(clampDirectoryWidth(Number.NaN, 1000)).toBe(280)
  })
  it('copies the actual selected line range with optional attribution', () => {
    expect(formatCodeCopy('a\nb', { filename: 'src/a.c', startLine: 12, includeFilename: true, includeLineNumbers: true })).toBe('src/a.c\n12 | a\n13 | b')
    expect(formatCodeCopy('a\nb', { includeFilename: false, includeLineNumbers: false })).toBe('a\nb')
  })
})
