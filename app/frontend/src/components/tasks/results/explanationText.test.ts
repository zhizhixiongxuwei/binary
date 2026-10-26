import { describe, expect, it } from 'vitest'
import { explanationBlocks, explanationLineParts } from '@/components/tasks/results/explanationText'

describe('safe explanation text presentation', () => {
  it('supports section headings, list markers and fenced code while preserving untrusted text literally', () => {
    expect(explanationBlocks('# 功能概述\n<img src=x onerror=alert(1)>\n- item\n```c\n<script>unsafe</script>\n```')).toEqual([
      { kind: 'heading', text: '功能概述' }, { kind: 'paragraph', text: '<img src=x onerror=alert(1)>' },
      { kind: 'bullet', text: 'item' }, { kind: 'code', text: '<script>unsafe</script>' },
    ])
  })
  it('only makes valid line references navigable and leaves URLs as text', () => {
    const parts = explanationLineParts('检查 L2–L4 和 L99。https://example.com', 10)
    expect(parts.find((part) => part.startLine)).toEqual({ text: 'L2–L4', startLine: 2, endLine: 4 })
    expect(parts.some((part) => part.startLine === 99)).toBe(false)
    expect(parts.map((part) => part.text).join('')).toBe('检查 L2–L4 和 L99。https://example.com')
  })
})
