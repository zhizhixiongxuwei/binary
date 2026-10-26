import { describe, expect, it } from 'vitest'
import { clampExplanationWidth, explanationMaximumWidth, explanationWidthPreference } from './explanationPanelLayout'

describe('explanation pane layout', () => {
  it('bounds a docked pane to the space left for it by the workbench', () => {
    expect(clampExplanationWidth(480, 360)).toBe(360)
    expect(clampExplanationWidth(720, 1000)).toBe(720)
    expect(explanationMaximumWidth(1200)).toBe(800)
    expect(explanationMaximumWidth(120)).toBe(280)
  })

  it('restores the preferred width when a temporarily narrow workbench grows', () => {
    const preference = explanationWidthPreference('640')
    expect(clampExplanationWidth(preference, 320)).toBe(320)
    expect(clampExplanationWidth(preference, 1000)).toBe(640)
  })

  it('rejects invalid UI storage values without producing a broken grid', () => {
    for (const value of [null, '', 'NaN', 'Infinity', '0', '-20', 'broken']) {
      expect(explanationWidthPreference(value)).toBe(480)
    }
    expect(explanationWidthPreference('999999')).toBe(800)
    expect(clampExplanationWidth(Number.NaN, 1000)).toBe(480)
  })
})
