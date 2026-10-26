export const EXPLANATION_MIN_WIDTH = 280
export const EXPLANATION_MAX_WIDTH = 800
export const EXPLANATION_DEFAULT_WIDTH = 480

/** availableWidth is the space reserved by the workbench after its code column. */
export function explanationMaximumWidth(availableWidth: number): number {
  const available = Number.isFinite(availableWidth) ? availableWidth : EXPLANATION_DEFAULT_WIDTH
  return Math.max(EXPLANATION_MIN_WIDTH, Math.min(EXPLANATION_MAX_WIDTH, Math.round(available)))
}

export function clampExplanationWidth(preferredWidth: number, availableWidth: number): number {
  const preferred = Number.isFinite(preferredWidth) ? preferredWidth : EXPLANATION_DEFAULT_WIDTH
  return Math.round(Math.max(EXPLANATION_MIN_WIDTH, Math.min(explanationMaximumWidth(availableWidth), preferred)))
}

export function explanationWidthPreference(stored: string | null): number {
  if (stored === null || stored.trim() === '') return EXPLANATION_DEFAULT_WIDTH
  const value = Number(stored)
  return Number.isFinite(value) && value >= EXPLANATION_MIN_WIDTH
    ? clampExplanationWidth(value, EXPLANATION_MAX_WIDTH)
    : EXPLANATION_DEFAULT_WIDTH
}
