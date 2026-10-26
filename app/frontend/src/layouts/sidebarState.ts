export const SIDEBAR_COLLAPSED_KEY = 'binaryscan.sidebar.collapsed.v1'

export function readSidebarPreference(value: string | null): boolean {
  return value === '1'
}

/** Reading mode is temporary; a narrow drawer always keeps its full labels. */
export function resolveSidebarCollapsed(
  preferred: boolean,
  narrow: boolean,
  readingFocus: boolean,
  focusOverride: boolean | null = null,
): boolean {
  return !narrow && (readingFocus ? focusOverride ?? true : preferred)
}

export function sidebarPathIsActive(current: string, target: string): boolean {
  if (target === '/') return current === '/'
  return current === target || current.startsWith(`${target}/`)
}
