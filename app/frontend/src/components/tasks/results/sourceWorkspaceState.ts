export interface SourceTab {
  projectId: string
  fileId: string
  path: string
  projectName: string
}

export const sourceTabKey = (tab: Pick<SourceTab, 'projectId' | 'fileId'>) => JSON.stringify([tab.projectId, tab.fileId])

export function rememberSourceTab(tabs: readonly SourceTab[], tab: SourceTab): SourceTab[] {
  const key = sourceTabKey(tab)
  const index = tabs.findIndex(item => sourceTabKey(item) === key)
  if (index < 0) return [...tabs, tab]
  return tabs.map((item, position) => position === index ? tab : item)
}

export function adjacentSourceTab(tabs: readonly SourceTab[], closingKey: string): SourceTab | undefined {
  const index = tabs.findIndex(item => sourceTabKey(item) === closingKey)
  return tabs[index + 1] ?? tabs[index - 1]
}

/** Keep a useful code viewport before allowing an additional AI column. */
export function sourceWorkbenchLayout(width: number, directory: boolean, ai: boolean, requestedDirectory: number, requestedAI: number) {
  const compact = width < 700
  const directoryWidth = Math.max(180, Math.min(360, requestedDirectory, width - 400))
  const aiMaximum = Math.max(280, Math.min(640, width - 420 - 8 - (directory ? directoryWidth + 8 : 0)))
  const docked = ai && width >= 420 + 280 + 8 + (directory ? directoryWidth + 8 : 0)
  const aiWidth = Math.max(280, Math.min(aiMaximum, requestedAI))
  return { compact, directoryWidth, aiMaximum, aiWidth, docked }
}
