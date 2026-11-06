export type MaintenanceTab =
  | 'runtime'
  | 'analyzers'
  | 'llm'
  | 'audit'

export const MAINTENANCE_TABS: readonly MaintenanceTab[] = [
  'runtime',
  'analyzers',
  'llm',
  'audit',
]
