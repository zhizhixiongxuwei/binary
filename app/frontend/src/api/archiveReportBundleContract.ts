import type {
  ArchiveReportBundle,
  ArchiveReportBundleList,
  ArchiveReportBundleStatus,
  ReportFormat,
} from '@/api/types'

const statuses = new Set<ArchiveReportBundleStatus>([
  'ready',
  'failed',
  'deleted',
])
const formats = new Set<ReportFormat>(['json', 'html', 'docx'])
const sha256Pattern = /^[a-f0-9]{64}$/

export class ArchiveReportBundleContractError extends Error {
  constructor(field: string) {
    super(`归档报告包响应不符合接口契约：${field}`)
    this.name = 'ArchiveReportBundleContractError'
  }
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ArchiveReportBundleContractError(field)
  }
  return value as Record<string, unknown>
}

function text(value: unknown, field: string, maximum = 256): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum) {
    throw new ArchiveReportBundleContractError(field)
  }
  return value
}

function integer(value: unknown, field: string, maximum = 100_000): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > maximum
  ) {
    throw new ArchiveReportBundleContractError(field)
  }
  return value
}

function timestamp(value: unknown, field: string): string {
  const parsed = text(value, field, 64)
  if (!Number.isFinite(Date.parse(parsed))) {
    throw new ArchiveReportBundleContractError(field)
  }
  return parsed
}

function parseBundle(value: unknown, field: string): ArchiveReportBundle {
  const item = record(value, field)
  const required = [
    'id',
    'archive_import_id',
    'status',
    'schema_version',
    'formats',
    'include_sources',
    'included_tasks',
    'omitted_tasks',
    'report_files',
    'source_files',
    'sha256',
    'size_bytes',
    'created_at',
    'completed_at',
  ] as const
  if (
    required.some((key) => !Object.prototype.hasOwnProperty.call(item, key)) ||
    Object.keys(item).some((key) => !required.includes(key as typeof required[number]))
  ) {
    throw new ArchiveReportBundleContractError(field)
  }
  const status = text(item.status, `${field}.status`, 24)
  if (!statuses.has(status as ArchiveReportBundleStatus)) {
    throw new ArchiveReportBundleContractError(`${field}.status`)
  }
  if (!Array.isArray(item.formats) || item.formats.length < 1 || item.formats.length > 3) {
    throw new ArchiveReportBundleContractError(`${field}.formats`)
  }
  const parsedFormats = item.formats.map((value, index) => {
    const format = text(value, `${field}.formats[${index}]`, 8)
    if (!formats.has(format as ReportFormat)) {
      throw new ArchiveReportBundleContractError(`${field}.formats[${index}]`)
    }
    return format as ReportFormat
  })
  if (new Set(parsedFormats).size !== parsedFormats.length) {
    throw new ArchiveReportBundleContractError(`${field}.formats`)
  }
  const digest = text(item.sha256, `${field}.sha256`, 64)
  if (!sha256Pattern.test(digest)) {
    throw new ArchiveReportBundleContractError(`${field}.sha256`)
  }
  if (typeof item.include_sources !== 'boolean') {
    throw new ArchiveReportBundleContractError(`${field}.include_sources`)
  }
  const sizeBytes = integer(item.size_bytes, `${field}.size_bytes`, 10 * 1024 ** 3)
  return {
    id: text(item.id, `${field}.id`, 128),
    archive_import_id: text(item.archive_import_id, `${field}.archive_import_id`, 128),
    status: status as ArchiveReportBundleStatus,
    schema_version: text(item.schema_version, `${field}.schema_version`, 128),
    formats: parsedFormats,
    include_sources: item.include_sources,
    included_tasks: integer(item.included_tasks, `${field}.included_tasks`),
    omitted_tasks: integer(item.omitted_tasks, `${field}.omitted_tasks`),
    report_files: integer(item.report_files, `${field}.report_files`),
    source_files: integer(item.source_files, `${field}.source_files`),
    sha256: digest,
    size_bytes: sizeBytes,
    created_at: timestamp(item.created_at, `${field}.created_at`),
    completed_at: timestamp(item.completed_at, `${field}.completed_at`),
  }
}

export function parseArchiveReportBundle(value: unknown): ArchiveReportBundle {
  const envelope = record(value, 'data')
  if (Object.keys(envelope).length !== 1 || envelope.bundle === undefined) {
    throw new ArchiveReportBundleContractError('data')
  }
  return parseBundle(envelope.bundle, 'data.bundle')
}

export function parseArchiveReportBundleList(value: unknown): ArchiveReportBundleList {
  const envelope = record(value, 'data')
  if (
    Object.keys(envelope).length !== 1 ||
    !Array.isArray(envelope.bundles) ||
    envelope.bundles.length > 100
  ) {
    throw new ArchiveReportBundleContractError('data.bundles')
  }
  const items = envelope.bundles.map((item, index) =>
    parseBundle(item, `data.bundles[${index}]`),
  )
  if (new Set(items.map((item) => item.id)).size !== items.length) {
    throw new ArchiveReportBundleContractError('data.bundles')
  }
  return { items }
}
