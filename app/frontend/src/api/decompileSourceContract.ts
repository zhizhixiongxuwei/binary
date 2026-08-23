import type {
  DecompileSourceFile,
  DecompileSourceFileContent,
  DecompileSourceFileList,
} from '@/api/types'

const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const sha256Pattern = /^[0-9a-f]{64}$/i
const MAX_SOURCE_FILES = 20_000
const MAX_SOURCE_CONTENT_LENGTH = 64 * 1024 * 1024

export class DecompileSourceContractError extends Error {
  constructor(field: string) {
    super(`invalid decompile source response: ${field}`)
    this.name = 'DecompileSourceContractError'
  }
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new DecompileSourceContractError(field)
  }
  return value as Record<string, unknown>
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  field: string,
): void {
  const allowed = new Set(required)
  if (
    required.some((key) => !(key in value)) ||
    Object.keys(value).some((key) => !allowed.has(key))
  ) {
    throw new DecompileSourceContractError(field)
  }
}

function identifier(value: unknown, field: string): string {
  if (typeof value !== 'string' || !idPattern.test(value)) {
    throw new DecompileSourceContractError(field)
  }
  return value
}

function text(
  value: unknown,
  field: string,
  minimum: number,
  maximum: number,
): string {
  if (
    typeof value !== 'string' ||
    value.length < minimum ||
    value.length > maximum ||
    value.includes('\0')
  ) {
    throw new DecompileSourceContractError(field)
  }
  return value
}

function nonNegativeInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new DecompileSourceContractError(field)
  }
  return value as number
}

function sourceFileValue(value: unknown, field: string): DecompileSourceFile {
  const source = record(value, field)
  exactKeys(
    source,
    [
      'id',
      'projectId',
      'logicalPath',
      'language',
      'sizeBytes',
      'lineCount',
      'sha256',
    ],
    field,
  )
  const sha256 = text(source.sha256, `${field}.sha256`, 64, 64)
  if (!sha256Pattern.test(sha256)) {
    throw new DecompileSourceContractError(`${field}.sha256`)
  }
  return {
    id: identifier(source.id, `${field}.id`),
    projectId: identifier(source.projectId, `${field}.projectId`),
    logicalPath: text(source.logicalPath, `${field}.logicalPath`, 1, 2_048),
    language: text(source.language, `${field}.language`, 1, 64),
    sizeBytes: nonNegativeInteger(source.sizeBytes, `${field}.sizeBytes`),
    lineCount: nonNegativeInteger(source.lineCount, `${field}.lineCount`),
    sha256: sha256.toLowerCase(),
  }
}

export function parseDecompileSourceFileList(
  value: unknown,
): DecompileSourceFileList {
  const result = record(value, 'source_file_list')
  exactKeys(result, ['files'], 'source_file_list')
  if (!Array.isArray(result.files) || result.files.length > MAX_SOURCE_FILES) {
    throw new DecompileSourceContractError('source_file_list.files')
  }
  return {
    files: result.files.map((file, index) =>
      sourceFileValue(file, `source_file_list.files[${index}]`),
    ),
  }
}

export function parseDecompileSourceFileContent(
  value: unknown,
): DecompileSourceFileContent {
  const result = record(value, 'source_file_content')
  exactKeys(
    result,
    [
      'id',
      'projectId',
      'logicalPath',
      'language',
      'sizeBytes',
      'lineCount',
      'sha256',
      'content',
    ],
    'source_file_content',
  )
  const metadata = sourceFileValue(
    Object.fromEntries(
      Object.entries(result).filter(([key]) => key !== 'content'),
    ),
    'source_file_content',
  )
  return {
    ...metadata,
    content: text(
      result.content,
      'source_file_content.content',
      0,
      MAX_SOURCE_CONTENT_LENGTH,
    ),
  }
}
