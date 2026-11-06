import type { LocationQuery, LocationQueryRaw } from 'vue-router'

import type { AnalysisMode, TaskExecutionStatus } from '@/api/types'
import { taskExecutionStatusLabels } from '@/components/tasks/taskExecutionPresentation'

export const TASK_PAGE_SIZES = [10, 20, 50] as const

export const ANALYSIS_MODE_OPTIONS = [
  { value: 'binary', label: '二进制' },
  { value: 'archive', label: '归档导入' },
  { value: 'container', label: '容器/映像' },
] as const satisfies readonly { value: AnalysisMode; label: string }[]

const taskExecutionFilterStatuses = [
  'UPLOADED', 'PREPARING', 'DECOMPILING', 'DECOMPILED',
  'DECOMPILE_PARTIAL', 'DECOMPILE_FAILED', 'SCANNING',
  'SCAN_COMPLETED', 'SCAN_PARTIAL', 'SCAN_FAILED', 'FAILED', 'CANCELLED',
  'UNSUPPORTED', 'DELETING',
] as const satisfies readonly TaskExecutionStatus[]
export const USER_TASK_STATUS_OPTIONS = taskExecutionFilterStatuses.map((value) => ({ value, label: taskExecutionStatusLabels[value] }))

export type TaskFilterStatus = (typeof USER_TASK_STATUS_OPTIONS)[number]['value']

export interface InputFormatGroup {
  label: string
  options: readonly string[]
}

export const INPUT_FORMAT_GROUPS: readonly InputFormatGroup[] = [
  {
    label: '二进制',
    options: ['pe32', 'pe32+', 'elf32', 'elf64', 'macho-thin', 'macho-fat'],
  },
  {
    label: '字节码',
    options: ['java-class', 'dex', 'pyc'],
  },
  {
    label: '归档',
    options: [
      'zip',
      'tar',
      'gzip',
      'bzip2',
      'xz',
      'zstd',
      '7z',
      'rar',
      'cab',
      'cpio',
      'ar',
      'rpm',
      'deb',
      'jar',
      'war',
      'ear',
      'apk',
    ],
  },
  {
    label: '映像',
    options: ['ext2', 'ext3', 'ext4', 'squashfs', 'iso9660', 'udf', 'mbr-img', 'gpt-img'],
  },
  {
    label: '容器',
    options: ['docker-tar', 'oci-tar'],
  },
  {
    label: '其他',
    options: ['unknown'],
  },
] as const

export interface TaskFilterValue {
  keyword: string
  status: TaskFilterStatus | ''
  input_type: string
  analysis_mode: AnalysisMode | ''
  creator: string
  tag: string
  created_from: string
  created_to: string
}

export interface TaskListRouteState extends TaskFilterValue {
  cursor: string
  expanded: string
  page_size: (typeof TASK_PAGE_SIZES)[number]
}

export const DEFAULT_TASK_LIST_STATE: Readonly<TaskListRouteState> = {
  keyword: '',
  status: '',
  input_type: '',
  analysis_mode: '',
  creator: '',
  tag: '',
  created_from: '',
  created_to: '',
  cursor: '',
  expanded: '',
  page_size: 20,
}

const userTaskStatuses = new Set<string>(
  USER_TASK_STATUS_OPTIONS.map((option) => option.value),
)
const inputFormatPattern = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/
const isoDatePattern = /^(\d{4})-(\d{2})-(\d{2})$/
const opaqueCursorPattern = /^[A-Za-z0-9_-]{1,256}$/

type RouteQueryValue = LocationQuery[string] | undefined

function singleQueryValue(value: RouteQueryValue): string | undefined {
  return typeof value === 'string' ? value : undefined
}

function parsePageSize(value: RouteQueryValue): TaskListRouteState['page_size'] {
  const candidate = singleQueryValue(value)
  if (!candidate || !/^[1-9]\d*$/.test(candidate)) {
    return DEFAULT_TASK_LIST_STATE.page_size
  }
  const numericValue = Number(candidate)
  return TASK_PAGE_SIZES.includes(numericValue as TaskListRouteState['page_size'])
    ? (numericValue as TaskListRouteState['page_size'])
    : DEFAULT_TASK_LIST_STATE.page_size
}

function parseCursor(value: RouteQueryValue): string {
  const candidate = singleQueryValue(value)
  return candidate && opaqueCursorPattern.test(candidate) ? candidate : ''
}

function hasControlCharacter(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0
    return codePoint <= 0x1f || codePoint === 0x7f
  })
}

function normalizeText(
  value: string,
  maximumLength: number,
): string | null {
  const candidate = value.trim()
  if (
    hasControlCharacter(candidate) ||
    Array.from(candidate).length > maximumLength
  ) {
    return null
  }
  return candidate
}

export function normalizeTaskKeyword(value: string): string | null {
  return normalizeText(value, 255)
}

export function normalizeTaskCreator(value: string): string | null {
  return normalizeText(value, 128)
}

export function normalizeTaskTag(value: string): string | null {
  return normalizeText(value, 64)
}

function parseText(
  value: RouteQueryValue,
  normalize: (candidate: string) => string | null,
): string {
  const candidate = singleQueryValue(value)
  if (candidate === undefined) return ''
  return normalize(candidate) ?? ''
}

function parseStatus(value: RouteQueryValue): TaskFilterStatus | '' {
  const candidate = singleQueryValue(value)
  return candidate && userTaskStatuses.has(candidate)
    ? (candidate as TaskFilterStatus)
    : ''
}

function parseAnalysisMode(value: RouteQueryValue): AnalysisMode | '' {
  const candidate = singleQueryValue(value)
  return ANALYSIS_MODE_OPTIONS.some((option) => option.value === candidate)
    ? candidate as AnalysisMode
    : ''
}

function parseExpanded(value: RouteQueryValue): string {
  const candidate = singleQueryValue(value)
  return candidate && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(candidate)
    ? candidate
    : ''
}

export function normalizeInputFormat(value: string): string | null {
  const candidate = value.trim().toLowerCase()
  if (!candidate) return ''
  return inputFormatPattern.test(candidate) ? candidate : null
}

function parseInputFormat(value: RouteQueryValue): string {
  const candidate = singleQueryValue(value)
  if (candidate === undefined) return ''
  return normalizeInputFormat(candidate) ?? ''
}

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
}

export function normalizeTaskDate(value: string): string | null {
  const candidate = value.trim()
  if (!candidate) return ''
  const match = isoDatePattern.exec(candidate)
  if (!match) return null

  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  if (year < 1 || month < 1 || month > 12 || day < 1) return null

  const daysInMonth = [
    31,
    isLeapYear(year) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ]
  return day <= (daysInMonth[month - 1] ?? 0) ? candidate : null
}

function parseTaskDate(value: RouteQueryValue): string {
  const candidate = singleQueryValue(value)
  if (candidate === undefined) return ''
  return normalizeTaskDate(candidate) ?? ''
}

export function taskDateRangeIsValid(
  createdFrom: string,
  createdTo: string,
): boolean {
  return !createdFrom || !createdTo || createdFrom <= createdTo
}

export function parseTaskListRouteQuery(query: LocationQuery): TaskListRouteState {
  const pageSize = parsePageSize(query.page_size)
  let createdFrom = parseTaskDate(query.created_from)
  let createdTo = parseTaskDate(query.created_to)
  if (!taskDateRangeIsValid(createdFrom, createdTo)) {
    createdFrom = ''
    createdTo = ''
  }
  return {
    keyword: parseText(query.keyword, normalizeTaskKeyword),
    status: parseStatus(query.status),
    input_type: parseInputFormat(query.input_type),
    analysis_mode: parseAnalysisMode(query.analysis_mode),
    creator: parseText(query.creator, normalizeTaskCreator),
    tag: parseText(query.tag, normalizeTaskTag),
    created_from: createdFrom,
    created_to: createdTo,
    cursor: parseCursor(query.cursor),
    expanded: parseExpanded(query.expanded),
    page_size: pageSize,
  }
}

export function serializeTaskListRouteQuery(
  state: TaskListRouteState,
): LocationQueryRaw {
  const query: LocationQueryRaw = {
    page_size: String(state.page_size),
  }
  if (state.cursor) query.cursor = state.cursor
  if (state.keyword) query.keyword = state.keyword
  if (state.status) query.status = state.status
  if (state.input_type) query.input_type = state.input_type
  if (state.analysis_mode) query.analysis_mode = state.analysis_mode
  if (state.expanded) query.expanded = state.expanded
  if (state.creator) query.creator = state.creator
  if (state.tag) query.tag = state.tag
  if (state.created_from) query.created_from = state.created_from
  if (state.created_to) query.created_to = state.created_to
  return query
}

export function taskRouteQueryIsCanonical(
  current: LocationQuery,
  canonical: LocationQueryRaw,
): boolean {
  const currentKeys = Object.keys(current).sort()
  const canonicalKeys = Object.keys(canonical).sort()
  if (
    currentKeys.length !== canonicalKeys.length ||
    currentKeys.some((key, index) => key !== canonicalKeys[index])
  ) {
    return false
  }
  return canonicalKeys.every((key) => {
    const currentValue = current[key]
    const canonicalValue = canonical[key]
    return typeof currentValue === 'string' && currentValue === canonicalValue
  })
}
