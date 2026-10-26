export interface ExplanationTextBlock { kind: 'heading' | 'paragraph' | 'bullet' | 'code'; text: string }
export interface ExplanationTextPart { text: string; startLine?: number; endLine?: number }

/** Keep model output as text. Only headings, list markers and fenced code affect layout. */
export function explanationBlocks(value: string): ExplanationTextBlock[] {
  const blocks: ExplanationTextBlock[] = []
  let code: string[] | null = null
  for (const raw of value.split(/\r?\n/)) {
    if (/^\s*```/.test(raw)) {
      if (code) { blocks.push({ kind: 'code', text: code.join('\n') }); code = null }
      else code = []
      continue
    }
    if (code) { code.push(raw); continue }
    const text = raw.trim()
    if (!text) continue
    const heading = text.match(/^#{1,6}\s+(.+)$/)
    const section = /^(?:\*\*)?(?:[一二三四1-4][、.．]\s*)?(?:功能概述|功能说明|关键函数(?:与参数)?|执行流程|推断说明|推断与限制|不确定性)(?:\*\*)?[：:]?$/.test(text)
    if (heading || section) blocks.push({ kind: 'heading', text: heading?.[1] ?? text.replace(/^\*\*|\*\*$/g, '') })
    else if (/^(?:[-*+] |\d+\. )/.test(text)) blocks.push({ kind: 'bullet', text: text.replace(/^(?:[-*+] |\d+\. )/, '') })
    else blocks.push({ kind: 'paragraph', text })
  }
  if (code) blocks.push({ kind: 'code', text: code.join('\n') })
  return blocks
}

export function explanationLineParts(text: string, lineCount: number): ExplanationTextPart[] {
  const parts: ExplanationTextPart[] = []
  const pattern = /\bL(\d+)(?:\s*[-–—~至]\s*L?(\d+))?\b/g
  let offset = 0
  for (const match of text.matchAll(pattern)) {
    const index = match.index
    if (index > offset) parts.push({ text: text.slice(offset, index) })
    const startLine = Number(match[1])
    const endLine = Number(match[2] ?? match[1])
    parts.push(Number.isSafeInteger(startLine) && startLine >= 1 && endLine >= startLine && endLine <= lineCount
      ? { text: match[0], startLine, endLine } : { text: match[0] })
    offset = index + match[0].length
  }
  if (offset < text.length) parts.push({ text: text.slice(offset) })
  return parts
}
