export interface SourceFunction { name: string; startLine: number; endLine: number }

/** Lightweight navigation hints, not a language parser. */
export function findSourceFunctions(source: string): SourceFunction[] {
  const lines = source.replace(/\r\n/g, '\n').split('\n')
  const result: SourceFunction[] = []
  const signature = /^(?!\s*(?:if|for|while|switch|catch|return|new)\b)(?:[\w.$<>\[\]*&,?:~]+\s+){0,5}([\w$.:~<>]+)\s*\([^;{}]*\)\s*(?:\{|throws\b|:|$)/
  for (let index = 0; index < lines.length && result.length < 150; index++) {
    const line = lines[index] ?? ''
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#')) continue
    const python = /^\s*(?:async\s+)?def\s+([\w]+)\s*\(/.exec(line)
    const match = python ?? signature.exec(trimmed)
    if (!match) continue
    const name = match[1] ?? ''
    if (!name || ['if', 'for', 'while', 'switch', 'catch', 'return'].includes(name)) continue
    let end = index
    if (python) {
      const indent = line.length - line.trimStart().length
      while (end + 1 < lines.length) {
        const next = lines[end + 1] ?? ''
        if (next.trim() && next.length - next.trimStart().length <= indent) break
        end++
      }
    } else {
      let depth = 0
      let opened = false
      for (let cursor = index; cursor < Math.min(lines.length, index + 500); cursor++) {
        for (const char of lines[cursor] ?? '') {
          if (char === '{') { depth++; opened = true }
          else if (char === '}') depth--
        }
        end = cursor
        if (opened && depth <= 0) break
        if (!opened && cursor > index + 2) break
      }
    }
    result.push({ name, startLine: index + 1, endLine: Math.max(index + 1, end + 1) })
    index = end
  }
  return result
}
