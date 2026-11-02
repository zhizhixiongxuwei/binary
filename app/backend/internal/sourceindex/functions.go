package sourceindex

import (
	"regexp"
	"strings"
)

// Function is a navigable declaration found in an immutable source artifact.
// The extractor is deliberately conservative: an omitted function is preferable
// to a link to a call expression or to a range outside the source file.
type Function struct {
	Name       string
	Signature  string
	StartLine  int
	EndLine    int
	SearchText string
}

const MaxFunctionsPerFile = 1000

var pythonFunction = regexp.MustCompile(`^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`)
var braceFunction = regexp.MustCompile(`^(?:[\w$<>\[\].,*?]+\s+){1,8}([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?:throws\s+[\w$.,\s]+)?\s*\{?\s*$`)

// Functions extracts approximate function boundaries from decompiler output.
// It accepts only actual declaration-looking lines and complete bodies.
func Functions(language, source string) []Function {
	lines := strings.Split(strings.ReplaceAll(source, "\r\n", "\n"), "\n")
	result := make([]Function, 0)
	for index := 0; index < len(lines) && len(result) < MaxFunctionsPerFile; index++ {
		line := lines[index]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if language == "python" {
			match := pythonFunction.FindStringSubmatch(line)
			if len(match) < 2 {
				continue
			}
			indent := len(line) - len(strings.TrimLeft(line, " \t"))
			end := index
			for end+1 < len(lines) {
				next := lines[end+1]
				if strings.TrimSpace(next) != "" && len(next)-len(strings.TrimLeft(next, " \t")) <= indent {
					break
				}
				end++
			}
			result = append(result, Function{truncate(match[1], 512), truncate(trimmed, 2048), index + 1, end + 1, truncate(strings.Join(lines[index:end+1], "\n"), 8192)})
			continue
		}
		if language != "java" && language != "c" {
			continue
		}
		match := braceFunction.FindStringSubmatch(trimmed)
		if len(match) < 2 || isControlWord(match[1]) || strings.HasPrefix(trimmed, "return ") || strings.HasPrefix(trimmed, "new ") {
			continue
		}
		end, found := bodyEnd(lines, index)
		if !found {
			continue
		}
		result = append(result, Function{truncate(match[1], 512), truncate(trimmed, 2048), index + 1, end + 1, truncate(strings.Join(lines[index:end+1], "\n"), 8192)})
		index = end
	}
	return result
}

func bodyEnd(lines []string, start int) (int, bool) {
	depth, opened := 0, false
	blockComment := false
	for index := start; index < len(lines) && index <= start+4000; index++ {
		line := lines[index]
		quote, escaped := byte(0), false
		for i := 0; i < len(line); i++ {
			ch := line[i]
			if blockComment {
				if ch == '*' && i+1 < len(line) && line[i+1] == '/' {
					blockComment = false
					i++
				}
				continue
			}
			if quote != 0 {
				if escaped {
					escaped = false
					continue
				}
				if ch == '\\' {
					escaped = true
					continue
				}
				if ch == quote {
					quote = 0
				}
				continue
			}
			if ch == '/' && i+1 < len(line) {
				if line[i+1] == '/' {
					break
				}
				if line[i+1] == '*' {
					blockComment = true
					i++
					continue
				}
			}
			if ch == '\'' || ch == '"' {
				quote = ch
				continue
			}
			if ch == '{' {
				depth++
				opened = true
			}
			if ch == '}' {
				depth--
			}
		}
		if opened && depth == 0 {
			return index, true
		}
		if !opened && index > start+2 {
			return 0, false
		}
	}
	return 0, false
}

func isControlWord(name string) bool {
	switch name {
	case "if", "for", "while", "switch", "catch", "return", "throw", "new", "synchronized":
		return true
	}
	return false
}

func truncate(value string, max int) string {
	runes := []rune(value)
	if len(runes) > max {
		return string(runes[:max])
	}
	return value
}
