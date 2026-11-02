package app

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"binaryscan.local/backend/internal/llm"
)

type searchCandidate struct {
	FileID    string `json:"fileId"`
	Path      string `json:"path"`
	Name      string `json:"name"`
	Signature string `json:"signature"`
	StartLine int    `json:"startLine"`
	EndLine   int    `json:"endLine"`
	Code      string `json:"code"`
}
type searchContext struct {
	TotalFiles int
	Candidates []searchCandidate
}
type searchCoverage struct {
	TotalFiles         int  `json:"totalFiles"`
	IndexedFiles       int  `json:"indexedFiles"`
	SampledFiles       int  `json:"sampledFiles"`
	CandidateFunctions int  `json:"candidateFunctions"`
	InputChars         int  `json:"inputChars"`
	Truncated          bool `json:"truncated"`
}

var searchTermPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.]{2,39}$`)

func parseSearchTerms(raw string) ([]string, error) {
	var value struct {
		Terms []string `json:"terms"`
	}
	if json.Unmarshal([]byte(stripJSONFence(raw)), &value) != nil {
		return nil, invalidInsightOutput()
	}
	terms, seen := make([]string, 0, 12), map[string]bool{}
	for _, term := range value.Terms {
		term = strings.ToLower(strings.TrimSpace(term))
		if !searchTermPattern.MatchString(term) || seen[term] {
			continue
		}
		terms = append(terms, term)
		seen[term] = true
		if len(terms) == 12 {
			break
		}
	}
	if len(terms) == 0 {
		return nil, invalidInsightOutput()
	}
	return terms, nil
}

func stripJSONFence(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "```") {
		if pos := strings.IndexByte(raw, 10); pos >= 0 {
			raw = strings.TrimSpace(raw[pos+1:])
			raw = strings.TrimSpace(strings.TrimSuffix(raw, "```"))
		}
	}
	return raw
}

func (s *taskService) searchCandidates(ctx context.Context, target explanationTarget, terms []string) (searchContext, error) {
	result := searchContext{Candidates: []searchCandidate{}}
	if err := s.ensureProjectSymbols(ctx, target); err != nil {
		return result, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM source_files WHERE source_project_id = ? AND state = 'ready'`, target.ProjectID).Scan(&result.TotalFiles); err != nil {
		return result, err
	}
	words := make([]string, 0, len(terms))
	for _, term := range terms {
		if searchTermPattern.MatchString(term) {
			words = append(words, term+"*")
		}
	}
	if len(words) == 0 {
		return result, nil
	}
	search := strings.Join(words, " ")
	rows, err := s.db.QueryContext(ctx, `SELECT sf.id, sf.logical_path, ss.name, COALESCE(ss.signature, ''), ss.start_line, ss.end_line, COALESCE(ss.search_text, '')
        FROM source_symbols ss JOIN source_files sf ON sf.id = ss.source_file_id AND sf.state = 'ready'
        JOIN source_projects p ON p.id = ss.source_project_id AND p.state = 'ready'
        JOIN tasks t ON t.id = p.task_id AND t.deleted_at IS NULL
        WHERE p.task_id = ? AND p.id = ? AND ss.symbol_kind = 'function'
          AND MATCH(ss.name, ss.signature, ss.search_text) AGAINST (? IN BOOLEAN MODE)
        ORDER BY MATCH(ss.name, ss.signature, ss.search_text) AGAINST (? IN BOOLEAN MODE) DESC, sf.logical_path, ss.start_line
        LIMIT 160`, target.TaskID, target.ProjectID, search, search)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var candidate searchCandidate
		if err := rows.Scan(&candidate.FileID, &candidate.Path, &candidate.Name, &candidate.Signature, &candidate.StartLine, &candidate.EndLine, &candidate.Code); err != nil {
			return result, err
		}
		result.Candidates = append(result.Candidates, candidate)
	}
	return result, rows.Err()
}

func (s *llmService) modelJSON(ctx context.Context, settings llm.Snapshot, prompt string, limit int) (string, error) {
	var output strings.Builder
	err := s.stream(ctx, settings, prompt, func(delta string) error {
		if output.Len()+len(delta) > limit {
			return invalidInsightOutput()
		}
		_, err := output.WriteString(delta)
		return err
	})
	return output.String(), err
}

func searchPrompt(query string, candidates []searchCandidate, terms []string, maxInput int) (string, []searchCandidate, int, error) {
	prompt := `根据检索条件，从候选函数中选择真正相关的函数。按相关性返回最多12项。只输出 JSON：{"summary":"中文简述","matches":[{"fileId":"候选文件ID","startLine":1,"reason":"中文相关性理由","evidence":"候选code中的原样短语"}]}。fileId和startLine必须与候选完全一致；evidence必须是code中的原样片段。无可靠结果返回空数组。检索条件：` + string(mustInsightJSON(query)) + "<untrusted_source>"
	selected := make([]searchCandidate, 0, 24)
	inputChars := 0
	for _, candidate := range candidates {
		if len(selected) == 24 {
			break
		}
		candidate.Code = searchSnippet(candidate.Code, terms, 1400)
		body, err := json.Marshal(candidate)
		if err != nil {
			return "", nil, 0, err
		}
		line := string(body) + ";"
		if utf8.RuneCountInString(prompt)+utf8.RuneCountInString(line)+24 > maxInput+7000 {
			break
		}
		prompt += line
		inputChars += utf8.RuneCountInString(candidate.Code)
		selected = append(selected, candidate)
	}
	if len(selected) == 0 {
		return "", nil, 0, llmFailure("llm_input_too_large", "模型输入上限不足以复核检索候选。", 413)
	}
	return prompt + "</untrusted_source>", selected, inputChars, nil
}

func truncateSearch(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

func searchSnippet(value string, terms []string, limit int) string {
	lower := strings.ToLower(value)
	position := len(value)
	for _, term := range terms {
		if found := strings.Index(lower, term); found >= 0 && found < position {
			position = found
		}
	}
	if position == len(value) {
		return truncateSearch(value, limit)
	}
	runes := []rune(value)
	offset := utf8.RuneCountInString(value[:position])
	start := max(0, offset-180)
	end := min(len(runes), start+limit)
	if start == 0 {
		return string(runes[:end])
	}
	header := strings.SplitN(value, string(byte(10)), 2)[0]
	return truncateSearch(header, 180) + " ... " + string(runes[start:end])
}

type searchModelMatch struct {
	FileID    string `json:"fileId"`
	StartLine int    `json:"startLine"`
	Reason    string `json:"reason"`
	Evidence  string `json:"evidence"`
}

func parseSearchMatches(raw string, selected []searchCandidate) (insightResult, error) {
	var value struct {
		Summary string             `json:"summary"`
		Matches []searchModelMatch `json:"matches"`
	}
	result := insightResult{Nodes: []architectureNode{}, Edges: []architectureEdge{}, Flow: []string{}, Matches: []functionMatch{}}
	if json.Unmarshal([]byte(stripJSONFence(raw)), &value) != nil || strings.TrimSpace(value.Summary) == "" || utf8.RuneCountInString(value.Summary) > 4000 {
		return result, invalidInsightOutput()
	}
	result.Summary = value.Summary
	seen := map[string]bool{}
	for _, match := range value.Matches {
		if len(result.Matches) == 12 {
			break
		}
		key := fmt.Sprintf("%s:%d", match.FileID, match.StartLine)
		if seen[key] || strings.TrimSpace(match.Reason) == "" || utf8.RuneCountInString(match.Reason) > 1000 {
			continue
		}
		evidence := strings.TrimSpace(match.Evidence)
		if evidence == "" || utf8.RuneCountInString(evidence) > 1500 {
			continue
		}
		for _, candidate := range selected {
			if candidate.FileID == match.FileID && candidate.StartLine == match.StartLine && strings.Contains(candidate.Code, evidence) {
				result.Matches = append(result.Matches, functionMatch{FileID: candidate.FileID, Path: candidate.Path, Name: candidate.Name, StartLine: candidate.StartLine, EndLine: candidate.EndLine, Reason: match.Reason, Evidence: evidence})
				seen[key] = true
				break
			}
		}
	}
	return result, nil
}

func (s *llmService) searchInsight(ctx context.Context, settings llm.Snapshot, target explanationTarget, query string) (insightResult, searchCoverage, error) {
	empty := insightResult{Nodes: []architectureNode{}, Edges: []architectureEdge{}, Flow: []string{}, Matches: []functionMatch{}}
	termsPrompt := `请为反编译源码函数检索生成4到12个英文代码关键词或API名（3到40个字母数字或点下划线），覆盖C、Java、Python常见实现；只输出JSON：{"terms":["keyword"]}。用户自然语言条件是JSON字符串：` + string(mustInsightJSON(query))
	raw, err := s.modelJSON(ctx, settings, termsPrompt, 4096)
	if err != nil {
		return empty, searchCoverage{}, err
	}
	terms, err := parseSearchTerms(raw)
	if err != nil {
		return empty, searchCoverage{}, err
	}
	source, err := s.searchProject(ctx, target, terms)
	if err != nil {
		return empty, searchCoverage{}, err
	}
	coverage := searchCoverage{TotalFiles: source.TotalFiles, IndexedFiles: source.TotalFiles, CandidateFunctions: len(source.Candidates)}
	if len(source.Candidates) == 0 {
		empty.Summary = "已检索项目函数索引，未发现与条件匹配的源码候选。可尝试换一种描述。"
		return empty, coverage, nil
	}
	prompt, selected, inputChars, err := searchPrompt(query, source.Candidates, terms, settings.MaxInputChars)
	if err != nil {
		return empty, coverage, err
	}
	coverage.InputChars = inputChars
	files := map[string]bool{}
	for _, item := range selected {
		files[item.FileID] = true
	}
	coverage.SampledFiles = len(files)
	coverage.Truncated = len(source.Candidates) > len(selected)
	raw, err = s.modelJSON(ctx, settings, prompt, 24000)
	if err != nil {
		return empty, coverage, err
	}
	result, err := parseSearchMatches(raw, selected)
	return result, coverage, err
}
