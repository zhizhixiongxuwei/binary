package checkrules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Rule struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	CWEs           []string `json:"cwes"`
	Severity       string   `json:"severity"`
	Language       string   `json:"language"`
	DefaultEnabled bool     `json:"default_enabled"`
	Limitations    []string `json:"limitations"`
}
type Catalog struct {
	Version        string `json:"version"`
	Language       string `json:"language"`
	CatalogVersion string `json:"catalogVersion"`
	Rules          []Rule `json:"rules"`
}
type Observation struct {
	Language string   `json:"language"`
	Status   string   `json:"status"`
	Error    string   `json:"error"`
	Catalog  *Catalog `json:"catalog"`
}
type Selection struct {
	CatalogVersion string   `json:"catalog_version"`
	EnabledRuleIDs []string `json:"enabled_rule_ids"`
	TotalRules     int      `json:"total_rules"`
	EnabledCount   int      `json:"enabled_count"`
	Mode           string   `json:"mode"`
	Engine         string   `json:"engine"`
	Language       string   `json:"language"`
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var versionPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var ErrUnavailable = errors.New("checker rule catalog unavailable")
var ErrVersion = errors.New("checker rule catalog version mismatch")
var ErrSelection = errors.New("invalid checker rule selection")

func (c Catalog) Validate(language string) error {
	if c.Version != "checker-v1" || c.Language != language || !versionPattern.MatchString(c.CatalogVersion) || len(c.Rules) == 0 || len(c.Rules) > 1000 {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	for _, rule := range c.Rules {
		if !idPattern.MatchString(rule.ID) || seen[rule.ID] || rule.Language != language || strings.TrimSpace(rule.Name) == "" {
			return ErrUnavailable
		}
		seen[rule.ID] = true
	}
	return nil
}
func Normalize(ids []string) ([]string, error) {
	if len(ids) == 0 || len(ids) > 1000 {
		return nil, ErrSelection
	}
	seen := map[string]bool{}
	result := []string{}
	for _, id := range ids {
		if !idPattern.MatchString(id) {
			return nil, ErrSelection
		}
		if !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}
	sort.Strings(result)
	return result, nil
}
func Select(c Catalog, ids []string, version string, all bool) (*Selection, error) {
	if c.Validate(c.Language) != nil {
		return nil, ErrUnavailable
	}
	if !all && version != c.CatalogVersion {
		return nil, ErrVersion
	}
	if all {
		ids = make([]string, 0, len(c.Rules))
		for _, rule := range c.Rules {
			ids = append(ids, rule.ID)
		}
	}
	normalized, err := Normalize(ids)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, rule := range c.Rules {
		known[rule.ID] = true
	}
	for _, id := range normalized {
		if !known[id] {
			return nil, ErrSelection
		}
	}
	mode := "custom"
	if len(normalized) == len(c.Rules) {
		mode = "all"
	}
	return &Selection{CatalogVersion: c.CatalogVersion, EnabledRuleIDs: normalized, EnabledCount: len(normalized), TotalRules: len(c.Rules), Mode: mode, Engine: c.Language + "-checker", Language: c.Language}, nil
}
func Same(a, b *Selection) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.CatalogVersion != b.CatalogVersion || a.Language != b.Language || a.Engine != b.Engine || a.TotalRules != b.TotalRules || len(a.EnabledRuleIDs) != len(b.EnabledRuleIDs) {
		return false
	}
	for i := range a.EnabledRuleIDs {
		if a.EnabledRuleIDs[i] != b.EnabledRuleIDs[i] {
			return false
		}
	}
	return true
}
func FromRequest(body []byte) (*Selection, error) {
	var request struct {
		Selection *Selection `json:"selection"`
	}
	if len(body) == 0 || string(body) == "null" {
		return nil, nil
	}
	if json.Unmarshal(body, &request) != nil {
		return nil, ErrSelection
	}
	if request.Selection == nil {
		return nil, nil
	}
	s := request.Selection
	ids, err := Normalize(s.EnabledRuleIDs)
	if err != nil || !versionPattern.MatchString(s.CatalogVersion) || s.TotalRules < len(ids) || s.TotalRules > 1000 || s.EnabledCount != len(ids) || s.Engine != s.Language+"-checker" || (s.Language != "c" && s.Language != "java" && s.Language != "python") || (s.Mode != "all" && s.Mode != "custom") || ((s.Mode == "all") != (len(ids) == s.TotalRules)) {
		return nil, ErrSelection
	}
	s.EnabledRuleIDs = ids
	return s, nil
}
func BaseURL(url string) string { return strings.TrimSuffix(strings.TrimRight(url, "/"), "/v1/check") }
func Fetch(ctx context.Context, url, language string) (Catalog, error) {
	var result Catalog
	if url == "" {
		return result, ErrUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, BaseURL(url)+"/v1/rules", nil)
	if err != nil {
		return result, ErrUnavailable
	}
	client := http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return result, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return result, ErrUnavailable
	}
	if json.Unmarshal(body, &result) != nil || result.Validate(language) != nil {
		return Catalog{}, ErrUnavailable
	}
	return result, nil
}
func Describe(selection *Selection) string {
	if selection == nil {
		return "规则选择未记录（历史运行）"
	}
	return fmt.Sprintf("启用 %d/%d 条规则；目录 %s；仅评价已启用规则：%s", selection.EnabledCount, selection.TotalRules, selection.CatalogVersion, strings.Join(selection.EnabledRuleIDs, ", "))
}
