package app

import (
	"binaryscan.local/backend/internal/sca"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

func (s *taskService) scaReportSnapshot(ctx context.Context, taskID string, runIDs []string) (map[string]any, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	store := sca.Store{DB: tx}
	items := []sca.Occurrence{}
	cursor := ""
	for {
		page, e := store.Occurrences(ctx, taskID, cursor, 200, sca.Filter{RunIDs: runIDs})
		if e != nil {
			return nil, e
		}
		items = append(items, page...)
		if len(items) > 10000 {
			return nil, fmt.Errorf("sca_report_scope_limit_exceeded")
		}
		if len(page) < 200 {
			break
		}
		cursor = page[len(page)-1].ID
	}
	summary := map[string]int{"total": len(items), "open": 0, "ignored": 0, "unknown": 0, "manualIgnoredScopes": 0, "policyIgnoredScopes": 0}
	unique := map[string]bool{}
	versions := map[string]bool{}
	policies := map[string]bool{}
	for _, o := range items {
		unique[o.Vulnerability.ID] = true
		summary[o.Status]++
		unknown := len(o.Assessments) == 0
		current := map[string]bool{}
		for _, scope := range o.Dispositions {
			if scope.AssessmentID == "" || scope.Validity != "valid" {
				unknown = true
			}
			current[scope.AssessmentID] = true
		}
		for _, b := range o.Assessments {
			var a map[string]any
			if e = json.Unmarshal(b, &a); e != nil {
				return nil, e
			}
			versions[reportText(a["environmentVersionId"])] = true
			policies[reportText(a["policyId"])] = true
			if current[reportText(a["id"])] && (a["reachability"] == "unknown" || a["environment"] == "unknown" || a["attack"] == "unknown") {
				unknown = true
			}
		}
		if unknown {
			summary["unknown"]++
		}
		for _, d := range o.Dispositions {
			versions[d.EnvironmentVersionID] = true
			if d.Status == "ignored" {
				if d.Source == "manual" {
					summary["manualIgnoredScopes"]++
				} else {
					summary["policyIgnoredScopes"]++
				}
			}
		}
	}
	summary["uniqueVulnerabilities"] = len(unique)
	inventories, e := store.Inventories(ctx, taskID)
	if e != nil {
		return nil, e
	}
	envs := []map[string]any{}
	for id := range versions {
		if id == "" {
			continue
		}
		var config []byte
		var profile, fingerprint string
		var revision uint64
		if e = tx.QueryRowContext(ctx, `SELECT profile_id,revision,fingerprint,config FROM environment_versions WHERE id=?`, id).Scan(&profile, &revision, &fingerprint, &config); e != nil {
			return nil, e
		}
		envs = append(envs, map[string]any{"id": id, "profileId": profile, "revision": revision, "fingerprint": fingerprint, "config": json.RawMessage(config)})
	}
	ps := []map[string]any{}
	for id := range policies {
		if id == "" {
			continue
		}
		var config []byte
		var fingerprint string
		if e = tx.QueryRowContext(ctx, `SELECT fingerprint,config FROM analysis_policy_versions WHERE id=?`, id).Scan(&fingerprint, &config); e != nil {
			return nil, e
		}
		ps = append(ps, map[string]any{"id": id, "fingerprint": fingerprint, "config": json.RawMessage(config)})
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return map[string]any{"schemaVersion": "sca-report-v1", "scope": "Occurrences associated with selected runs; related analysis history and current effective disposition frozen at report time", "summary": summary, "inventories": inventories, "occurrences": items, "environments": envs, "policies": ps}, nil
}
func reportSCAText(value any) string {
	body, e := json.Marshal(value)
	if e != nil || string(body) == "null" {
		return ""
	}
	var data struct {
		Summary      map[string]int   `json:"summary"`
		Inventories  []sca.Inventory  `json:"inventories"`
		Occurrences  []sca.Occurrence `json:"occurrences"`
		Environments []map[string]any `json:"environments"`
		Policies     []map[string]any `json:"policies"`
	}
	if json.Unmarshal(body, &data) != nil {
		return ""
	}
	var text strings.Builder
	fmt.Fprintf(&text, "原始漏洞实例 %d；待处置 %d；已忽略 %d；含未知 %d（未知可与待处置重叠）。\n人工忽略范围 %d；自动忽略范围 %d（按环境分别统计）。\n", data.Summary["total"], data.Summary["open"], data.Summary["ignored"], data.Summary["unknown"], data.Summary["manualIgnoredScopes"], data.Summary["policyIgnoredScopes"])
	text.WriteString("本节保留所选运行关联漏洞的原始命中、相关分析历史及报告生成时的有效处置。已忽略不等于已修复；环境画像为分析假设与证据快照。\n")
	for _, i := range data.Inventories {
		fmt.Fprintf(&text, "\n清单 %s / %s %s：组件 %d，关系 %d，质量 %s；摘要 %s\n", i.ID, i.Document.Standard, i.Document.SpecVersion, i.ComponentCount, i.DependencyCount, i.Document.Quality, i.Document.Fingerprint)
		for _, d := range i.Document.Diagnostics {
			fmt.Fprintf(&text, "  %s：%s (%s)\n", d.Code, d.Message, d.Ref)
		}
	}
	for _, o := range data.Occurrences {
		v := o.Vulnerability
		fmt.Fprintf(&text, "\n%s | %s %s | %s\n组件实例：%s\n修复版本：%s\n原始 CVSS：%s\n", v.ID, v.Component.Name, v.Component.Version, map[string]string{"open": "待处置", "ignored": "已忽略"}[o.Status], v.Component.Path, v.FixedVersion, string(v.CVSS))
		for _, d := range o.Dispositions {
			fmt.Fprintf(&text, "处置：环境 %s，%s，来源 %s，有效性 %s，原因 %s，有效至 %s，人工保留至 %s\n", d.ProfileID, d.Status, d.Source, d.Validity, d.Reason, d.ExpiresAt, d.OverrideUntil)
		}
		for _, a := range o.Assessments {
			var parsed map[string]any
			if json.Unmarshal(a, &parsed) == nil {
				formatted, _ := json.MarshalIndent(parsed, "", "  ")
				text.WriteString("分析证据：\n" + string(formatted) + "\n")
			}
		}
	}
	envJSON, _ := json.MarshalIndent(data.Environments, "", "  ")
	policyJSON, _ := json.MarshalIndent(data.Policies, "", "  ")
	text.WriteString("\n环境版本快照：\n" + string(envJSON) + "\n策略版本快照：\n" + string(policyJSON))
	return text.String()
}
