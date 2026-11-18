package impact

import (
	"binaryscan.local/backend/internal/sbom"
	"strings"
	"time"
)

func Evaluate(occurrence, run string, env EnvironmentVersion, policy PolicyVersion, bundle Bundle, rule *Rule, code CodeResult, now time.Time) Assessment {
	a := Assessment{OccurrenceID: occurrence, RunID: run, EnvironmentVersionID: env.ID, ProfileID: env.ProfileID, PolicyID: policy.ID, KnowledgeDigest: bundle.Digest, Reachability: "not_analyzed", Environment: "not_analyzed", Attack: "not_analyzed", Evidence: []string{}, Code: code, ValidUntil: now.Add(time.Duration(policy.Config.ValidHours) * time.Hour)}
	if policy.Config.Reachability {
		a.Reachability = "unknown"
	}
	if policy.Config.Environment {
		a.Environment = "unknown"
	}
	if policy.Config.Attack {
		a.Attack = "unknown"
	}
	if rule == nil {
		a.Reason = "NO_REVIEWED_VULNERABILITY_RULE"
		a.ID = sbom.Digest([]string{occurrence, run, env.ID})
		return a
	}
	if policy.Config.Reachability {
		if code.State == "reachable" {
			a.Reachability = "reachable"
		}
		if code.State == "not_reachable" && code.Complete && code.InputSHA256 != "" && code.ViewDigest != "" && code.RuleID == rule.ID && rule.CodeCoverageComplete {
			a.Reachability = "not_reachable"
			a.Excluded = true
			a.Reason = "CODE_NOT_REACHABLE_WITHIN_MODEL"
		}
	}
	dimension := func(name string) (string, bool) {
		if len(rule.Alternatives) == 0 || !rule.ConditionsComplete {
			return "unknown", false
		}
		allBranchesExcluded := true
		anyAllSatisfied := false
		hasCondition := false
		for _, branch := range rule.Alternatives {
			excluded := false
			allSatisfied := true
			inDimension := false
			for _, condition := range branch {
				if condition.Dimension != name {
					continue
				}
				hasCondition = true
				inDimension = true
				state := factState(env.Config.Facts[condition.Key], condition, now)
				a.Evidence = append(a.Evidence, condition.Key+" "+condition.Operator+" "+condition.Value+": "+state)
				if state == "false" {
					excluded = true
				}
				if state != "true" {
					allSatisfied = false
				}
				fact := env.Config.Facts[condition.Key]
				if fact.ExpiresAt != nil && fact.ExpiresAt.After(now) && fact.ExpiresAt.Before(a.ValidUntil) {
					a.ValidUntil = *fact.ExpiresAt
				}
			}
			if !excluded {
				allBranchesExcluded = false
			}
			if inDimension && allSatisfied {
				anyAllSatisfied = true
			}
		}
		if !hasCondition {
			return "unknown", false
		}
		if allBranchesExcluded {
			return "excluded", true
		}
		if anyAllSatisfied {
			return "satisfied", false
		}
		return "unknown", false
	}
	if policy.Config.Environment {
		state, excluded := dimension("environment")
		if excluded {
			a.Environment = "not_applicable"
			a.Excluded = true
			a.Reason = "REQUIRED_ENVIRONMENT_ABSENT"
		} else if state == "satisfied" {
			a.Environment = "applicable"
		}
	}
	if policy.Config.Attack {
		state, excluded := dimension("attack")
		if excluded {
			a.Attack = "not_satisfied"
			a.Excluded = true
			a.Reason = "REQUIRED_ATTACK_CONDITION_ABSENT"
		} else if state == "satisfied" {
			a.Attack = "satisfied"
		}
	}
	// Different dimensions can disprove different alternative exploit branches.
	if rule.ConditionsComplete && len(rule.Alternatives) > 0 {
		all := true
		for _, branch := range rule.Alternatives {
			excluded := false
			for _, c := range branch {
				enabled := c.Dimension == "environment" && policy.Config.Environment || c.Dimension == "attack" && policy.Config.Attack
				if enabled && factState(env.Config.Facts[c.Key], c, now) == "false" {
					excluded = true
				}
			}
			if !excluded {
				all = false
			}
		}
		if all {
			a.Excluded = true
			if a.Reason == "" {
				a.Reason = "ALL_KNOWN_EXPLOIT_BRANCHES_EXCLUDED"
			}
		}
	}
	if a.Reason == "" {
		a.Reason = "NO_RELIABLE_EXCLUSION"
	}
	a.ID = sbom.Digest([]string{occurrence, run, env.ID})
	return a
}
func factState(f Fact, c Condition, now time.Time) string {
	if !f.Verified || strings.TrimSpace(f.Evidence) == "" || f.Value == "" || f.ExpiresAt != nil && !f.ExpiresAt.After(now) {
		return "unknown"
	}
	equal := f.Value == c.Value
	if c.Operator == "neq" {
		equal = !equal
	}
	if equal {
		return "true"
	}
	return "false"
}
