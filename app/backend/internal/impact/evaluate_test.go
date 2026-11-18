package impact

import (
	"testing"
	"time"
)

func TestAlternativeExploitPathsAndUnverifiedFacts(t *testing.T) {
	now := time.Now()
	env := EnvironmentVersion{ID: "env", Config: Environment{Facts: map[string]Fact{"a": {Value: "off", Verified: true, Evidence: "effective config"}, "b": {Value: "on", Verified: true, Evidence: "effective config"}}}}
	p := PolicyVersion{Config: Policy{Mode: "automatic", ValidHours: 24, Environment: true, Attack: true, Reachability: true}}
	rule := Rule{ID: "test", ConditionsComplete: true, Alternatives: [][]Condition{{{Key: "a", Operator: "eq", Value: "on", Dimension: "environment"}}, {{Key: "b", Operator: "eq", Value: "on", Dimension: "attack"}}}}
	a := Evaluate("o", "r", env, p, Bundle{}, &rule, CodeResult{}, now)
	if a.Excluded {
		t.Fatal("one disqualified branch incorrectly excludes another viable branch")
	}
	env.Config.Facts["b"] = Fact{Value: "off", Verified: false}
	if Evaluate("o", "r", env, p, Bundle{}, &rule, CodeResult{}, now).Excluded {
		t.Fatal("unverified fact used as proof")
	}
	env.Config.Facts["b"] = Fact{Value: "off", Verified: true, Evidence: "verified"}
	if !Evaluate("o", "r", env, p, Bundle{}, &rule, CodeResult{}, now).Excluded {
		t.Fatal("all alternative paths excluded")
	}
}
func TestIncompleteCodeCannotIgnore(t *testing.T) {
	p := PolicyVersion{Config: Policy{ValidHours: 24, Reachability: true}}
	r := Rule{ID: "test", CodeCoverageComplete: true}
	code := CodeResult{State: "not_reachable", RuleID: "test", InputSHA256: "sha", ViewDigest: "view"}
	a := Evaluate("o", "r", EnvironmentVersion{}, p, Bundle{}, &r, code, time.Now())
	if a.Excluded || a.Reachability != "unknown" {
		t.Fatal(a)
	}
}
