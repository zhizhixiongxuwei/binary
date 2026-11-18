package impact

import (
	"binaryscan.local/backend/internal/sbom"
	"encoding/json"
	"fmt"
	"os"
)

// A conservative target superset of the API named by the vendor, including all
// interpolator lookups. This is reachability, never an input-sanitization proof.
var builtin = Bundle{Version: "reviewed-java-20261117-v1", Rules: []Rule{{
	ID: "apache-commons-text-interpolation-v1", Vulnerability: "CVE-2022-42889", PURLPrefix: "pkg:maven/org.apache.commons/commons-text@",
	Sources:             []string{"https://commons.apache.org/proper/commons-text/security.html"},
	TargetClassPrefixes: []string{"org/apache/commons/text/StringSubstitutor", "org/apache/commons/text/lookup/"}, CodeCoverageComplete: true,
	Note: "Conservative interpolation API target superset; reachable does not prove untrusted input. No environment or attack exclusion is inferred from the advisory.",
}, {
	ID: "log4j-context-recursion-v1", Vulnerability: "CVE-2021-45105", PURLPrefix: "pkg:maven/org.apache.logging.log4j/log4j-core@",
	Sources:            []string{"https://logging.apache.org/security.html#CVE-2021-45105"},
	ConditionsComplete: true, Alternatives: [][]Condition{{
		{Key: "log4j.contextLookupPattern", Operator: "eq", Value: "true", Dimension: "environment"},
		{Key: "log4j.attackerControlledMdc", Operator: "eq", Value: "true", Dimension: "attack"},
	}}, Note: "Vendor-described recursion prerequisite; verified evidence must describe effective logging configuration and all deployed instances. Does not exclude other Log4j CVEs.",
}}}

func Rules() (Bundle, error) {
	b := builtin
	if path := os.Getenv("BINARY_IMPACT_RULE_BUNDLE"); path != "" {
		body, e := os.ReadFile(path)
		if e != nil {
			return b, e
		}
		if len(body) > 8<<20 {
			return b, fmt.Errorf("rule_bundle_limit")
		}
		if e = json.Unmarshal(body, &b); e != nil {
			return b, e
		}
		expected := os.Getenv("BINARY_IMPACT_RULE_SHA256")
		if len(expected) != 64 || expected != sbom.BytesDigest(body) {
			return b, fmt.Errorf("rule_bundle_digest_mismatch")
		}
	}
	if b.Version == "" || len(b.Rules) > 10000 {
		return b, fmt.Errorf("invalid_rule_bundle")
	}
	seen := map[string]bool{}
	for _, r := range b.Rules {
		if r.ID == "" || r.Vulnerability == "" || r.PURLPrefix == "" || len(r.Sources) == 0 || seen[r.ID] {
			return b, fmt.Errorf("invalid_rule_identity")
		}
		seen[r.ID] = true
		for _, branch := range r.Alternatives {
			if len(branch) == 0 {
				return b, fmt.Errorf("empty_exploit_branch")
			}
			for _, c := range branch {
				if c.Key == "" || (c.Operator != "eq" && c.Operator != "neq") || (c.Dimension != "environment" && c.Dimension != "attack") {
					return b, fmt.Errorf("invalid_rule_condition")
				}
			}
		}
	}
	b.Digest = ""
	b.Digest = sbom.Digest(b)
	return b, nil
}
