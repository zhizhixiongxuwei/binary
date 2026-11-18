package impact

import (
	"fmt"
	"strings"
	"time"
)

const Version = "impact-v1"

type Fact struct {
	Value     string     `json:"value"`
	Verified  bool       `json:"verified"`
	Evidence  string     `json:"evidence"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}
type Environment struct {
	Name                 string          `json:"name"`
	JavaRelease          int             `json:"javaRelease"`
	ApplicationType      string          `json:"applicationType"`
	EntryPoints          []string        `json:"entryPoints"`
	Facts                map[string]Fact `json:"facts"`
	ExternalDependencies []string        `json:"externalDependencies"`
}

func (e Environment) Validate() error {
	if strings.TrimSpace(e.Name) == "" || len(e.Name) > 255 {
		return fmt.Errorf("environment_name_required")
	}
	switch e.JavaRelease {
	case 8, 11, 17, 21:
	default:
		return fmt.Errorf("unsupported_java_release")
	}
	if e.ApplicationType != "java" && e.ApplicationType != "spring" && e.ApplicationType != "war" {
		return fmt.Errorf("invalid_application_type")
	}
	if len(e.EntryPoints) > 1000 || len(e.Facts) > 200 || len(e.ExternalDependencies) > 100 {
		return fmt.Errorf("environment_limit_exceeded")
	}
	for k, f := range e.Facts {
		if len(k) > 128 || len(f.Value) > 1024 || len(f.Evidence) > 8192 || f.Verified && strings.TrimSpace(f.Evidence) == "" {
			return fmt.Errorf("invalid_environment_fact")
		}
	}
	for _, entry := range e.EntryPoints {
		if len(entry) > 1024 || !strings.Contains(entry, "#") {
			return fmt.Errorf("invalid_entry_point")
		}
	}
	return nil
}

type Policy struct {
	Mode         string `json:"mode"`
	ValidHours   int    `json:"validHours"`
	Reachability bool   `json:"reachability"`
	Environment  bool   `json:"environment"`
	Attack       bool   `json:"attack"`
}

func (p Policy) Validate() error {
	if (p.Mode != "suggest" && p.Mode != "automatic") || p.ValidHours < 1 || p.ValidHours > 24*90 {
		return fmt.Errorf("invalid_analysis_policy")
	}
	return nil
}

type EnvironmentVersion struct {
	ID          string      `json:"id"`
	ProfileID   string      `json:"profileId"`
	Revision    uint64      `json:"revision"`
	Fingerprint string      `json:"fingerprint"`
	Config      Environment `json:"config"`
}
type PolicyVersion struct {
	ID          string `json:"id"`
	TaskID      string `json:"taskId"`
	Fingerprint string `json:"fingerprint"`
	Config      Policy `json:"config"`
}
type Condition struct {
	Key       string `json:"key"`
	Operator  string `json:"operator"`
	Value     string `json:"value"`
	Dimension string `json:"dimension"`
}
type Rule struct {
	ID                   string        `json:"id"`
	Vulnerability        string        `json:"vulnerability"`
	PURLPrefix           string        `json:"purlPrefix"`
	Sources              []string      `json:"sources"`
	TargetClassPrefixes  []string      `json:"targetClassPrefixes"`
	CodeCoverageComplete bool          `json:"codeCoverageComplete"`
	Alternatives         [][]Condition `json:"alternatives"`
	ConditionsComplete   bool          `json:"conditionsComplete"`
	Note                 string        `json:"note"`
}
type Bundle struct {
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Rules   []Rule `json:"rules"`
}
type CodeResult struct {
	State         string   `json:"state"`
	Path          []string `json:"path"`
	Diagnostics   []string `json:"diagnostics"`
	Complete      bool     `json:"complete"`
	EngineVersion string   `json:"engineVersion"`
	InputSHA256   string   `json:"inputSha256"`
	ViewDigest    string   `json:"viewDigest"`
	RuleID        string   `json:"ruleId"`
}
type Assessment struct {
	ID                   string     `json:"id"`
	OccurrenceID         string     `json:"occurrenceId"`
	RunID                string     `json:"runId"`
	EnvironmentVersionID string     `json:"environmentVersionId"`
	ProfileID            string     `json:"profileId"`
	PolicyID             string     `json:"policyId"`
	KnowledgeDigest      string     `json:"knowledgeDigest"`
	Reachability         string     `json:"reachability"`
	Environment          string     `json:"environment"`
	Attack               string     `json:"attack"`
	Excluded             bool       `json:"excluded"`
	Reason               string     `json:"reason"`
	Evidence             []string   `json:"evidence"`
	Code                 CodeResult `json:"code"`
	ValidUntil           time.Time  `json:"validUntil"`
}
