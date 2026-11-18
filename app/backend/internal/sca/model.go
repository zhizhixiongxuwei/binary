package sca

import (
	"binaryscan.local/backend/internal/sbom"
	"encoding/json"
	"fmt"
	"strings"
)

const Version = "sca-v1"

type Vulnerability struct {
	ID           string          `json:"id"`
	ComponentID  string          `json:"componentId"`
	Component    sbom.Component  `json:"component"`
	Severity     string          `json:"severity"`
	Title        string          `json:"title"`
	Description  string          `json:"description"`
	FixedVersion string          `json:"fixedVersion"`
	PrimaryURL   string          `json:"primaryUrl"`
	CVSS         json.RawMessage `json:"cvss,omitempty"`
	DataSource   json.RawMessage `json:"dataSource,omitempty"`
}
type Report struct {
	Results []struct {
		Target          string
		Vulnerabilities []struct {
			VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, Title, Description, PrimaryURL string
			PkgIdentifier                                                                                      struct{ PURL, UID, BOMRef string }
			CVSS                                                                                               json.RawMessage
			DataSource                                                                                         json.RawMessage
		}
	}
}

func Findings(body []byte, d sbom.Document) ([]Vulnerability, []sbom.Diagnostic, error) {
	var r Report
	if e := json.Unmarshal(body, &r); e != nil {
		return nil, nil, e
	}
	result := []Vulnerability{}
	diagnostics := []sbom.Diagnostic{}
	seen := map[string]bool{}
	for _, group := range r.Results {
		for _, v := range group.Vulnerabilities {
			matches := []sbom.Component{}
			for _, c := range d.Components {
				if c.ID == v.PkgIdentifier.BOMRef || v.PkgIdentifier.PURL != "" && c.PURL == v.PkgIdentifier.PURL {
					matches = append(matches, c)
				}
			}
			if len(matches) == 0 {
				diagnostics = append(diagnostics, sbom.Diagnostic{Code: "VULNERABILITY_INSTANCE_UNMAPPED", Message: "Scanner vulnerability cannot be safely assigned to an inventory instance", Ref: v.VulnerabilityID})
				// Keep the original scanner hit visible with an explicitly unresolved
				// instance. It must never become a code reachability proof.
				c := sbom.Component{Name: v.PkgName, Version: v.InstalledVersion, SourceRef: "scanner-unmapped:" + sbom.Digest([]string{group.Target, v.PkgName, v.InstalledVersion, v.PkgIdentifier.PURL}), Path: group.Target, Quality: "unresolved"}
				c.Identity = sbom.Digest([]string{c.SourceRef})
				c.ID = c.Identity
				matches = append(matches, c)
			}
			for _, c := range matches {
				key := c.ID + "/" + v.VulnerabilityID
				if seen[key] {
					continue
				}
				seen[key] = true
				title := v.Title
				if title == "" {
					title = v.VulnerabilityID
				}
				result = append(result, Vulnerability{ID: v.VulnerabilityID, ComponentID: c.ID, Component: c, Severity: strings.ToLower(v.Severity), Title: title, Description: v.Description, FixedVersion: v.FixedVersion, PrimaryURL: v.PrimaryURL, CVSS: v.CVSS, DataSource: v.DataSource})
			}
		}
	}
	if len(result) > 100000 {
		return nil, nil, fmt.Errorf("SCA_FINDING_LIMIT_EXCEEDED")
	}
	return result, diagnostics, nil
}

type Inventory struct {
	ID              string        `json:"id"`
	TaskID          string        `json:"taskId"`
	RunID           string        `json:"runId"`
	Document        sbom.Document `json:"document"`
	CreatedAt       string        `json:"createdAt"`
	ComponentCount  int           `json:"componentCount"`
	DependencyCount int           `json:"dependencyCount"`
}
type Occurrence struct {
	ID            string             `json:"id"`
	TaskID        string             `json:"taskId"`
	Vulnerability Vulnerability      `json:"vulnerability"`
	Assessments   []json.RawMessage  `json:"assessments"`
	Dispositions  []ScopeDisposition `json:"dispositions"`
	Status        string             `json:"status"`
}
type ScopeDisposition struct {
	ProfileID            string `json:"profileId"`
	EnvironmentVersionID string `json:"environmentVersionId"`
	AssessmentID         string `json:"assessmentId,omitempty"`
	Status               string `json:"status"`
	Source               string `json:"source"`
	Revision             uint64 `json:"revision"`
	Reason               string `json:"reason"`
	Validity             string `json:"validity"`
	ExpiresAt            string `json:"expiresAt,omitempty"`
	OverrideUntil        string `json:"overrideUntil,omitempty"`
}
