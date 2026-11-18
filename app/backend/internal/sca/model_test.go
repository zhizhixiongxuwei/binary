package sca

import (
	"binaryscan.local/backend/internal/sbom"
	"testing"
)

func TestVulnerabilityExpandsAllPackageInstances(t *testing.T) {
	d := sbom.Document{Components: []sbom.Component{{ID: "a", PURL: "pkg:maven/a/b@1", Path: "lib/a"}, {ID: "b", PURL: "pkg:maven/a/b@1", Path: "lib/b"}}}
	b := []byte(`{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-TEST","PkgIdentifier":{"PURL":"pkg:maven/a/b@1"}}]}]}`)
	got, diag, e := Findings(b, d)
	if e != nil || len(diag) != 0 || len(got) != 2 {
		t.Fatalf("%+v %+v %v", got, diag, e)
	}
}
