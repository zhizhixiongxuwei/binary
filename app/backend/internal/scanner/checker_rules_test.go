package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"binaryscan.local/backend/internal/checkrules"
)

func scannerRuleCatalog() checkrules.Catalog {
	return checkrules.Catalog{Version: "checker-v1", Language: "c", CatalogVersion: "sha256:" + strings.Repeat("a", 64), Rules: []checkrules.Rule{{ID: "rule-a", Name: "A", Language: "c"}, {ID: "rule-b", Name: "B", Language: "c"}}}
}
func TestWorkerValidatesFrozenCatalogBeforeSendingSource(t *testing.T) {
	catalog := scannerRuleCatalog()
	selection, _ := checkrules.Select(catalog, []string{"rule-a"}, catalog.CatalogVersion, false)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/rules" {
			t.Fatal("unexpected source submission")
		}
		_ = json.NewEncoder(w).Encode(catalog)
	}))
	defer server.Close()
	if err := validateCheckerSelection(context.Background(), server.URL+"/v1/check", "c", selection); err != nil {
		t.Fatal(err)
	}
	catalog.CatalogVersion = "sha256:" + strings.Repeat("b", 64)
	if err := validateCheckerSelection(context.Background(), server.URL+"/v1/check", "c", selection); !errors.Is(err, checkrules.ErrVersion) {
		t.Fatalf("catalog drift=%v", err)
	}
}
func TestCheckerProtocolRejectsDisabledRulesAndFalseAppliedSnapshots(t *testing.T) {
	catalog := scannerRuleCatalog()
	response := checkerResponse{Version: "checker-v1", ProjectID: "project", Status: "complete", CatalogVersion: catalog.CatalogVersion, AppliedRuleIDs: []string{"rule-a"}, Findings: []checkerFinding{{RuleID: "rule-a"}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request checkerRequest
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request.CatalogVersion != catalog.CatalogVersion || len(request.RuleIDs) != 1 || request.RuleIDs[0] != "rule-a" {
			t.Error("snapshot not transmitted")
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	request := checkerRequest{Version: "checker-v1", ProjectID: "project", Language: "c", RuleIDs: []string{"rule-a"}, CatalogVersion: catalog.CatalogVersion}
	if _, err := callChecker(context.Background(), server.Client(), server.URL, request); err != nil {
		t.Fatal(err)
	}
	response.Findings[0].RuleID = "rule-b"
	if _, err := callChecker(context.Background(), server.Client(), server.URL, request); !errors.Is(err, checkrules.ErrSelection) {
		t.Fatalf("disabled finding accepted: %v", err)
	}
	response.Findings = nil
	response.AppliedRuleIDs = []string{"rule-a", "rule-b"}
	if _, err := callChecker(context.Background(), server.Client(), server.URL, request); !errors.Is(err, checkrules.ErrSelection) {
		t.Fatalf("wrong coverage accepted: %v", err)
	}
	response.AppliedRuleIDs = []string{"rule-a"}
	response.CatalogVersion = "old"
	if _, err := callChecker(context.Background(), server.Client(), server.URL, request); !errors.Is(err, checkrules.ErrVersion) {
		t.Fatalf("wrong version accepted: %v", err)
	}
}
