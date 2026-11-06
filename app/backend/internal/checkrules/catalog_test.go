package checkrules

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testCatalog() Catalog {
	return Catalog{Version: "checker-v1", Language: "c", CatalogVersion: "sha256:" + strings.Repeat("a", 64), Rules: []Rule{{ID: "rule-a", Name: "A", Language: "c"}, {ID: "rule-b", Name: "B", Language: "c"}}}
}
func TestRuleSelectionCanonicalizesAndFreezesCoverage(t *testing.T) {
	catalog := testCatalog()
	selection, err := Select(catalog, []string{"rule-b", "rule-a", "rule-b"}, catalog.CatalogVersion, false)
	if err != nil || selection.Mode != "all" || selection.EnabledCount != 2 || selection.EnabledRuleIDs[0] != "rule-a" {
		t.Fatalf("selection=%+v err=%v", selection, err)
	}
	custom, err := Select(catalog, []string{"rule-b"}, catalog.CatalogVersion, false)
	if err != nil || custom.Mode != "custom" || custom.TotalRules != 2 {
		t.Fatalf("selection=%+v err=%v", custom, err)
	}
	for _, ids := range [][]string{nil, {}, {"unknown"}, {"rule a"}} {
		if _, err := Select(catalog, ids, catalog.CatalogVersion, false); !errors.Is(err, ErrSelection) {
			t.Fatalf("invalid ids %v err=%v", ids, err)
		}
	}
	if _, err := Select(catalog, []string{"rule-a"}, "old", false); !errors.Is(err, ErrVersion) {
		t.Fatal("version drift accepted")
	}
	body, _ := json.Marshal(map[string]any{"selection": custom})
	decoded, err := FromRequest(body)
	if err != nil || !Same(decoded, custom) {
		t.Fatalf("snapshot roundtrip=%+v err=%v", decoded, err)
	}
	legacy, err := FromRequest([]byte(`{"source":"manual"}`))
	if err != nil || legacy != nil {
		t.Fatal("legacy history must remain unrecorded")
	}
}
func TestCatalogFetchValidatesProtocolAndLanguage(t *testing.T) {
	catalog := testCatalog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/rules" {
			t.Error("unexpected request")
		}
		_ = json.NewEncoder(w).Encode(catalog)
	}))
	defer server.Close()
	if _, err := Fetch(context.Background(), server.URL+"/v1/check", "c"); err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(context.Background(), server.URL, "java"); err == nil {
		t.Fatal("different checker language accepted")
	}
	catalog.CatalogVersion = "placeholder"
	if _, err := Fetch(context.Background(), server.URL, "c"); err == nil {
		t.Fatal("invalid catalog identity accepted")
	}
}
