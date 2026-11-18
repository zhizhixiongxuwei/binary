package sbom

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEquivalentInputs(t *testing.T) {
	root := "../../../../test-fixtures/sca"
	if _, e := os.Stat(root); e != nil {
		t.Skip("run script/fixtures/sca_samples.py")
	}
	var want string
	for _, name := range []string{"spdx.json", "spdx.spdx", "cyclonedx-1.4.json", "cyclonedx-1.5.json", "cyclonedx-1.6.json"} {
		t.Run(name, func(t *testing.T) {
			b, e := os.ReadFile(filepath.Join(root, name))
			if e != nil {
				t.Fatal(e)
			}
			d, e := Parse(context.Background(), b, "")
			if e != nil {
				t.Fatal(e)
			}
			if len(d.Components) != 1 {
				t.Fatalf("components: %+v", d)
			}
			got := d.Components[0].PURL
			if want == "" {
				want = got
			}
			if got != want {
				t.Fatalf("identity mismatch %s", got)
			}
			if d.Components[0].Quality != "identified" {
				t.Fatal(d.Diagnostics)
			}
		})
	}
}
func TestRejectAmbiguousJSON(t *testing.T) {
	for _, s := range []string{`{"bomFormat":"CycloneDX","specVersion":"1.6","specVersion":"1.4"}`, `{"bomFormat":"CycloneDX","specVersion":"9.0"}`, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library"}]}`} {
		if _, e := Parse(context.Background(), []byte(s), ""); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}
func TestXMLDoesNotResolveEntities(t *testing.T) {
	_, e := Parse(context.Background(), []byte(`<!DOCTYPE bom [<!ENTITY x SYSTEM "file:///etc/passwd">]><bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components>&x;</components></bom>`), "")
	if e == nil || !strings.Contains(e.Error(), "DIRECTIVES_DISABLED") {
		t.Fatal(e)
	}
}
func TestNoVersionDoesNotBecomeClean(t *testing.T) {
	d := Document{Components: []Component{{Name: "commons-text", SourceRef: "x"}}}
	if e := Finalize(&d); e != nil {
		t.Fatal(e)
	}
	if d.Quality != "partial" || d.Components[0].Quality != "unresolved" {
		t.Fatal(d)
	}
}

func TestSPDX231OfficialExamples(t *testing.T) {
	for _, name := range []string{"spdx-2.3.1-official.json", "spdx-2.3.1-official.spdx"} {
		body, err := os.ReadFile(filepath.Join("../../../../test-fixtures/sca", name))
		if os.IsNotExist(err) {
			t.Skip("generate fixture corpus")
		}
		if err != nil {
			t.Fatal(err)
		}
		d, err := Parse(context.Background(), body, "")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d.SpecVersion != "SPDX-2.3" || len(d.Components) == 0 {
			t.Fatal("official maintenance example did not produce an inventory")
		}
	}
}
