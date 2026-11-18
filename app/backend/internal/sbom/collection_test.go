package sbom

import "testing"

func TestSWIDCollectionResolvesOnlyExplicitLocalMembers(t *testing.T) {
	app := Document{Standard: "SWID", Encoding: "xml", InputSHA256: BytesDigest([]byte("app")), Components: []Component{{SourceRef: "app-tag", Name: "app", Version: "1", References: []Reference{{Type: "component", Value: "lib.swidtag"}, {Type: "see-also", Value: "https://unreachable.invalid/remote.swidtag"}}}}}
	lib := Document{Standard: "SWID", Encoding: "xml", InputSHA256: BytesDigest([]byte("lib")), Components: []Component{{SourceRef: "lib-tag", Name: "Commons Text", Version: "1.9"}}}
	d, err := SWIDCollection([]LocalTag{{app, "tags/app.swidtag"}, {lib, "tags/lib.swidtag"}}, map[string]string{"lib-tag": "pkg:maven/org.apache.commons/commons-text@1.9"})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Dependencies) != 1 || d.Dependencies[0].To != "lib-tag" || d.Components[1].Quality != "identified" || d.Components[0].Quality != "unresolved" {
		t.Fatalf("%+v", d)
	}
	if d.Fingerprint == "" || d.Schema != Version {
		t.Fatal("collection was not finalized")
	}
	_, err = SWIDCollection([]LocalTag{{app, "../app.swidtag"}}, nil)
	if err == nil {
		t.Fatal("unsafe local member accepted")
	}
	_, err = SWIDCollection([]LocalTag{{app, "app.swidtag"}, {app, "other.swidtag"}}, nil)
	if err == nil {
		t.Fatal("duplicate tag id accepted")
	}
}

func TestSWIDComponentLinkDoesNotRewriteSelfIdentity(t *testing.T) {
	root, err := parseXML([]byte(`<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" name="host" tagId="host-tag" version="1"><Link rel="component" href="pkg:maven/org.apache.commons/commons-text@1.9"/></SoftwareIdentity>`))
	if err != nil {
		t.Fatal(err)
	}
	d := Document{}
	parseSWID(root, &d)
	if err = Finalize(&d); err != nil {
		t.Fatal(err)
	}
	if d.Components[0].PURL != "" || d.Components[0].Quality != "unresolved" {
		t.Fatal("a dependency link became the host's identity")
	}
}
