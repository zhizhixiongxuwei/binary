package sbom

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	spdxcommon "github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
	v23reader "github.com/spdx/tools-golang/spdx/v2/v2_3/tagvalue/reader"
	tvreader "github.com/spdx/tools-golang/tagvalue/reader"
)

//go:embed schemas/*
var Schemas embed.FS
var schemaCache sync.Map

type offlineLoader struct{}

func (offlineLoader) Load(u string) (any, error) {
	return nil, fmt.Errorf("remote schema loading is disabled: %s", u)
}

var cdxMarker = regexp.MustCompile(`"bomFormat"\s*:\s*"CycloneDX"`)
var spdxMarker = regexp.MustCompile(`"spdxVersion"\s*:\s*"SPDX-`)

func Detect(body []byte) string {
	b := bytes.TrimSpace(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf}))
	if len(b) > 0 && b[0] == '{' {
		if cdxMarker.Match(b) {
			return "cyclonedx-json"
		}
		if spdxMarker.Match(b) {
			return "spdx-json"
		}
	}
	if bytes.HasPrefix(b, []byte("SPDXVersion:")) {
		return "spdx-tag-value"
	}
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		t, e := dec.Token()
		if e != nil {
			break
		}
		if start, ok := t.(xml.StartElement); ok {
			if start.Name.Local == "bom" && strings.HasPrefix(start.Name.Space, "http://cyclonedx.org/schema/bom/") {
				return "cyclonedx-xml"
			}
			if start.Name.Local == "SoftwareIdentity" && start.Name.Space == swidNamespace {
				return "swid-xml"
			}
			break
		}
	}
	return ""
}

const swidNamespace = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd"

func Parse(ctx context.Context, body []byte, xmlTool string) (Document, error) {
	d := Document{InputSHA256: BytesDigest(body)}
	if len(body) > MaxBytes {
		return d, fmt.Errorf("SBOM_LIMIT_EXCEEDED")
	}
	body = bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})
	format := Detect(body)
	switch format {
	case "cyclonedx-json", "spdx-json":
		value, err := strictJSON(body)
		if err != nil {
			return d, err
		}
		root, ok := value.(map[string]any)
		if !ok {
			return d, fmt.Errorf("INVALID_SBOM_ROOT")
		}
		d.Encoding = "json"
		if format == "cyclonedx-json" {
			d.Standard = "CycloneDX"
			d.SpecVersion = str(root["specVersion"])
			if !cdxVersion(d.SpecVersion) {
				return d, fmt.Errorf("UNSUPPORTED_SBOM_VERSION: %s", d.SpecVersion)
			}
			if err = validateJSON(root, "bom-"+d.SpecVersion+".schema.json"); err != nil {
				return d, err
			}
			parseCDX(root, &d)
		} else {
			d.Standard = "SPDX"
			d.SpecVersion = str(root["spdxVersion"])
			if d.SpecVersion != "SPDX-2.3" {
				return d, fmt.Errorf("UNSUPPORTED_SBOM_VERSION: %s", d.SpecVersion)
			}
			if err = validateJSON(root, "spdx-2.3.json"); err != nil {
				return d, err
			}
			parseSPDX(root, &d)
		}
	case "spdx-tag-value":
		root, err := tagValue(body)
		if err != nil {
			return d, err
		}
		if str(root["spdxVersion"]) != "SPDX-2.3" {
			return d, fmt.Errorf("UNSUPPORTED_SBOM_VERSION")
		}
		if err = validateJSON(root, "spdx-2.3.json"); err != nil {
			return d, err
		}
		d.Standard = "SPDX"
		d.SpecVersion = "SPDX-2.3"
		d.Encoding = "tag-value"
		parseSPDX(root, &d)
	case "cyclonedx-xml", "swid-xml":
		root, err := parseXML(body)
		if err != nil {
			return d, err
		}
		d.Encoding = "xml"
		schema := "swid.xsd"
		if format == "cyclonedx-xml" {
			d.Standard = "CycloneDX"
			d.SpecVersion = strings.TrimPrefix(root.Name.Space, "http://cyclonedx.org/schema/bom/")
			if !cdxVersion(d.SpecVersion) {
				return d, fmt.Errorf("UNSUPPORTED_SBOM_VERSION: %s", d.SpecVersion)
			}
			schema = "bom-" + d.SpecVersion + ".xsd"
		} else {
			d.Standard = "SWID"
			d.SpecVersion = "2015"
		}
		if err = validateXML(ctx, body, schema, xmlTool); err != nil {
			return d, err
		}
		if format == "cyclonedx-xml" {
			parseCDXXML(root, &d)
		} else {
			parseSWID(root, &d)
		}
	default:
		return d, fmt.Errorf("UNSUPPORTED_SBOM_FORMAT")
	}
	if err := Finalize(&d); err != nil {
		return d, err
	}
	return d, nil
}
func cdxVersion(v string) bool { return v == "1.4" || v == "1.5" || v == "1.6" }
func str(v any) string         { s, _ := v.(string); return s }
func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func arr(v any) []any          { a, _ := v.([]any); return a }
func parseCDX(root map[string]any, d *Document) {
	d.DocumentID = str(root["serialNumber"])
	var visit func([]any)
	visit = func(values []any) {
		for _, v := range values {
			m := obj(v)
			c := Component{SourceRef: str(m["bom-ref"]), Name: str(m["name"]), Group: str(m["group"]), Version: str(m["version"]), PURL: str(m["purl"]), CPE: str(m["cpe"])}
			for _, h := range arr(m["hashes"]) {
				if strings.EqualFold(str(obj(h)["alg"]), "SHA-256") {
					c.SHA256 = str(obj(h)["content"])
				}
			}
			c.Supplier = str(obj(m["supplier"])["name"])
			d.Components = append(d.Components, c)
			visit(arr(m["components"]))
		}
	}
	if m := obj(obj(root["metadata"])["component"]); m != nil {
		visit([]any{m})
	}
	visit(arr(root["components"]))
	for _, v := range arr(root["dependencies"]) {
		m := obj(v)
		for _, to := range arr(m["dependsOn"]) {
			d.Dependencies = append(d.Dependencies, Dependency{str(m["ref"]), str(to), "DEPENDS_ON"})
		}
	}
	if len(arr(root["vulnerabilities"])) > 0 {
		d.Diagnostics = append(d.Diagnostics, Diagnostic{"IMPORTED_CLAIMS_UNTRUSTED", "Original vulnerability/VEX declarations preserved in source; local scan does not trust their disposition", ""})
	}
}
func parseSPDX(root map[string]any, d *Document) {
	d.DocumentID = str(root["documentNamespace"])
	for _, v := range arr(root["packages"]) {
		m := obj(v)
		c := Component{SourceRef: str(m["SPDXID"]), Name: str(m["name"]), Version: str(m["versionInfo"]), Path: str(m["packageFileName"]), Supplier: str(m["supplier"])}
		for _, v := range arr(m["externalRefs"]) {
			r := obj(v)
			t, value := str(r["referenceType"]), str(r["referenceLocator"])
			c.References = append(c.References, Reference{t, value})
			if t == "purl" {
				c.PURL = value
			}
			if t == "cpe23Type" || t == "cpe22Type" {
				c.CPE = value
			}
		}
		for _, v := range arr(m["checksums"]) {
			h := obj(v)
			if str(h["algorithm"]) == "SHA256" {
				c.SHA256 = str(h["checksumValue"])
			}
		}
		d.Components = append(d.Components, c)
	}
	for _, v := range arr(root["relationships"]) {
		m := obj(v)
		d.Dependencies = append(d.Dependencies, Dependency{str(m["spdxElementId"]), str(m["relatedSpdxElement"]), str(m["relationshipType"])})
	}
}

// Reject duplicates/deep structures before schema validation; do not permit
// different parsers to interpret duplicate identity or version fields differently.
func strictJSON(body []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	count := 0
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		count++
		if depth > 128 || count > 2000000 {
			return nil, fmt.Errorf("SBOM_STRUCTURE_LIMIT")
		}
		t, e := dec.Token()
		if e != nil {
			return nil, e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return t, nil
		}
		switch delim {
		case '{':
			m := map[string]any{}
			for dec.More() {
				k, e := dec.Token()
				if e != nil {
					return nil, e
				}
				key, ok := k.(string)
				if !ok {
					return nil, fmt.Errorf("invalid key")
				}
				if _, ok = m[key]; ok {
					return nil, fmt.Errorf("DUPLICATE_JSON_KEY: %s", key)
				}
				v, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				m[key] = v
			}
			_, e = dec.Token()
			return m, e
		case '[':
			a := []any{}
			for dec.More() {
				v, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			_, e = dec.Token()
			return a, e
		}
		return nil, fmt.Errorf("invalid JSON")
	}
	v, e := read(0)
	if e != nil {
		return nil, e
	}
	if _, e = dec.Token(); e != io.EOF {
		return nil, fmt.Errorf("TRAILING_JSON_CONTENT")
	}
	return v, nil
}
func validateJSON(v any, name string) error {
	cached, ok := schemaCache.Load(name)
	if !ok {
		c := jsonschema.NewCompiler()
		c.UseLoader(offlineLoader{})
		entries, _ := Schemas.ReadDir("schemas")
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") || entry.Name() == "manifest.json" {
				continue
			}
			b, e := Schemas.ReadFile("schemas/" + entry.Name())
			if e != nil {
				return e
			}
			value, e := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if e != nil {
				return e
			}
			if e = c.AddResource("https://binaryscan.local/schemas/"+entry.Name(), value); e != nil {
				return e
			}
			if e = c.AddResource("http://cyclonedx.org/schema/"+entry.Name(), value); e != nil {
				return e
			}
		}
		schema, e := c.Compile("https://binaryscan.local/schemas/" + name)
		if e != nil {
			return fmt.Errorf("SCHEMA_UNAVAILABLE: %w", e)
		}
		cached, _ = schemaCache.LoadOrStore(name, schema)
	}
	if e := cached.(*jsonschema.Schema).Validate(v); e != nil {
		return fmt.Errorf("SBOM_SCHEMA_INVALID: %w", e)
	}
	return nil
}

type xmlNode struct {
	Name     xml.Name
	Attrs    []xml.Attr
	Text     string
	Children []*xmlNode
}

func (n *xmlNode) attr(k string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == k {
			return a.Value
		}
	}
	return ""
}
func (n *xmlNode) child(k string) *xmlNode {
	for _, c := range n.Children {
		if c.Name.Local == k {
			return c
		}
	}
	return &xmlNode{}
}
func (n *xmlNode) text(k string) string { return strings.TrimSpace(n.child(k).Text) }
func parseXML(body []byte) (*xmlNode, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	stack := []*xmlNode{}
	var root *xmlNode
	nodes := 0
	for {
		t, e := dec.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		switch t := t.(type) {
		case xml.Directive:
			return nil, fmt.Errorf("XML_DTD_AND_DIRECTIVES_DISABLED")
		case xml.StartElement:
			nodes++
			if nodes > 2000000 || len(stack) >= 128 {
				return nil, fmt.Errorf("SBOM_STRUCTURE_LIMIT")
			}
			n := &xmlNode{Name: t.Name, Attrs: t.Attr}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, n)
			} else {
				if root != nil {
					return nil, fmt.Errorf("MULTIPLE_XML_ROOTS")
				}
				root = n
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("invalid XML")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				n := stack[len(stack)-1]
				n.Text += string(t)
			} else if strings.TrimSpace(string(t)) != "" {
				return nil, fmt.Errorf("XML_TRAILING_CONTENT")
			}
		}
	}
	if root == nil || len(stack) > 0 {
		return nil, fmt.Errorf("EMPTY_XML")
	}
	return root, nil
}
func validateXML(ctx context.Context, body []byte, name, tool string) error {
	if tool == "" {
		tool = "xmllint"
	}
	dir, e := os.MkdirTemp("", "sbom-schema-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	entries, _ := Schemas.ReadDir("schemas")
	for _, en := range entries {
		if strings.HasSuffix(en.Name(), ".xsd") {
			b, _ := Schemas.ReadFile("schemas/" + en.Name())
			if e = os.WriteFile(filepath.Join(dir, en.Name()), b, 0600); e != nil {
				return e
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, "--nonet", "--noout", "--schema", filepath.Join(dir, name), "-")
	cmd.Stdin = bytes.NewReader(body)
	var stderr limitedBuffer
	cmd.Stderr = &stderr
	if e = cmd.Run(); e != nil {
		return fmt.Errorf("XML_SCHEMA_VALIDATION_FAILED: %w: %s", e, stderr.String())
	}
	return nil
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 8192 - b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.Buffer.Write(p)
	}
	return n, nil
}
func parseCDXXML(root *xmlNode, d *Document) {
	d.DocumentID = root.attr("serialNumber")
	var visit func(*xmlNode)
	visit = func(n *xmlNode) {
		for _, x := range n.Children {
			if x.Name.Local != "component" {
				continue
			}
			c := Component{SourceRef: x.attr("bom-ref"), Name: x.text("name"), Group: x.text("group"), Version: x.text("version"), PURL: x.text("purl"), CPE: x.text("cpe"), Supplier: x.child("supplier").text("name")}
			for _, h := range x.child("hashes").Children {
				if h.attr("alg") == "SHA-256" {
					c.SHA256 = strings.TrimSpace(h.Text)
				}
			}
			d.Components = append(d.Components, c)
			visit(x.child("components"))
		}
	}
	visit(root.child("components"))
	if m := root.child("metadata").child("component"); m.Name.Local != "" {
		visit(&xmlNode{Children: []*xmlNode{m}})
	}
	for _, dep := range root.child("dependencies").Children {
		for _, to := range dep.Children {
			d.Dependencies = append(d.Dependencies, Dependency{dep.attr("ref"), to.attr("ref"), "DEPENDS_ON"})
		}
	}
	if len(root.child("vulnerabilities").Children) > 0 {
		d.Diagnostics = append(d.Diagnostics, Diagnostic{"IMPORTED_CLAIMS_UNTRUSTED", "Imported VEX is not an automatic disposition proof", ""})
	}
}
func parseSWID(root *xmlNode, d *Document) {
	d.DocumentID = root.attr("tagId")
	c := Component{SourceRef: d.DocumentID, Name: root.attr("name"), Version: root.attr("version")}
	if _, _, _, _, ok := PackageIdentity(d.DocumentID); ok {
		c.PURL = d.DocumentID
	}
	for _, n := range root.Children {
		if n.Name.Local == "Entity" {
			if strings.Contains(n.attr("role"), "softwareCreator") {
				c.Supplier = n.attr("name")
			}
			c.References = append(c.References, Reference{"entity", n.attr("regid")})
		}
		if n.Name.Local == "Link" {
			href := n.attr("href")
			c.References = append(c.References, Reference{n.attr("rel"), href})
			if strings.HasPrefix(href, "pkg:") && href != c.PURL {
				d.Diagnostics = append(d.Diagnostics, Diagnostic{"SWID_LINK_IDENTITY_UNVERIFIED", "A link may identify another component; use a self-identifying tagId or explicit local identity mapping", c.SourceRef})
			}
			if strings.HasPrefix(href, "swid:") {
				d.Dependencies = append(d.Dependencies, Dependency{c.SourceRef, strings.TrimPrefix(href, "swid:"), n.attr("rel")})
			}
		}
	}
	d.Components = append(d.Components, c)
	if root.attr("patch") == "true" || root.attr("supplemental") == "true" {
		d.Diagnostics = append(d.Diagnostics, Diagnostic{"SWID_NON_PRIMARY", "Patch/supplemental tag relationships retained; no automatic product replacement inferred", c.SourceRef})
	}
}
func tagValue(body []byte) (map[string]any, error) {
	pairs, err := tvreader.ReadTagValues(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("INVALID_SPDX_TAG_VALUE: %w", err)
	}
	pairs, err = orderSnippets(pairs)
	if err != nil {
		return nil, err
	}
	doc, err := v23reader.ParseTagValues(pairs)
	if err != nil {
		return nil, fmt.Errorf("INVALID_SPDX_TAG_VALUE: %w", err)
	}
	// The upstream reader stores package files and snippets in nested Go
	// structures; the standard JSON schema requires flat document collections.
	for _, p := range doc.Packages {
		for _, f := range p.Files {
			doc.Relationships = append(doc.Relationships, &v23.Relationship{RefA: spdxcommon.DocElementID{ElementRefID: p.PackageSPDXIdentifier}, RefB: spdxcommon.DocElementID{ElementRefID: f.FileSPDXIdentifier}, Relationship: "CONTAINS"})
		}
		doc.Files = append(doc.Files, p.Files...)
		p.Files = nil
	}
	seenSnippets := map[string]bool{}
	for _, f := range doc.Files {
		for _, s := range f.Snippets {
			id := string(s.SnippetSPDXIdentifier)
			if seenSnippets[id] {
				return nil, fmt.Errorf("DUPLICATE_SNIPPET_ID")
			}
			seenSnippets[id] = true
			doc.Snippets = append(doc.Snippets, *s)
		}
	}
	// Deterministic ordering prevents Go map iteration from changing fingerprints.
	sort.Slice(doc.Snippets, func(i, j int) bool {
		return string(doc.Snippets[i].SnippetSPDXIdentifier) < string(doc.Snippets[j].SnippetSPDXIdentifier)
	})
	encoded, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	value, err := strictJSON(encoded)
	if err != nil {
		return nil, err
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("INVALID_SPDX_DOCUMENT")
	}
	return root, nil
}

// SPDX permits a snippet section after package sections. tools-golang 0.5.7
// accepts it only while in file state. Reorder complete token sections next to
// their explicitly referenced file; field parsing remains with the upstream parser.
func orderSnippets(pairs []tvreader.TagValuePair) ([]tvreader.TagValuePair, error) {
	if len(pairs) == 0 || pairs[0].Tag != "SPDXVersion" || pairs[0].Value != v23.Version {
		return nil, fmt.Errorf("UNSUPPORTED_SBOM_VERSION")
	}
	sections := [][]tvreader.TagValuePair{}
	snippets := map[string][][]tvreader.TagValuePair{}
	current := []tvreader.TagValuePair{}
	ids := map[string]bool{}
	flush := func() error {
		if len(current) == 0 {
			return nil
		}
		singletons := map[string]bool{}
		for _, p := range current {
			switch p.Tag {
			case "SPDXVersion", "DataLicense", "SPDXID", "DocumentName", "DocumentNamespace", "PackageName", "PackageVersion", "FilesAnalyzed", "FileName", "SnippetSPDXID", "SnippetFromFileSPDXID":
				if singletons[p.Tag] {
					return fmt.Errorf("DUPLICATE_SPDX_FIELD: %s", p.Tag)
				}
				singletons[p.Tag] = true
			}
			if p.Tag == "SPDXID" || p.Tag == "SnippetSPDXID" {
				if ids[p.Value] {
					return fmt.Errorf("DUPLICATE_SPDX_ELEMENT_ID")
				}
				ids[p.Value] = true
			}
		}
		if current[0].Tag == "SnippetSPDXID" {
			file := ""
			for _, p := range current {
				if p.Tag == "SnippetFromFileSPDXID" {
					if file != "" {
						return fmt.Errorf("DUPLICATE_SNIPPET_FILE_REF")
					}
					file = p.Value
				}
			}
			if file == "" {
				return fmt.Errorf("SNIPPET_FILE_REF_REQUIRED")
			}
			snippets[file] = append(snippets[file], current)
		} else {
			sections = append(sections, current)
		}
		current = nil
		return nil
	}
	for _, p := range pairs {
		switch p.Tag {
		case "PackageName", "FileName", "SnippetSPDXID", "LicenseID", "Reviewer":
			if err := flush(); err != nil {
				return nil, err
			}
		}
		current = append(current, p)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	ordered := []tvreader.TagValuePair{}
	for _, section := range sections {
		ordered = append(ordered, section...)
		if section[0].Tag == "FileName" {
			for _, p := range section {
				if p.Tag == "SPDXID" {
					for _, snippet := range snippets[p.Value] {
						ordered = append(ordered, snippet...)
					}
					delete(snippets, p.Value)
				}
			}
		}
	}
	if len(snippets) > 0 {
		return nil, fmt.Errorf("SNIPPET_FILE_NOT_IN_DOCUMENT")
	}
	return ordered, nil
}
