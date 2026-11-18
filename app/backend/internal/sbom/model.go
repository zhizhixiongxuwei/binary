// Package sbom implements bounded offline normalization, preserving source identity.
package sbom

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

const Version = "sbom-normalizer-v1"
const MaxBytes = 64 << 20
const MaxComponents = 100000

type Diagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Ref     string `json:"ref,omitempty"`
}
type Reference struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
type Component struct {
	ID         string      `json:"id"`
	SourceRef  string      `json:"sourceRef"`
	Name       string      `json:"name"`
	Group      string      `json:"group,omitempty"`
	Version    string      `json:"version"`
	PURL       string      `json:"purl,omitempty"`
	CPE        string      `json:"cpe,omitempty"`
	Supplier   string      `json:"supplier,omitempty"`
	Path       string      `json:"path"`
	SHA256     string      `json:"sha256,omitempty"`
	Identity   string      `json:"identity"`
	Quality    string      `json:"quality"`
	References []Reference `json:"references,omitempty"`
}
type Dependency struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}
type Document struct {
	Schema       string       `json:"schemaVersion"`
	Standard     string       `json:"standard"`
	SpecVersion  string       `json:"specVersion"`
	Encoding     string       `json:"encoding"`
	DocumentID   string       `json:"documentId"`
	InputSHA256  string       `json:"inputSha256"`
	Fingerprint  string       `json:"fingerprint"`
	Quality      string       `json:"quality"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies"`
	Diagnostics  []Diagnostic `json:"diagnostics"`
}

func Digest(v any) string         { b, _ := json.Marshal(v); return fmt.Sprintf("%x", sha256.Sum256(b)) }
func BytesDigest(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func MavenPURL(group, name, version string) string {
	if group == "" || name == "" || version == "" {
		return ""
	}
	return "pkg:maven/" + url.PathEscape(group) + "/" + url.PathEscape(name) + "@" + url.PathEscape(version)
}
func MavenIdentity(purl string) (group, name, version string, ok bool) {
	if !strings.HasPrefix(purl, "pkg:maven/") {
		return
	}
	value := strings.SplitN(strings.TrimPrefix(purl, "pkg:maven/"), "?", 2)[0]
	value = strings.SplitN(value, "#", 2)[0]
	identity, v, found := strings.Cut(value, "@")
	if !found {
		return
	}
	g, n, found := strings.Cut(identity, "/")
	if !found {
		return
	}
	group, e1 := url.PathUnescape(g)
	name, e2 := url.PathUnescape(n)
	version, e3 := url.PathUnescape(v)
	ok = e1 == nil && e2 == nil && e3 == nil && group != "" && name != "" && version != ""
	return
}
func PackageIdentity(purl string) (kind, group, name, version string, ok bool) {
	if !strings.HasPrefix(purl, "pkg:") {
		return
	}
	kind, rest, found := strings.Cut(strings.TrimPrefix(purl, "pkg:"), "/")
	if !found {
		return
	}
	supported := map[string]bool{"maven": true, "npm": true, "pypi": true, "golang": true, "cargo": true, "gem": true, "nuget": true, "composer": true, "hex": true, "swift": true, "cocoapods": true, "deb": true, "rpm": true, "apk": true, "alpm": true, "conan": true, "conda": true}
	if !supported[kind] {
		return
	}
	rest = strings.SplitN(strings.SplitN(rest, "?", 2)[0], "#", 2)[0]
	at := strings.LastIndex(rest, "@")
	if at < 1 {
		return
	}
	identity := rest[:at]
	version, err := url.PathUnescape(rest[at+1:])
	if err != nil || version == "" {
		return
	}
	slash := strings.LastIndex(identity, "/")
	if slash >= 0 {
		group, err = url.PathUnescape(identity[:slash])
		if err != nil {
			return
		}
		identity = identity[slash+1:]
	}
	name, err = url.PathUnescape(identity)
	ok = err == nil && name != ""
	return
}
func Finalize(d *Document) error {
	if len(d.Components) > MaxComponents || len(d.Dependencies) > MaxComponents*10 {
		return fmt.Errorf("SBOM_LIMIT_EXCEEDED")
	}
	refs := map[string]string{}
	seen := map[string]bool{}
	for i := range d.Components {
		c := &d.Components[i]
		if c.SourceRef == "" {
			c.SourceRef = fmt.Sprintf("anonymous-%d", i)
			d.Diagnostics = append(d.Diagnostics, Diagnostic{"MISSING_SOURCE_REF", "Component has no source identifier", c.Name})
		}
		if seen[c.SourceRef] {
			return fmt.Errorf("DUPLICATE_COMPONENT_REF: %s", c.SourceRef)
		}
		seen[c.SourceRef] = true
		if c.Name == "" {
			return fmt.Errorf("COMPONENT_NAME_REQUIRED: %s", c.SourceRef)
		}
		c.Quality = "unresolved"
		if kind, group, name, version, ok := PackageIdentity(c.PURL); ok {
			if c.Version != "" && c.Version != version {
				d.Diagnostics = append(d.Diagnostics, Diagnostic{"IDENTITY_VERSION_CONFLICT", "Declared version disagrees with PURL; exact matching disabled", c.SourceRef})
			} else {
				if c.Name != name {
					c.References = append(c.References, Reference{"original-name", c.Name})
				}
				c.Group = group
				c.Name = name
				c.Version = version
				c.Quality = "identified"
				if kind == "deb" || kind == "rpm" || kind == "apk" || kind == "alpm" {
					d.Diagnostics = append(d.Diagnostics, Diagnostic{"OS_CONTEXT_NOT_VERIFIED", "OS package identity is preserved; distro and repository context must be independently verified for accurate matching", c.SourceRef})
				}
			}
		}
		if len(c.Name) > 512 || len(c.Version) > 255 || len(c.Path) > 4096 || len(c.SourceRef) > 4096 || len(c.PURL) > 4096 {
			return fmt.Errorf("SBOM_COMPONENT_FIELD_LIMIT: %s", c.SourceRef)
		}
		if c.Version == "" {
			d.Diagnostics = append(d.Diagnostics, Diagnostic{"MISSING_VERSION", "Component version is missing", c.SourceRef})
		}
		if c.Quality == "unresolved" {
			d.Diagnostics = append(d.Diagnostics, Diagnostic{"IDENTITY_UNRESOLVED", "No supported exact ecosystem identity; vulnerability matching is incomplete", c.SourceRef})
		}
		c.Identity = Digest([]string{c.Supplier, c.Group, c.Name, c.Version, c.PURL, c.CPE})
		c.ID = Digest([]string{c.Identity, c.Path, c.SourceRef, c.SHA256})
		refs[c.SourceRef] = c.ID
	}
	for _, r := range d.Dependencies {
		if refs[r.From] == "" || refs[r.To] == "" {
			d.Diagnostics = append(d.Diagnostics, Diagnostic{"DANGLING_RELATION", "Relation references an element not represented as a component", r.From + " -> " + r.To})
		}
	}
	d.Schema = Version
	uniqueDiagnostics := make([]Diagnostic, 0, len(d.Diagnostics))
	seenDiagnostics := map[Diagnostic]bool{}
	for _, diagnostic := range d.Diagnostics {
		if !seenDiagnostics[diagnostic] {
			seenDiagnostics[diagnostic] = true
			uniqueDiagnostics = append(uniqueDiagnostics, diagnostic)
		}
	}
	d.Diagnostics = uniqueDiagnostics
	if len(d.Diagnostics) > 500 {
		total := len(d.Diagnostics)
		d.Diagnostics = append(d.Diagnostics[:500], Diagnostic{"DIAGNOSTICS_TRUNCATED", fmt.Sprintf("%d diagnostics; first 500 shown. Original input is preserved.", total), ""})
	}
	d.Quality = "complete"
	if len(d.Diagnostics) > 0 {
		d.Quality = "partial"
	}
	if d.Components == nil {
		d.Components = []Component{}
	}
	if d.Dependencies == nil {
		d.Dependencies = []Dependency{}
	}
	if d.Diagnostics == nil {
		d.Diagnostics = []Diagnostic{}
	}
	d.Fingerprint = ""
	d.Fingerprint = Digest(d)
	return nil
}

// CycloneDX produces an identity-preserving scanner input. It never trusts an imported VEX claim.
func CycloneDX(d Document) ([]byte, error) {
	components := make([]map[string]any, 0, len(d.Components))
	for _, c := range d.Components {
		if c.Quality != "identified" {
			continue
		}
		components = append(components, map[string]any{"type": "library", "bom-ref": c.ID, "group": c.Group, "name": c.Name, "version": c.Version, "purl": c.PURL})
	}
	return json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components})
}
