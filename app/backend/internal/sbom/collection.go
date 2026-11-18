package sbom

import (
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
)

// CollectionMember pins an already validated local tag. No links are fetched.
type CollectionMember struct {
	TaskID      string `json:"taskId"`
	InventoryID string `json:"inventoryId"`
	Fingerprint string `json:"fingerprint"`
	LogicalPath string `json:"logicalPath"`
}
type CollectionRequest struct {
	Members          []CollectionMember `json:"swidMembers"`
	IdentityMappings map[string]string  `json:"identityMappings"`
}
type LocalTag struct {
	Document    Document
	LogicalPath string
}

func SWIDCollection(tags []LocalTag, mappings map[string]string) (Document, error) {
	d := Document{Standard: "SWID", SpecVersion: "2015", Encoding: "xml-collection"}
	if len(tags) < 1 || len(tags) > 100 || len(mappings) > 100 {
		return d, fmt.Errorf("SWID_COLLECTION_LIMIT")
	}
	paths := map[string]string{}
	refs := map[string]bool{}
	digests := []string{}
	for _, tag := range tags {
		if tag.Document.Standard != "SWID" || tag.Document.Encoding != "xml" {
			return d, fmt.Errorf("SWID_SINGLE_TAG_REQUIRED")
		}
		p := path.Clean(tag.LogicalPath)
		if p == "." || p == ".." || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00:") || len(p) > 4096 || paths[p] != "" {
			return d, fmt.Errorf("INVALID_SWID_LOCAL_PATH")
		}
		for _, c := range tag.Document.Components {
			if refs[c.SourceRef] {
				return d, fmt.Errorf("DUPLICATE_SWID_TAG_ID")
			}
			refs[c.SourceRef] = true
			paths[p] = c.SourceRef
			c.Path = p
			if mapped, ok := mappings[c.SourceRef]; ok {
				if _, _, _, _, ok = PackageIdentity(mapped); !ok {
					return d, fmt.Errorf("INVALID_SWID_IDENTITY_MAPPING")
				}
				if c.PURL != "" && c.PURL != mapped {
					return d, fmt.Errorf("SWID_IDENTITY_MAPPING_CONFLICT")
				}
				c.PURL = mapped
				c.References = append(c.References, Reference{"operator-identity-mapping", mapped})
			}
			d.Components = append(d.Components, c)
		}
		for _, x := range tag.Document.Diagnostics {
			if x.Code != "DANGLING_RELATION" && x.Code != "IDENTITY_UNRESOLVED" && x.Code != "MISSING_VERSION" {
				d.Diagnostics = append(d.Diagnostics, x)
			}
		}
		digests = append(digests, p+":"+tag.Document.InputSHA256)
	}
	for ref := range mappings {
		if !refs[ref] {
			return d, fmt.Errorf("SWID_MAPPING_TAG_NOT_IN_COLLECTION")
		}
	}
	for _, c := range d.Components {
		for _, r := range c.References {
			if strings.HasPrefix(r.Value, "swid:") {
				d.Dependencies = append(d.Dependencies, Dependency{c.SourceRef, strings.TrimPrefix(r.Value, "swid:"), r.Type})
				continue
			}
			u, err := url.Parse(r.Value)
			if err != nil || u.IsAbs() || u.Host != "" || u.Path == "" {
				continue
			}
			target := paths[path.Clean(path.Join(path.Dir(c.Path), u.Path))]
			if target != "" {
				d.Dependencies = append(d.Dependencies, Dependency{c.SourceRef, target, r.Type})
			}
		}
	}
	sort.Strings(digests)
	d.InputSHA256 = Digest(struct {
		Tags     []string
		Mappings map[string]string
	}{digests, mappings})
	d.DocumentID = "swid-collection:" + d.InputSHA256
	err := Finalize(&d)
	return d, err
}
