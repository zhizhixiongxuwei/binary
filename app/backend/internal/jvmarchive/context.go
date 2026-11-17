package jvmarchive

// Source analysis sidecars contain type signatures and selected text resources,
// never executable code. They are published with the immutable source manifest.
import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const TypeIndexPath = ".binaryscan/java-types.json"

func StageStandaloneContext(ctx context.Context, original, output, inputSHA string) error {
	p := Prepared{Scope: Scope{InputSHA256: inputSHA, ClasspathOrder: "standalone"}, Targets: []Unit{{Module: Module{EntryPath: "root", Role: "application"}, Path: original}}}
	return p.StageContext(ctx, original, output)
}

func StageClassContext(original, output, inputSHA string) error {
	body, err := os.ReadFile(original)
	if err != nil {
		return err
	}
	if len(body) > 4<<20 || !strings.EqualFold(ContextDigest(body), inputSHA) {
		return fmt.Errorf("class context does not match original input")
	}
	definition, err := readTypeMetadata(body)
	if err != nil {
		return err
	}
	definition.Module = "root"
	definition.SHA256 = inputSHA
	index := TypeIndex{Version: "java-type-index-v1", InputSHA256: inputSHA, ClasspathOrder: "standalone-class", Types: []TypeMetadata{definition}, Diagnostics: []string{}}
	encoded, err := json.Marshal(index)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(output, ".binaryscan"), 0700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(output, filepath.FromSlash(TypeIndexPath)), encoded, 0600)
}

type TypeMember struct {
	Name        string   `json:"name"`
	Descriptor  string   `json:"descriptor"`
	Signature   string   `json:"signature,omitempty"`
	Access      uint16   `json:"access"`
	Annotations []string `json:"annotations,omitempty"`
}
type TypeMetadata struct {
	Name         string       `json:"name"`
	Parent       string       `json:"parent"`
	Interfaces   []string     `json:"interfaces"`
	References   []string     `json:"references,omitempty"`
	Signature    string       `json:"signature,omitempty"`
	Access       uint16       `json:"access"`
	Fields       []TypeMember `json:"fields,omitempty"`
	Methods      []TypeMember `json:"methods,omitempty"`
	Annotations  []string     `json:"annotations,omitempty"`
	Module       string       `json:"module"`
	SourcePrefix string       `json:"sourcePrefix,omitempty"`
	SHA256       string       `json:"sha256"`
}
type TypeIndex struct {
	Version                string         `json:"version"`
	InputSHA256            string         `json:"inputSha256"`
	ClasspathOrder         string         `json:"classpathOrder"`
	Types                  []TypeMetadata `json:"types"`
	Diagnostics            []string       `json:"diagnostics"`
	MapperRegistryComplete bool           `json:"mapperRegistryComplete"`
}

// StageContext reads normalized effective class files. The dependency closure is
// rooted in application signatures; it does not decompile third-party bodies.
func (p *Prepared) StageContext(ctx context.Context, original, output string) error {
	index := TypeIndex{Version: "java-type-index-v1", InputSHA256: p.Scope.InputSHA256, ClasspathOrder: p.Scope.ClasspathOrder, Types: []TypeMetadata{}, Diagnostics: []string{}, MapperRegistryComplete: true}
	byName := map[string][]TypeMetadata{}
	wanted := map[string]bool{}
	refs := regexp.MustCompile(`L([^;<:]+)`)
	addRefs := func(t TypeMetadata) {
		for _, value := range append([]string{t.Parent, t.Signature}, t.Interfaces...) {
			if value != "" {
				wanted[value] = true
			}
			for _, m := range refs.FindAllStringSubmatch(value, -1) {
				wanted[strings.ReplaceAll(m[1], "/", ".")] = true
			}
		}
	}
	units := append(append([]Unit{}, p.Targets...), p.Dependencies...)
	totalBytes := int64(0)
	count := 0
	for _, unit := range units {
		if err := ctx.Err(); err != nil {
			return err
		}
		jar, err := zip.OpenReader(unit.Path)
		if err != nil {
			return err
		}
		for _, entry := range jar.File {
			if !strings.HasSuffix(entry.Name, ".class") {
				continue
			}
			count++
			if count > MaxEntries || entry.UncompressedSize64 > 4<<20 {
				jar.Close()
				return fmt.Errorf("Java type metadata class limit exceeded")
			}
			stream, err := entry.Open()
			if err != nil {
				index.MapperRegistryComplete = false
				jar.Close()
				return err
			}
			body, err := io.ReadAll(io.LimitReader(stream, (4<<20)+1))
			stream.Close()
			totalBytes += int64(len(body))
			if err != nil || totalBytes > MaxExpandedBytes {
				jar.Close()
				return fmt.Errorf("Java type metadata byte limit exceeded")
			}
			t, err := readTypeMetadata(body)
			if err != nil {
				index.MapperRegistryComplete = false
				if len(index.Diagnostics) < 100 {
					index.Diagnostics = append(index.Diagnostics, "Unreadable class metadata: "+unit.EntryPath+"!/"+entry.Name)
				}
				continue
			}
			t.Module = unit.EntryPath
			t.SourcePrefix = unit.SourcePrefix
			t.SHA256 = fmt.Sprintf("%x", sha256.Sum256(body))
			byName[t.Name] = append(byName[t.Name], t)
			if unit.Role == "application" || unit.SourcePrefix != "" {
				wanted[t.Name] = true
				for _, reference := range t.References {
					wanted[reference] = true
				}
				addRefs(t)
				for _, m := range append(append([]TypeMember{}, t.Methods...), t.Fields...) {
					for _, value := range []string{m.Descriptor, m.Signature} {
						for _, r := range refs.FindAllStringSubmatch(value, -1) {
							wanted[strings.ReplaceAll(r[1], "/", ".")] = true
						}
					}
				}
			}
		}
		jar.Close()
	}
	mapperTypes := map[string]bool{"io.github.linpeilie.BaseMapper": true}
	for round := 0; round < 64; round++ {
		changed := false
		for name, definitions := range byName {
			if mapperTypes[name] {
				continue
			}
			for _, definition := range definitions {
				parents := append([]string{definition.Parent}, definition.Interfaces...)
				for _, parent := range parents {
					if mapperTypes[parent] {
						mapperTypes[name] = true
						wanted[name] = true
						changed = true
						break
					}
				}
			}
		}
		if !changed {
			break
		}
		if round == 63 {
			index.MapperRegistryComplete = false
		}
	}
	// Only ancestors and their signatures are added recursively. Arbitrary method
	// return graphs would pull an entire framework into a supposedly small index.
	for round := 0; round < 32; round++ {
		changed := false
		names := make([]string, 0, len(wanted))
		for n := range wanted {
			names = append(names, n)
		}
		for _, name := range names {
			for _, t := range byName[name] {
				before := len(wanted)
				addRefs(t)
				changed = changed || before != len(wanted)
			}
		}
		if !changed {
			break
		}
	}
	names := make([]string, 0, len(wanted))
	for n := range wanted {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, t := range byName[name] {
			if len(index.Types) >= 6000 {
				index.MapperRegistryComplete = false
				index.Diagnostics = append(index.Diagnostics, "Java dependency type index truncated at 6000 definitions")
				break
			}
			index.Types = append(index.Types, t)
		}
		if len(index.Types) >= 6000 {
			break
		}
	}
	body, err := json.Marshal(index)
	if err != nil {
		return err
	}
	if len(body) > 24<<20 {
		return fmt.Errorf("Java type index exceeds 24 MiB")
	}
	if err := os.MkdirAll(filepath.Join(output, ".binaryscan"), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, filepath.FromSlash(TypeIndexPath)), body, 0600); err != nil {
		return err
	}
	return p.stageResources(ctx, original, output)
}

func ResourcePath(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".properties") || strings.HasSuffix(lower, ".xml") || strings.HasSuffix(lower, ".jsp") || strings.HasSuffix(lower, ".jspx") || strings.HasSuffix(lower, ".json") || strings.HasPrefix(lower, "meta-inf/services/") || lower == "meta-inf/manifest.mf" || strings.HasSuffix(lower, ".imports") || strings.HasSuffix(lower, "spring.factories")
}
func (p *Prepared) stageResources(ctx context.Context, original, output string) error {
	outer, err := zip.OpenReader(original)
	if err != nil {
		return err
	}
	defer outer.Close()
	modules := map[string]Module{}
	for _, m := range p.Scope.Modules {
		if m.SourcePrefix != "" && strings.HasSuffix(m.EntryPath, ".jar") {
			modules[m.EntryPath] = m
		}
	}
	count := 0
	var size int64
	copyEntries := func(entries []*zip.File, prefix, strip string) error {
		for _, e := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := e.Name
			if strip != "" {
				if !strings.HasPrefix(name, strip) {
					continue
				}
				name = strings.TrimPrefix(name, strip)
			}
			if !ResourcePath(name) || e.FileInfo().IsDir() {
				continue
			}
			if !safeContextPath(name) || strings.HasPrefix(name, ".binaryscan/") {
				return fmt.Errorf("unsafe Java resource path")
			}
			if count >= 2000 || e.UncompressedSize64 > 1<<20 {
				return fmt.Errorf("Java resource limit exceeded")
			}
			r, err := e.Open()
			if err != nil {
				return err
			}
			body, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
			r.Close()
			size += int64(len(body))
			if err != nil || len(body) > 1<<20 || size > 16<<20 {
				return fmt.Errorf("Java resource byte limit exceeded")
			}
			if !utf8.Valid(body) {
				continue
			}
			destination := filepath.Join(output, "resources", filepath.FromSlash(prefix), filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
				return err
			}
			if _, err := os.Lstat(destination); err == nil {
				return fmt.Errorf("duplicate Java resource path")
			}
			if err := os.WriteFile(destination, body, 0600); err != nil {
				return err
			}
			count++
		}
		return nil
	}
	strip := "BOOT-INF/classes/"
	if p.Scope.ClasspathOrder == "standalone" {
		strip = ""
	}
	if err := copyEntries(outer.File, "application", strip); err != nil {
		return err
	}
	for _, e := range outer.File {
		m, ok := modules[e.Name]
		if !ok {
			continue
		}
		r, err := e.Open()
		if err != nil {
			return err
		}
		body, err := io.ReadAll(io.LimitReader(r, (64<<20)+1))
		r.Close()
		if err != nil || len(body) > 64<<20 {
			return fmt.Errorf("nested Java resources exceed limit")
		}
		jar, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			return err
		}
		if err := copyEntries(jar.File, m.SourcePrefix, ""); err != nil {
			return err
		}
	}
	return nil
}
func safeContextPath(name string) bool {
	return name != "" && !strings.ContainsAny(name, "\\:\x00") && !strings.HasPrefix(name, "/") && path.Clean(name) == name && !strings.HasPrefix(name, "../") && name != ".."
}

// Minimal JVMS header reader: Code and bootstrap payload attributes are skipped.
type classCursor struct {
	b       []byte
	at      int
	cp      []string
	classes []uint16
}

func (c *classCursor) take(n int) ([]byte, error) {
	if n < 0 || n > len(c.b)-c.at {
		return nil, io.ErrUnexpectedEOF
	}
	v := c.b[c.at : c.at+n]
	c.at += n
	return v, nil
}
func (c *classCursor) u2() (uint16, error) {
	b, e := c.take(2)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint16(b), nil
}
func (c *classCursor) text(i uint16) string {
	if int(i) >= len(c.cp) {
		return ""
	}
	return c.cp[i]
}
func (c *classCursor) name(i uint16) string {
	if int(i) >= len(c.classes) {
		return ""
	}
	return strings.ReplaceAll(c.text(c.classes[i]), "/", ".")
}
func readTypeMetadata(body []byte) (TypeMetadata, error) {
	var t TypeMetadata
	c := classCursor{b: body}
	head, e := c.take(8)
	if e != nil || !bytes.Equal(head[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) {
		return t, fmt.Errorf("invalid class header")
	}
	n, e := c.u2()
	if e != nil {
		return t, e
	}
	c.cp = make([]string, n)
	c.classes = make([]uint16, n)
	for i := 1; i < int(n); i++ {
		b, e := c.take(1)
		if e != nil {
			return t, e
		}
		switch b[0] {
		case 1:
			l, e := c.u2()
			if e != nil {
				return t, e
			}
			v, e := c.take(int(l))
			if e != nil {
				return t, e
			}
			c.cp[i] = string(v)
		case 7:
			v, e := c.u2()
			if e != nil {
				return t, e
			}
			c.classes[i] = v
		case 3, 4, 9, 10, 11, 12, 17, 18:
			_, e = c.take(4)
		case 5, 6:
			_, e = c.take(8)
			i++
		case 8, 16, 19, 20:
			_, e = c.take(2)
		case 15:
			_, e = c.take(3)
		default:
			return t, fmt.Errorf("unknown constant pool tag")
		}
		if e != nil {
			return t, e
		}
	}
	if t.Access, e = c.u2(); e != nil {
		return t, e
	}
	for i, nameIndex := range c.classes {
		if nameIndex != 0 {
			name := c.name(uint16(i))
			if name != "" && !strings.HasPrefix(name, "[") {
				t.References = append(t.References, name)
			}
		}
	}
	sort.Strings(t.References)
	self, e := c.u2()
	if e != nil {
		return t, e
	}
	super, e := c.u2()
	if e != nil {
		return t, e
	}
	t.Name = c.name(self)
	t.Parent = c.name(super)
	n, e = c.u2()
	if e != nil {
		return t, e
	}
	t.Interfaces = []string{}
	for i := 0; i < int(n); i++ {
		v, e := c.u2()
		if e != nil {
			return t, e
		}
		t.Interfaces = append(t.Interfaces, c.name(v))
	}
	members := func() ([]TypeMember, error) {
		n, e := c.u2()
		if e != nil {
			return nil, e
		}
		out := []TypeMember{}
		for i := 0; i < int(n); i++ {
			a, e := c.u2()
			if e != nil {
				return nil, e
			}
			name, e := c.u2()
			if e != nil {
				return nil, e
			}
			desc, e := c.u2()
			if e != nil {
				return nil, e
			}
			sig, annotations, e := c.attributes()
			if e != nil {
				return nil, e
			}
			if a&0x0005 != 0 {
				out = append(out, TypeMember{Name: c.text(name), Descriptor: c.text(desc), Signature: sig, Access: a, Annotations: annotations})
			}
		}
		return out, nil
	}
	if t.Fields, e = members(); e != nil {
		return t, e
	}
	if t.Methods, e = members(); e != nil {
		return t, e
	}
	t.Signature, t.Annotations, e = c.attributes()
	return t, e
}
func (c *classCursor) attributes() (string, []string, error) {
	n, e := c.u2()
	if e != nil {
		return "", nil, e
	}
	sig := ""
	annotations := []string{}
	for i := 0; i < int(n); i++ {
		name, e := c.u2()
		if e != nil {
			return "", nil, e
		}
		raw, e := c.take(4)
		if e != nil {
			return "", nil, e
		}
		size := binary.BigEndian.Uint32(raw)
		if uint64(size) > uint64(len(c.b)-c.at) {
			return "", nil, io.ErrUnexpectedEOF
		}
		value, e := c.take(int(size))
		if e != nil {
			return "", nil, e
		}
		switch c.text(name) {
		case "Signature":
			if len(value) == 2 {
				sig = c.text(binary.BigEndian.Uint16(value))
			}
		case "RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations":
			a := classCursor{b: value, cp: c.cp}
			count, e := a.u2()
			if e != nil {
				return "", nil, e
			}
			for j := 0; j < int(count); j++ {
				v, e := a.annotation(0)
				if e != nil {
					return "", nil, e
				}
				annotations = append(annotations, v)
			}
		}
	}
	return sig, annotations, nil
}
func (c *classCursor) annotation(depth int) (string, error) {
	if depth > 32 {
		return "", fmt.Errorf("annotation nesting limit")
	}
	name, e := c.u2()
	if e != nil {
		return "", e
	}
	n, e := c.u2()
	if e != nil {
		return "", e
	}
	for i := 0; i < int(n); i++ {
		if _, e = c.u2(); e != nil {
			return "", e
		}
		if e = c.element(depth + 1); e != nil {
			return "", e
		}
	}
	return strings.TrimSuffix(strings.TrimPrefix(strings.ReplaceAll(c.text(name), "/", "."), "L"), ";"), nil
}
func (c *classCursor) element(depth int) error {
	if depth > 32 {
		return fmt.Errorf("annotation nesting limit")
	}
	tag, e := c.take(1)
	if e != nil {
		return e
	}
	switch tag[0] {
	case '@':
		_, e = c.annotation(depth + 1)
		return e
	case '[':
		n, e := c.u2()
		if e != nil {
			return e
		}
		for i := 0; i < int(n); i++ {
			if e := c.element(depth + 1); e != nil {
				return e
			}
		}
		return nil
	case 'e':
		_, e = c.take(4)
		return e
	default:
		_, e = c.take(2)
		return e
	}
}

// Stable identity used by consumers to compare definitions without depending on
// archive traversal order. Hashes never certify a dependency's trustworthiness.
func ContextDigest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
