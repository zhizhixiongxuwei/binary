package jvmarchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func metadataClass(name, descriptor string) []byte {
	var b bytes.Buffer
	u2 := func(v uint16) { _ = binary.Write(&b, binary.BigEndian, v) }
	u4 := func(v uint32) { _ = binary.Write(&b, binary.BigEndian, v) }
	b.Write([]byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65})
	u2(12)
	text := func(s string) { b.WriteByte(1); u2(uint16(len(s))); b.WriteString(s) }
	text(name)
	b.WriteByte(7)
	u2(1)
	text("java/lang/Object")
	b.WriteByte(7)
	u2(3)
	text("find")
	text(descriptor)
	text("Signature")
	text("<T:Ljava/lang/Object;>Ljava/lang/Object;")
	text("RuntimeVisibleAnnotations")
	text("Lorg/jetbrains/annotations/Nullable;")
	text("fixture-body-data-that-must-not-be-exported")
	u2(0x401)
	u2(2)
	u2(4)
	u2(0)
	u2(0)
	u2(1)
	u2(0x401)
	u2(5)
	u2(6)
	u2(1)
	u2(9)
	u4(6)
	u2(1)
	u2(10)
	u2(0)
	u2(1)
	u2(7)
	u4(2)
	u2(8)
	return b.Bytes()
}
func TestTypeHeaderPreservesSignaturesAndAnnotationsWithoutExportingConstants(t *testing.T) {
	body := metadataClass("example/Parent", "(Lvendor/Support;)Ljava/lang/String;")
	meta, err := readTypeMetadata(body)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Name != "example.Parent" || meta.Signature != "<T:Ljava/lang/Object;>Ljava/lang/Object;" || len(meta.Methods) != 1 || len(meta.Methods[0].Annotations) != 1 || meta.Methods[0].Annotations[0] != "org.jetbrains.annotations.Nullable" {
		t.Fatalf("metadata lost: %+v", meta)
	}
	encoded, _ := json.Marshal(meta)
	if bytes.Contains(encoded, []byte("fixture-body-data")) {
		t.Fatal("non-metadata constant was exported")
	}
	for _, cut := range []int{0, 3, 8, len(body) - 1} {
		if _, err := readTypeMetadata(body[:cut]); err == nil {
			t.Fatalf("accepted truncated header %d", cut)
		}
	}
}
func TestStageContextPinsTypesAndOnlySelectedApplicationResources(t *testing.T) {
	original := jarBytes(t, map[string][]byte{
		"META-INF/maven/example/app/pom.properties": []byte("groupId=example\n"),
		"BOOT-INF/classes/":                         {},
		"BOOT-INF/classes/example/Main.class":       metadataClass("example/Main", "(Lvendor/Support;)Ljava/lang/String;"),
		"BOOT-INF/classes/application.yml":          []byte("jwt:\n  secret: fixture\n"),
		"BOOT-INF/lib/own.jar":                      jarBytes(t, map[string][]byte{"META-INF/maven/example/own/pom.properties": []byte("groupId=example\n"), "example/Own.class": metadataClass("example/Own", "()V"), "mapper/Own.xml": []byte("<mapper namespace=\"Own\"/>")}),
		"BOOT-INF/lib/vendor.jar":                   jarBytes(t, map[string][]byte{"META-INF/maven/vendor/dep/pom.properties": []byte("groupId=vendor\n"), "vendor/Support.class": metadataClass("vendor/Support", "()V"), "application.yml": []byte("third-party-resource-must-not-be-published")}),
	})
	root := t.TempDir()
	file := filepath.Join(root, "original.jar")
	if err := os.WriteFile(file, original, 0600); err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(original))
	p, err := Prepare(context.Background(), file, filepath.Join(root, "prepared"), Options{ExpectedSHA256: hash})
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "output")
	if err := p.StageContext(context.Background(), file, output); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(output, filepath.FromSlash(TypeIndexPath)))
	if err != nil {
		t.Fatal(err)
	}
	var index TypeIndex
	if err := json.Unmarshal(body, &index); err != nil {
		t.Fatal(err)
	}
	if index.InputSHA256 != hash || len(index.Types) != 3 {
		t.Fatalf("wrong type provenance: %+v", index)
	}
	if _, err := os.Stat(filepath.Join(output, "resources/application/application.yml")); err != nil {
		t.Fatal(err)
	}
	own := false
	err = filepath.WalkDir(filepath.Join(output, "resources"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if bytes.Contains(b, []byte("third-party-resource")) {
			t.Fatal("dependency resource was treated as application configuration")
		}
		own = own || strings.HasSuffix(path, "Own.xml")
		return err
	})
	if err != nil || !own {
		t.Fatalf("resource missing: %v", err)
	}
}

func TestStandaloneClassContextAcceptsUppercaseHexIdentity(t *testing.T) {
	root := t.TempDir()
	body := metadataClass("example/Probe", "()V")
	file := filepath.Join(root, "Probe.class")
	if err := os.WriteFile(file, body, 0600); err != nil {
		t.Fatal(err)
	}
	digest := strings.ToUpper(fmt.Sprintf("%x", sha256.Sum256(body)))
	if err := StageClassContext(file, filepath.Join(root, "output"), digest); err != nil {
		t.Fatal(err)
	}
}
