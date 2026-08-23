package app

import (
	"crypto/sha256"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseContentRange(t *testing.T) {
	t.Parallel()
	value, err := parseContentRange("bytes 8388608-8388617/8388618")
	if err != nil {
		t.Fatalf("parse valid range: %v", err)
	}
	if value.Start != 8388608 || value.End != 8388617 || value.Total != 8388618 {
		t.Fatalf("unexpected range: %#v", value)
	}
	for _, input := range []string{"", "items 0-1/2", "bytes */2", "bytes 2-1/3", "bytes 0-2/2"} {
		if _, err := parseContentRange(input); err == nil {
			t.Fatalf("expected %q to be rejected", input)
		}
	}
}

func TestValidateUploadPartsRequiresExactSequence(t *testing.T) {
	t.Parallel()
	parts := []storedUploadPart{
		{Number: 1, Offset: 0, Size: uploadPartSize},
		{Number: 2, Offset: uploadPartSize, Size: 7},
	}
	if err := validateUploadParts(parts, uploadPartSize+7); err != nil {
		t.Fatalf("validate exact sequence: %v", err)
	}
	parts[1].Offset++
	if err := validateUploadParts(parts, uploadPartSize+7); err == nil {
		t.Fatal("expected a gap to be rejected")
	}
}

func TestVerifyUploadPartDetectsTampering(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "part")
	body := []byte("immutable upload part")
	if err := os.WriteFile(path, body, 0o400); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	part := storedUploadPart{Size: int64(len(body)), SHA256: digest}
	if err := verifyUploadPart(path, part); err != nil {
		t.Fatalf("verify valid part: %v", err)
	}
	part.SHA256[0] ^= 0xff
	if err := verifyUploadPart(path, part); err == nil {
		t.Fatal("expected digest mismatch")
	}
}

func TestCanonicalUUIDRejectsPathMaterial(t *testing.T) {
	t.Parallel()
	if !canonicalUUID("11111111-1111-4111-8111-111111111111") {
		t.Fatal("canonical UUID rejected")
	}
	for _, value := range []string{"../upload", "11111111-1111-4111-8111-11111111111g", "11111111111141118111111111111111"} {
		if canonicalUUID(value) {
			t.Fatalf("unsafe identifier accepted: %q", value)
		}
	}
}

func TestUploadAPIStatusExposesDurableAssembly(t *testing.T) {
	t.Parallel()
	record := uploadRecord{
		Status:            "open",
		ExpiresAt:         time.Now().UTC().Add(time.Hour),
		ReceivedSize:      1,
		AssemblyStartedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
		AssemblyToken:     sql.NullString{String: "token", Valid: true},
	}
	if status := uploadAPIStatus(record); status != "assembling" {
		t.Fatalf("status = %q, want assembling", status)
	}
	record.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	if status := uploadAPIStatus(record); status != "assembling" {
		t.Fatalf("expired active assembly status = %q, want assembling", status)
	}
	record.ExpiresAt = time.Now().UTC().Add(time.Hour)
	record.AssemblyStartedAt.Time = time.Now().UTC().Add(-uploadAssemblyStale - time.Minute)
	if status := uploadAPIStatus(record); status != "uploading" {
		t.Fatalf("stale assembly status = %q, want uploading", status)
	}
}

func TestReplaceUploadPartRepairsExistingFile(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	destination := filepath.Join(directory, "part")
	temporary := filepath.Join(directory, "replacement")
	if err := os.WriteFile(destination, []byte("corrupt"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(temporary, []byte("repaired"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceUploadPart(temporary, destination); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "repaired" {
		t.Fatalf("replacement body = %q", body)
	}
}
