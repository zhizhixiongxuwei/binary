package app

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"binaryscan.local/backend/internal/storage"

	"github.com/gin-gonic/gin"
)

func TestCreateRejectsCategoryMismatchBeforeDatabaseWrites(t *testing.T) {
	gin.SetMode(gin.TestMode)
	storageRoot := t.TempDir()
	blobs, err := storage.NewBlobStore(filepath.Join(storageRoot, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	// A nil database makes this test fail immediately if validation reaches any
	// Task, Run, or Upload persistence path.
	service := &taskService{blobs: blobs, uploadMaxBytes: 1 << 20, storageRoot: storageRoot}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("input_category", "container"); err != nil {
		t.Fatal(err)
	}
	part, err := writer.CreateFormFile("file", "sample.elf")
	if err != nil {
		t.Fatal(err)
	}
	elf := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, make([]byte, 56)...)
	if _, err := part.Write(elf); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodPost, "/api/v1/tasks", &body)
	context.Request.Header.Set("Content-Type", writer.FormDataContentType())
	service.create(context)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusUnprocessableEntity, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"error":"input_category_mismatch"`) ||
		!strings.Contains(recorder.Body.String(), `"detectedFormat":"elf64"`) {
		t.Fatalf("unexpected mismatch response: %s", recorder.Body.String())
	}
}
