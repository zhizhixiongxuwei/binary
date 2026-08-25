package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"binaryscan.local/backend/internal/filetype"
	"binaryscan.local/backend/internal/identity"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/storage"

	"github.com/gin-gonic/gin"
)

const (
	uploadPartSize      int64 = 8 << 20
	uploadSessionTTL          = 24 * time.Hour
	uploadAssemblyStale       = 2 * time.Hour
	maxUploadJSONBytes  int64 = 16 << 10
)

type createUploadRequest struct {
	Filename    string `json:"filename"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
}

type createUploadTaskRequest struct {
	AnalysisMode string `json:"analysis_mode"`
}

type uploadValidationMessage struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type uploadRecord struct {
	ID                string
	CreatedBy         uint64
	OriginalName      string
	ContentType       string
	InputCategory     string
	DeclaredSize      int64
	ReceivedSize      int64
	Status            string
	BlobID            sql.NullString
	ValidationStatus  string
	DetectedCategory  sql.NullString
	DetectedFormat    sql.NullString
	ValidationError   []byte
	ExpiresAt         time.Time
	AssemblyStartedAt sql.NullTime
	AssemblyToken     sql.NullString
	CreatedAt         time.Time
	CompletedAt       sql.NullTime
	IdempotencyKey    sql.NullString
}

type uploadSessionResponse struct {
	ID               string                   `json:"id"`
	Filename         string                   `json:"filename"`
	ContentType      string                   `json:"content_type"`
	PartSize         int64                    `json:"part_size"`
	SHA256           string                   `json:"sha256,omitempty"`
	SizeBytes        *int64                   `json:"size_bytes,omitempty"`
	Status           string                   `json:"status"`
	UploadedParts    []uint32                 `json:"uploaded_parts"`
	ExpiresAt        time.Time                `json:"expires_at"`
	InputCategory    string                   `json:"input_category,omitempty"`
	ValidationStatus string                   `json:"validation_status"`
	DetectedCategory string                   `json:"detected_category,omitempty"`
	DetectedFormat   string                   `json:"detected_format,omitempty"`
	ValidationError  *uploadValidationMessage `json:"validation_error,omitempty"`
	ArchiveImportID  string                   `json:"archive_import_id,omitempty"`
	TaskID           string                   `json:"task_id,omitempty"`
	AnalysisOptions  []uploadAnalysisOption   `json:"analysis_options,omitempty"`
	Tasks            []uploadTaskResponse     `json:"tasks,omitempty"`
}

type uploadAnalysisOption struct {
	Mode      string `json:"mode"`
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
}

type uploadTaskResponse struct {
	TaskID          string `json:"task_id"`
	AnalysisMode    string `json:"analysis_mode"`
	Status          string `json:"status"`
	Supported       bool   `json:"supported"`
	ArchiveImportID string `json:"archive_import_id,omitempty"`
}

type contentRange struct {
	Start int64
	End   int64
	Total int64
}

type storedUploadPart struct {
	Number uint32
	Offset int64
	Size   int64
	SHA256 [sha256.Size]byte
}

type uploadValidationFailure struct {
	code     string
	message  string
	detected filetype.Result
}

func (e *uploadValidationFailure) Error() string { return e.message }

func (s *taskService) createUpload(c *gin.Context) {
	idempotencyKey := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if !validIdempotencyKey(idempotencyKey) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idempotency_key_required"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUploadJSONBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var request createUploadRequest
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_upload_request"})
		return
	}
	name, err := cleanUploadName(request.Filename)
	if err != nil || request.Size <= 0 || request.Size > s.uploadMaxBytes {
		status := http.StatusBadRequest
		code := "invalid_upload_request"
		if request.Size > s.uploadMaxBytes {
			status, code = http.StatusRequestEntityTooLarge, "upload_too_large"
		}
		c.JSON(status, gin.H{"error": code})
		return
	}
	contentType := strings.TrimSpace(request.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if !validUploadText(contentType, 128) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_content_type"})
		return
	}
	user := mustCurrentUser(c)
	if existing, found, err := s.loadUploadByIdempotency(c, user.ID, idempotencyKey); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_creation_failed"})
		return
	} else if found {
		if existing.OriginalName != name || existing.DeclaredSize != request.Size ||
			existing.ContentType != contentType {
			c.JSON(http.StatusConflict, gin.H{"error": "upload_conflict"})
			return
		}
		s.writeUploadSession(c, existing, http.StatusOK)
		return
	}

	uploadID, err := identity.UUID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_creation_failed"})
		return
	}
	expiresAt := time.Now().UTC().Add(uploadSessionTTL)
	_, err = s.db.ExecContext(c, `INSERT INTO uploads
		(id, created_by, original_name, content_type, input_category, declared_size, received_size,
			 status, idempotency_key, validation_status, expires_at)
		VALUES (?, ?, ?, ?, NULL, ?, 0, 'open', ?, 'pending', ?)`,
		uploadID, user.ID, name, contentType, request.Size, idempotencyKey, expiresAt)
	if err != nil {
		// A concurrent retry may have won the unique idempotency-key insert.
		if existing, found, queryErr := s.loadUploadByIdempotency(c, user.ID, idempotencyKey); queryErr == nil && found {
			if existing.OriginalName == name && existing.DeclaredSize == request.Size &&
				existing.ContentType == contentType {
				s.writeUploadSession(c, existing, http.StatusOK)
				return
			}
			c.JSON(http.StatusConflict, gin.H{"error": "upload_conflict"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_creation_failed"})
		return
	}
	record := uploadRecord{ID: uploadID, CreatedBy: user.ID, OriginalName: name, ContentType: contentType,
		DeclaredSize: request.Size, Status: "open",
		ValidationStatus: "pending", ExpiresAt: expiresAt, CreatedAt: time.Now().UTC()}
	s.writeUploadSession(c, record, http.StatusCreated)
}

func (s *taskService) listUploads(c *gin.Context) {
	limit := 50
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 && value <= 100 {
			limit = value
		}
	}
	pendingAnalysis := false
	if raw := strings.TrimSpace(c.Query("pending_analysis")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_pending_analysis"})
			return
		}
		pendingAnalysis = value
	}
	query := `SELECT u.id FROM uploads u
		WHERE u.created_by = ? AND u.status <> 'aborted'`
	if pendingAnalysis {
		query += ` AND u.status = 'complete' AND u.validation_status = 'valid'
			AND NOT EXISTS (SELECT 1 FROM tasks t
				WHERE t.upload_id = u.id AND t.deleted_at IS NULL)`
	}
	query += ` ORDER BY u.created_at DESC LIMIT ?`
	rows, err := s.db.QueryContext(c, query, mustCurrentUser(c).ID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_query_failed"})
		return
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_query_failed"})
			return
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_query_failed"})
		return
	}
	items := make([]uploadSessionResponse, 0, len(ids))
	for _, id := range ids {
		record, found, err := s.loadOwnedUpload(c, id, mustCurrentUser(c).ID, false)
		if err != nil || !found {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_query_failed"})
			return
		}
		item, err := s.buildUploadSession(c, record)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_query_failed"})
			return
		}
		items = append(items, item)
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (s *taskService) getUpload(c *gin.Context) {
	record, found, err := s.loadOwnedUpload(c, c.Param("uploadID"), mustCurrentUser(c).ID, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_query_failed"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "upload_not_found"})
		return
	}
	s.writeUploadSession(c, record, http.StatusOK)
}

func (s *taskService) createUploadTask(c *gin.Context) {
	idempotencyKey := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if !validIdempotencyKey(idempotencyKey) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idempotency_key_required"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUploadJSONBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var request createUploadTaskRequest
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_analysis_mode"})
		return
	}
	mode, ok := filetype.ParseAnalysisMode(request.AnalysisMode)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_analysis_mode"})
		return
	}
	record, found, err := s.loadOwnedUpload(c, c.Param("uploadID"), mustCurrentUser(c).ID, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_query_failed"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "upload_not_found"})
		return
	}
	if record.Status != "complete" || record.ValidationStatus != "valid" || !record.BlobID.Valid || !record.DetectedFormat.Valid {
		c.JSON(http.StatusConflict, gin.H{"error": "upload_not_completed"})
		return
	}
	if existing, found, err := s.loadUploadTaskResponse(c, record.ID, mode); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_creation_failed"})
		return
	} else if found {
		c.JSON(http.StatusOK, existing)
		return
	}
	result, err := s.persistUploadAnalysisTask(c, record, mode, idempotencyKey)
	if err != nil {
		// A concurrent request may have won the unique upload/mode insert.
		if existing, found, queryErr := s.loadUploadTaskResponse(c, record.ID, mode); queryErr == nil && found {
			c.JSON(http.StatusOK, existing)
			return
		}
		slog.Error("create upload analysis task failed", "request_id", c.GetString("requestID"),
			"upload_id", record.ID, "analysis_mode", mode, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "task_creation_failed"})
		return
	}
	c.JSON(http.StatusCreated, result)
}

func (s *taskService) putUploadPart(c *gin.Context) {
	partNumber64, err := strconv.ParseUint(c.Param("partNumber"), 10, 32)
	if err != nil || partNumber64 == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_upload_part"})
		return
	}
	partNumber := uint32(partNumber64)
	rangeValue, err := parseContentRange(c.GetHeader("Content-Range"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_content_range"})
		return
	}
	expectedDigest, err := parseSHA256Header(c.GetHeader("X-Chunk-SHA256"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_chunk_sha256"})
		return
	}
	record, found, err := s.loadOwnedUpload(c, c.Param("uploadID"), mustCurrentUser(c).ID, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_query_failed"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "upload_not_found"})
		return
	}
	if record.Status != "open" || uploadAPIStatus(record) == "assembling" {
		c.JSON(http.StatusConflict, gin.H{"error": "upload_invalid_state"})
		return
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		c.JSON(http.StatusGone, gin.H{"error": "upload_expired"})
		return
	}
	if rangeValue.Total != record.DeclaredSize || rangeValue.Start != int64(partNumber-1)*uploadPartSize {
		c.JSON(http.StatusConflict, gin.H{"error": "upload_conflict"})
		return
	}
	expectedEnd := rangeValue.Start + uploadPartSize - 1
	if expectedEnd >= record.DeclaredSize {
		expectedEnd = record.DeclaredSize - 1
	}
	if rangeValue.End != expectedEnd {
		c.JSON(http.StatusConflict, gin.H{"error": "upload_conflict"})
		return
	}
	expectedSize := rangeValue.End - rangeValue.Start + 1
	uploadDirectory, err := s.uploadDirectory(record.ID)
	if err != nil || os.MkdirAll(filepath.Join(uploadDirectory, "parts"), 0o700) != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_storage_failed"})
		return
	}
	temporary, err := os.CreateTemp(filepath.Join(uploadDirectory, "parts"), ".part-*")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_storage_failed"})
		return
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	hasher := sha256.New()
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, expectedSize+1)
	written, copyErr := io.Copy(io.MultiWriter(temporary, hasher), c.Request.Body)
	closeErr := temporary.Close()
	if copyErr != nil || closeErr != nil || written != expectedSize {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_upload_part"})
		return
	}
	if actual := hasher.Sum(nil); !equalDigest(actual, expectedDigest[:]) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "chunk_sha256_mismatch"})
		return
	}

	tx, err := s.db.BeginTx(c, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_storage_failed"})
		return
	}
	defer tx.Rollback()
	var status string
	var expiresAt time.Time
	var assemblyStarted sql.NullTime
	var assemblyToken sql.NullString
	if err := tx.QueryRowContext(c, `SELECT status, expires_at, assembly_started_at, assembly_token FROM uploads
		WHERE id = ? AND created_by = ? FOR UPDATE`, record.ID, record.CreatedBy).Scan(
		&status, &expiresAt, &assemblyStarted, &assemblyToken); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "upload_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_storage_failed"})
		}
		return
	}
	assembling := assemblyToken.Valid &&
		(!assemblyStarted.Valid || assemblyStarted.Time.After(time.Now().UTC().Add(-uploadAssemblyStale)))
	if status != "open" || assembling || time.Now().UTC().After(expiresAt) {
		code, responseStatus := "upload_invalid_state", http.StatusConflict
		if time.Now().UTC().After(expiresAt) {
			code, responseStatus = "upload_expired", http.StatusGone
		}
		c.JSON(responseStatus, gin.H{"error": code})
		return
	}
	var priorOffset, priorSize int64
	var priorDigest []byte
	queryErr := tx.QueryRowContext(c, `SELECT byte_offset, size_bytes, sha256 FROM upload_parts
		WHERE upload_id = ? AND part_number = ?`, record.ID, partNumber).Scan(&priorOffset, &priorSize, &priorDigest)
	if queryErr == nil {
		if priorOffset == rangeValue.Start && priorSize == expectedSize && equalDigest(priorDigest, expectedDigest[:]) {
			destination := uploadPartPath(uploadDirectory, partNumber)
			priorPart := storedUploadPart{Number: partNumber, Offset: priorOffset, Size: priorSize,
				SHA256: expectedDigest}
			if err := verifyUploadPart(destination, priorPart); err != nil {
				if err := replaceUploadPart(temporaryPath, destination); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_storage_failed"})
					return
				}
			}
			if err := tx.Commit(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_storage_failed"})
				return
			}
			c.Status(http.StatusNoContent)
			return
		}
		c.JSON(http.StatusConflict, gin.H{"error": "upload_conflict"})
		return
	}
	if !errors.Is(queryErr, sql.ErrNoRows) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_storage_failed"})
		return
	}
	destination := uploadPartPath(uploadDirectory, partNumber)
	if err := replaceUploadPart(temporaryPath, destination); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_storage_failed"})
		return
	}
	if _, err := tx.ExecContext(c, `INSERT INTO upload_parts
		(upload_id, part_number, byte_offset, size_bytes, sha256) VALUES (?, ?, ?, ?, ?)`,
		record.ID, partNumber, rangeValue.Start, expectedSize, expectedDigest[:]); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_storage_failed"})
		return
	}
	if _, err := tx.ExecContext(c, `UPDATE uploads SET received_size = received_size + ? WHERE id = ?`,
		expectedSize, record.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_storage_failed"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_storage_failed"})
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *taskService) completeUpload(c *gin.Context) {
	record, found, err := s.loadOwnedUpload(c, c.Param("uploadID"), mustCurrentUser(c).ID, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_query_failed"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "upload_not_found"})
		return
	}
	if record.Status == "complete" {
		s.writeUploadSession(c, record, http.StatusOK)
		return
	}
	if record.Status != "open" {
		s.writeUploadStateError(c, record)
		return
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		c.JSON(http.StatusGone, gin.H{"error": "upload_expired"})
		return
	}
	assemblyToken, claimed, err := s.claimUploadAssembly(c, record.ID, record.CreatedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_completion_failed"})
		return
	}
	if !claimed {
		current, found, queryErr := s.loadOwnedUpload(c, record.ID, record.CreatedBy, false)
		if queryErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_query_failed"})
			return
		}
		if found && current.Status == "complete" {
			s.writeUploadSession(c, current, http.StatusOK)
			return
		}
		c.JSON(http.StatusConflict, gin.H{"error": "upload_invalid_state"})
		return
	}
	finalized := false
	defer func() {
		if !finalized {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if releaseErr := s.releaseUploadAssembly(cleanupContext, record.ID, record.CreatedBy, assemblyToken); releaseErr != nil {
				slog.Error("release upload assembly failed", "request_id", c.GetString("requestID"),
					"upload_id", record.ID, "error", releaseErr)
			}
		}
	}()
	uploadDirectory, err := s.uploadDirectory(record.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_storage_failed"})
		return
	}
	if err := os.MkdirAll(uploadDirectory, 0o700); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_storage_failed"})
		return
	}

	parts, err := s.loadUploadParts(c, record.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_query_failed"})
		return
	}
	if err := validateUploadParts(parts, record.DeclaredSize); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "upload_incomplete"})
		return
	}
	for _, part := range parts {
		if err := verifyUploadPart(uploadPartPath(uploadDirectory, part.Number), part); err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "upload_conflict"})
			return
		}
	}
	reader := &uploadPartsReader{directory: uploadDirectory, parts: parts}
	defer reader.Close()
	blob, err := s.blobs.Ingest(reader, s.uploadMaxBytes)
	if err != nil {
		if errors.Is(err, storage.ErrBlobTooLarge) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "upload_too_large"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_storage_failed"})
		}
		return
	}
	if blob.SizeBytes != record.DeclaredSize {
		c.JSON(http.StatusConflict, gin.H{"error": "upload_conflict"})
		return
	}
	blobPath := filepath.Join(s.storageRoot, "blobs", filepath.FromSlash(blob.StorageKey))
	detected, err := filetype.Detect(blobPath, record.OriginalName)
	if err != nil {
		if errors.Is(err, filetype.ErrInvalidInput) {
			// Malformed archive metadata is a terminal input validation failure.
			detected = filetype.Result{Format: "unknown"}
		} else {
			slog.Error("server-side upload detection failed", "request_id", c.GetString("requestID"),
				"upload_id", record.ID, "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_detection_failed"})
			return
		}
	}
	result, validationErr, err := s.finalizeUpload(c, record, blob, detected, assemblyToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_completion_failed"})
		return
	}
	finalized = true
	// The content-addressed blob is now durable. Upload parts are no longer
	// needed and would otherwise duplicate every completed sample on disk.
	if removeErr := os.RemoveAll(uploadDirectory); removeErr != nil {
		slog.Warn("cleanup completed upload parts failed", "request_id", c.GetString("requestID"),
			"upload_id", record.ID, "error", removeErr)
	}
	if validationErr != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": validationErr.code,
			"details": gin.H{"upload_id": record.ID, "detected_category": validationErr.detected.Category,
				"detected_format": validationErr.detected.Format},
		})
		return
	}
	s.writeUploadSession(c, result, http.StatusOK)
}

func (s *taskService) deleteUpload(c *gin.Context) {
	record, found, err := s.loadOwnedUpload(c, c.Param("uploadID"), mustCurrentUser(c).ID, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_deletion_failed"})
		return
	}
	if !found || record.Status == "aborted" {
		c.JSON(http.StatusNotFound, gin.H{"error": "upload_not_found"})
		return
	}
	tx, err := s.db.BeginTx(c, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_deletion_failed"})
		return
	}
	defer tx.Rollback()
	var currentStatus string
	var category sql.NullString
	var assemblyStarted sql.NullTime
	var assemblyToken sql.NullString
	if err := tx.QueryRowContext(c, `SELECT status, input_category, assembly_started_at, assembly_token FROM uploads
		WHERE id = ? AND created_by = ? FOR UPDATE`, record.ID, record.CreatedBy).Scan(
		&currentStatus, &category, &assemblyStarted, &assemblyToken); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "upload_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_deletion_failed"})
		}
		return
	}
	if currentStatus == "open" && assemblyToken.Valid &&
		(!assemblyStarted.Valid || assemblyStarted.Time.After(time.Now().UTC().Add(-uploadAssemblyStale))) {
		c.JSON(http.StatusConflict, gin.H{"error": "upload_invalid_state"})
		return
	}
	if currentStatus == "aborted" {
		c.JSON(http.StatusNotFound, gin.H{"error": "upload_not_found"})
		return
	}
	if currentStatus == "complete" && category.Valid && category.String != "" && category.String != string(filetype.CategoryArchive) {
		c.JSON(http.StatusConflict, gin.H{"error": "upload_invalid_state"})
		return
	}
	if currentStatus == "complete" && (!category.Valid || category.String == "") {
		var liveTasks int
		if err := tx.QueryRowContext(c, `SELECT COUNT(*) FROM tasks
			WHERE upload_id = ? AND deleted_at IS NULL`, record.ID).Scan(&liveTasks); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_deletion_failed"})
			return
		}
		if liveTasks != 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "upload_invalid_state"})
			return
		}
	}
	if currentStatus == "complete" && category.String == string(filetype.CategoryArchive) {
		var taskID string
		if err := tx.QueryRowContext(c, `SELECT id FROM tasks WHERE upload_id = ? AND deleted_at IS NULL FOR UPDATE`,
			record.ID).Scan(&taskID); err != nil && !errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_deletion_failed"})
			return
		}
		if taskID != "" {
			var active int
			if err := tx.QueryRowContext(c, `SELECT COUNT(*) FROM runs WHERE task_id = ? AND kind = 'archive_import'
				AND status IN ('queued', 'running')`, taskID).Scan(&active); err != nil || active != 0 {
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_deletion_failed"})
				} else {
					c.JSON(http.StatusConflict, gin.H{"error": "upload_invalid_state"})
				}
				return
			}
			if _, err := tx.ExecContext(c, `DELETE ae FROM archive_entries ae
				JOIN runs r ON r.id = ae.import_run_id WHERE r.task_id = ? AND ae.created_task_id IS NULL`, taskID); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_deletion_failed"})
				return
			}
			if _, err := tx.ExecContext(c, `UPDATE tasks SET status = 'deleted', deleted_at = UTC_TIMESTAMP(6)
				WHERE id = ?`, taskID); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_deletion_failed"})
				return
			}
		}
	}
	if _, err := tx.ExecContext(c, `UPDATE uploads SET status = 'aborted' WHERE id = ?`, record.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_deletion_failed"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_deletion_failed"})
		return
	}
	if directory, pathErr := s.uploadDirectory(record.ID); pathErr == nil {
		_ = os.RemoveAll(directory)
	}
	c.Status(http.StatusNoContent)
}

func (s *taskService) claimUploadAssembly(
	ctx *gin.Context, uploadID string, userID uint64,
) (string, bool, error) {
	token, err := identity.UUID()
	if err != nil {
		return "", false, err
	}
	staleBefore := time.Now().UTC().Add(-uploadAssemblyStale)
	result, err := s.db.ExecContext(ctx, `UPDATE uploads
		SET assembly_started_at = UTC_TIMESTAMP(6), assembly_token = ?
		WHERE id = ? AND created_by = ? AND status = 'open'
		  AND (assembly_token IS NULL OR assembly_started_at IS NULL OR assembly_started_at < ?)`,
		token, uploadID, userID, staleBefore)
	if err != nil {
		return "", false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return "", false, err
	}
	return token, changed == 1, nil
}

func (s *taskService) releaseUploadAssembly(
	ctx context.Context, uploadID string, userID uint64, token string,
) error {
	_, err := s.db.ExecContext(ctx, `UPDATE uploads
		SET assembly_started_at = NULL, assembly_token = NULL
		WHERE id = ? AND created_by = ? AND status = 'open' AND assembly_token = ?`,
		uploadID, userID, token)
	return err
}

func (s *taskService) persistUploadAnalysisTask(
	ctx *gin.Context, record uploadRecord, mode filetype.AnalysisMode, idempotencyKey string,
) (uploadTaskResponse, error) {
	taskID, err := identity.UUID()
	if err != nil {
		return uploadTaskResponse{}, err
	}
	fileID, err := identity.UUID()
	if err != nil {
		return uploadTaskResponse{}, err
	}
	runID, err := identity.UUID()
	if err != nil {
		return uploadTaskResponse{}, err
	}
	supported := filetype.SupportsAnalysisMode(record.DetectedFormat.String, mode)
	taskStatus := "ready"
	if !supported {
		taskStatus = "partial"
	} else if mode == filetype.AnalysisModeArchive {
		taskStatus = "queued"
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return uploadTaskResponse{}, err
	}
	defer tx.Rollback()
	var status, validationStatus, blobID, detectedFormat string
	var detectedCategory sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT status, validation_status, blob_id, detected_category, detected_format
		FROM uploads WHERE id = ? AND created_by = ? FOR UPDATE`, record.ID, record.CreatedBy).Scan(
		&status, &validationStatus, &blobID, &detectedCategory, &detectedFormat); err != nil {
		return uploadTaskResponse{}, err
	}
	if status != "complete" || validationStatus != "valid" || blobID == "" || detectedFormat == "" {
		return uploadTaskResponse{}, fmt.Errorf("upload is not ready for analysis")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO tasks
		(id, created_by, upload_id, blob_id, display_name, input_category, analysis_mode,
		 detected_category, detected_format, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?)`, taskID, record.CreatedBy, record.ID,
		blobID, record.OriginalName, mode, mode, detectedCategory.String, detectedFormat, taskStatus); err != nil {
		return uploadTaskResponse{}, fmt.Errorf("create analysis task: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO file_nodes
		(id, task_id, blob_id, logical_path, node_kind, detected_format, size_bytes)
		VALUES (?, ?, ?, ?, 'file', ?, ?)`, fileID, taskID, blobID, record.OriginalName,
		detectedFormat, record.ReceivedSize); err != nil {
		return uploadTaskResponse{}, fmt.Errorf("create analysis root file: %w", err)
	}

	response := uploadTaskResponse{TaskID: taskID, AnalysisMode: string(mode), Status: taskStatus, Supported: supported}
	message := "已按" + analysisModeLabel(mode) + "创建任务"
	if mode == filetype.AnalysisModeArchive && supported {
		if _, err := tx.ExecContext(ctx, `INSERT INTO runs
			(id, kind, status, task_id, subject_type, subject_id, created_by, idempotency_key, request)
			VALUES (?, 'archive_import', 'queued', ?, 'file_node', ?, ?, ?,
			 JSON_OBJECT('source', 'analysis-mode', 'analysisMode', ?, 'detectedFormat', ?))`,
			runID, taskID, fileID, record.CreatedBy, idempotencyKey, mode, detectedFormat); err != nil {
			return uploadTaskResponse{}, fmt.Errorf("create archive analysis run: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO jobs (run_id, kind, status, max_attempts)
			VALUES (?, ?, 'queued', 3)`, runID, job.KindArchiveImport); err != nil {
			return uploadTaskResponse{}, fmt.Errorf("enqueue archive analysis: %w", err)
		}
		response.ArchiveImportID = runID
		message += "，归档一层解析已排队"
	} else if !supported {
		kind := job.KindScan
		subjectType, subjectID := "file_node", fileID
		if mode == filetype.AnalysisModeArchive {
			kind = job.KindArchiveImport
			response.ArchiveImportID = runID
		} else if mode == filetype.AnalysisModeContainer {
			kind = job.KindTrivyScan
		}
		reason := unsupportedAnalysisMessage(mode, detectedFormat)
		if _, err := tx.ExecContext(ctx, `INSERT INTO runs
			(id, kind, status, task_id, subject_type, subject_id, created_by, idempotency_key, request,
			 error_code, error_message, completed_at)
			VALUES (?, ?, 'unsupported', ?, ?, ?, ?, ?,
			 JSON_OBJECT('source', 'analysis-mode', 'analysisMode', ?, 'detectedFormat', ?),
			 'analysis_mode_not_applicable', ?, UTC_TIMESTAMP(6))`, runID, kind, taskID, subjectType,
			subjectID, record.CreatedBy, idempotencyKey, mode, detectedFormat, reason); err != nil {
			return uploadTaskResponse{}, fmt.Errorf("record unsupported analysis: %w", err)
		}
		message = "未执行检测：" + reason
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO task_events
		(task_id, event_type, message) VALUES (?, ?, ?)`, taskID,
		map[bool]string{true: "analysis.ready", false: "analysis.unsupported"}[supported], message); err != nil {
		return uploadTaskResponse{}, fmt.Errorf("record analysis task event: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs
		(actor_user_id, action, object_type, object_id, request_id, client_ip, outcome, details)
		VALUES (?, 'task.create', 'task', ?, ?, ?, 'success',
		JSON_OBJECT('uploadId', ?, 'analysisMode', ?, 'detectedFormat', ?, 'supported', ?))`,
		record.CreatedBy, taskID, ctx.GetString("requestID"), ctx.ClientIP(), record.ID, mode,
		detectedFormat, supported); err != nil {
		return uploadTaskResponse{}, fmt.Errorf("audit analysis task creation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return uploadTaskResponse{}, err
	}
	return response, nil
}

func (s *taskService) loadUploadTaskResponse(
	ctx context.Context, uploadID string, mode filetype.AnalysisMode,
) (uploadTaskResponse, bool, error) {
	var response uploadTaskResponse
	var detectedFormat string
	err := s.db.QueryRowContext(ctx, `SELECT id, COALESCE(analysis_mode, input_category, ''), status,
		COALESCE(detected_format, '') FROM tasks
		WHERE upload_id = ? AND COALESCE(analysis_mode, input_category, '') = ? AND deleted_at IS NULL
		ORDER BY created_at LIMIT 1`, uploadID, mode).Scan(
		&response.TaskID, &response.AnalysisMode, &response.Status, &detectedFormat)
	if errors.Is(err, sql.ErrNoRows) {
		return uploadTaskResponse{}, false, nil
	}
	if err != nil {
		return uploadTaskResponse{}, false, err
	}
	response.Supported = filetype.SupportsAnalysisMode(detectedFormat, mode)
	if mode == filetype.AnalysisModeArchive {
		var runID sql.NullString
		if err := s.db.QueryRowContext(ctx, `SELECT id FROM runs WHERE task_id = ? AND kind = 'archive_import'
			ORDER BY created_at DESC LIMIT 1`, response.TaskID).Scan(&runID); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return uploadTaskResponse{}, false, err
		}
		response.ArchiveImportID = runID.String
	}
	return response, true, nil
}

func analysisModeLabel(mode filetype.AnalysisMode) string {
	switch mode {
	case filetype.AnalysisModeBinary:
		return "二进制模式"
	case filetype.AnalysisModeArchive:
		return "压缩包模式"
	case filetype.AnalysisModeContainer:
		return "容器/映像模式"
	default:
		return "所选模式"
	}
}

func unsupportedAnalysisMessage(mode filetype.AnalysisMode, format string) string {
	switch mode {
	case filetype.AnalysisModeBinary:
		return fmt.Sprintf("二进制反编译器不支持 %s 格式", format)
	case filetype.AnalysisModeArchive:
		return fmt.Sprintf("一层归档解析器不支持 %s 格式", format)
	case filetype.AnalysisModeContainer:
		return fmt.Sprintf("Trivy 镜像扫描器不支持 %s 格式", format)
	default:
		return fmt.Sprintf("当前分析引擎不支持 %s 格式", format)
	}
}

func analysisOptions(format string) []uploadAnalysisOption {
	modes := []filetype.AnalysisMode{
		filetype.AnalysisModeBinary,
		filetype.AnalysisModeArchive,
		filetype.AnalysisModeContainer,
	}
	options := make([]uploadAnalysisOption, 0, len(modes))
	for _, mode := range modes {
		supported := filetype.SupportsAnalysisMode(format, mode)
		option := uploadAnalysisOption{Mode: string(mode), Supported: supported}
		if !supported {
			option.Reason = unsupportedAnalysisMessage(mode, format)
		}
		options = append(options, option)
	}
	return options
}

func (s *taskService) finalizeUpload(
	ctx *gin.Context, record uploadRecord, blob storage.Blob, detected filetype.Result, assemblyToken string,
) (uploadRecord, *uploadValidationFailure, error) {
	blobID, err := identity.UUID()
	if err != nil {
		return uploadRecord{}, nil, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return uploadRecord{}, nil, err
	}
	defer tx.Rollback()
	var state string
	var currentToken sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT status, assembly_token FROM uploads
		WHERE id = ? AND created_by = ? FOR UPDATE`, record.ID, record.CreatedBy).Scan(&state, &currentToken); err != nil {
		return uploadRecord{}, nil, err
	}
	if state != "open" || !currentToken.Valid || currentToken.String != assemblyToken {
		return uploadRecord{}, nil, fmt.Errorf("upload assembly fence was lost in state %s", state)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO blobs
		(id, sha256, size_bytes, storage_key, state) VALUES (?, ?, ?, ?, 'ready')
		ON DUPLICATE KEY UPDATE state = 'ready', deleted_at = NULL`,
		blobID, blob.SHA256[:], blob.SizeBytes, blob.StorageKey); err != nil {
		return uploadRecord{}, nil, fmt.Errorf("persist upload blob: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT id FROM blobs WHERE sha256 = ?`, blob.SHA256[:]).Scan(&blobID); err != nil {
		return uploadRecord{}, nil, fmt.Errorf("resolve upload blob: %w", err)
	}

	var validationFailure *uploadValidationFailure
	validationStatus := "valid"
	if detected.Category == "" || detected.Format == "unknown" {
		validationStatus = "unsupported"
		validationFailure = &uploadValidationFailure{code: "unsupported_input_format",
			message: "unsupported input format", detected: detected}
	}
	if validationFailure != nil {
		errorBody, _ := json.Marshal(uploadValidationMessage{Code: validationFailure.code, Message: validationFailure.message})
		if _, err := tx.ExecContext(ctx, `UPDATE uploads SET status = 'failed', blob_id = ?, received_size = ?,
			validation_status = ?, detected_category = NULLIF(?, ''), detected_format = NULLIF(?, ''),
			validation_error = ?, assembly_started_at = NULL, assembly_token = NULL,
			completed_at = UTC_TIMESTAMP(6) WHERE id = ?`,
			blobID, blob.SizeBytes, validationStatus, detected.Category, detected.Format, errorBody, record.ID); err != nil {
			return uploadRecord{}, nil, fmt.Errorf("record upload validation failure: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return uploadRecord{}, nil, err
		}
		return uploadRecord{}, validationFailure, nil
	}

	if _, err := tx.ExecContext(ctx, `UPDATE uploads SET status = 'complete', blob_id = ?, received_size = ?,
		validation_status = 'valid', detected_category = ?, detected_format = ?, validation_error = NULL,
		assembly_started_at = NULL, assembly_token = NULL,
		completed_at = UTC_TIMESTAMP(6) WHERE id = ?`, blobID, blob.SizeBytes, detected.Category,
		detected.Format, record.ID); err != nil {
		return uploadRecord{}, nil, fmt.Errorf("complete upload: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs
		(actor_user_id, action, object_type, object_id, request_id, client_ip, outcome, details)
		VALUES (?, 'upload.complete', 'upload', ?, ?, ?, 'success',
		JSON_OBJECT('detectedCategory', ?, 'detectedFormat', ?))`, record.CreatedBy,
		record.ID, ctx.GetString("requestID"), ctx.ClientIP(), detected.Category, detected.Format); err != nil {
		return uploadRecord{}, nil, fmt.Errorf("audit upload completion: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return uploadRecord{}, nil, err
	}
	record.Status = "complete"
	record.BlobID = sql.NullString{String: blobID, Valid: true}
	record.ReceivedSize = blob.SizeBytes
	record.ValidationStatus = "valid"
	record.DetectedCategory = sql.NullString{String: string(detected.Category), Valid: true}
	record.DetectedFormat = sql.NullString{String: detected.Format, Valid: true}
	record.CompletedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	record.AssemblyStartedAt = sql.NullTime{}
	record.AssemblyToken = sql.NullString{}
	return record, nil, nil
}

func (s *taskService) writeUploadSession(c *gin.Context, record uploadRecord, status int) {
	response, err := s.buildUploadSession(c, record)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload_query_failed"})
		return
	}
	c.JSON(status, response)
}

func (s *taskService) buildUploadSession(ctx context.Context, record uploadRecord) (uploadSessionResponse, error) {
	parts, err := s.uploadedPartNumbers(ctx, record.ID)
	if err != nil {
		return uploadSessionResponse{}, err
	}
	response := uploadSessionResponse{ID: record.ID, Filename: record.OriginalName, ContentType: record.ContentType,
		PartSize: uploadPartSize, Status: uploadAPIStatus(record),
		UploadedParts: parts, ExpiresAt: record.ExpiresAt, InputCategory: record.InputCategory,
		ValidationStatus: record.ValidationStatus, DetectedCategory: record.DetectedCategory.String,
		DetectedFormat: record.DetectedFormat.String}
	if len(record.ValidationError) != 0 {
		var validation uploadValidationMessage
		if json.Unmarshal(record.ValidationError, &validation) == nil && validation.Code != "" && validation.Message != "" {
			response.ValidationError = &validation
		}
	}
	if record.Status == "complete" {
		response.SizeBytes = &record.ReceivedSize
		var digest []byte
		if err := s.db.QueryRowContext(ctx, `SELECT sha256 FROM blobs WHERE id = ? AND state = 'ready'`,
			record.BlobID.String).Scan(&digest); err != nil {
			return uploadSessionResponse{}, fmt.Errorf("load upload digest: %w", err)
		}
		if len(digest) != sha256.Size {
			return uploadSessionResponse{}, fmt.Errorf("load upload digest: invalid SHA-256 length")
		}
		response.SHA256 = hex.EncodeToString(digest)
		response.AnalysisOptions = analysisOptions(record.DetectedFormat.String)
		rows, err := s.db.QueryContext(ctx, `SELECT id, COALESCE(analysis_mode, input_category, ''), status,
			COALESCE(detected_format, '') FROM tasks
			WHERE upload_id = ? AND deleted_at IS NULL ORDER BY created_at`, record.ID)
		if err != nil {
			return uploadSessionResponse{}, err
		}
		for rows.Next() {
			var task uploadTaskResponse
			var detectedFormat string
			if err := rows.Scan(&task.TaskID, &task.AnalysisMode, &task.Status, &detectedFormat); err != nil {
				rows.Close()
				return uploadSessionResponse{}, err
			}
			mode, ok := filetype.ParseAnalysisMode(task.AnalysisMode)
			if ok {
				task.Supported = filetype.SupportsAnalysisMode(detectedFormat, mode)
			}
			response.Tasks = append(response.Tasks, task)
		}
		if err := rows.Close(); err != nil {
			return uploadSessionResponse{}, err
		}
		if err := rows.Err(); err != nil {
			return uploadSessionResponse{}, err
		}
		for index := range response.Tasks {
			if response.Tasks[index].AnalysisMode != string(filetype.AnalysisModeArchive) {
				continue
			}
			var runID sql.NullString
			if err := s.db.QueryRowContext(ctx, `SELECT id FROM runs WHERE task_id = ? AND kind = 'archive_import'
				ORDER BY created_at DESC LIMIT 1`, response.Tasks[index].TaskID).Scan(&runID); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return uploadSessionResponse{}, err
			}
			response.Tasks[index].ArchiveImportID = runID.String
		}
		// Keep the legacy single-task fields populated for old API consumers.
		if len(response.Tasks) == 1 {
			if response.Tasks[0].AnalysisMode == string(filetype.AnalysisModeArchive) {
				response.ArchiveImportID = response.Tasks[0].ArchiveImportID
			} else {
				response.TaskID = response.Tasks[0].TaskID
			}
		}
	}
	return response, nil
}

func (s *taskService) writeUploadStateError(c *gin.Context, record uploadRecord) {
	code, status := "upload_invalid_state", http.StatusConflict
	if uploadAPIStatus(record) == "expired" {
		code, status = "upload_expired", http.StatusGone
	} else if record.ValidationStatus == "mismatch" {
		code, status = "input_category_mismatch", http.StatusUnprocessableEntity
	} else if record.ValidationStatus == "unsupported" {
		code, status = "unsupported_input_format", http.StatusUnprocessableEntity
	}
	c.JSON(status, gin.H{"error": code, "details": gin.H{"upload_id": record.ID,
		"detected_category": record.DetectedCategory.String, "detected_format": record.DetectedFormat.String}})
}

func (s *taskService) loadOwnedUpload(
	ctx *gin.Context, uploadID string, userID uint64, lock bool,
) (uploadRecord, bool, error) {
	query := `SELECT id, created_by, original_name, content_type, input_category, declared_size,
		received_size, status, blob_id, validation_status, detected_category, detected_format,
		validation_error, expires_at, assembly_started_at, assembly_token, created_at, completed_at, idempotency_key
		FROM uploads WHERE id = ? AND created_by = ?`
	if lock {
		query += " FOR UPDATE"
	}
	var record uploadRecord
	var contentType, inputCategory, validationStatus sql.NullString
	var expiresAt sql.NullTime
	err := s.db.QueryRowContext(ctx, query, uploadID, userID).Scan(&record.ID, &record.CreatedBy,
		&record.OriginalName, &contentType, &inputCategory, &record.DeclaredSize,
		&record.ReceivedSize, &record.Status, &record.BlobID, &validationStatus,
		&record.DetectedCategory, &record.DetectedFormat, &record.ValidationError, &expiresAt,
		&record.AssemblyStartedAt, &record.AssemblyToken, &record.CreatedAt, &record.CompletedAt,
		&record.IdempotencyKey)
	if errors.Is(err, sql.ErrNoRows) {
		return uploadRecord{}, false, nil
	}
	if err != nil {
		return uploadRecord{}, false, err
	}
	record.ContentType = contentType.String
	if record.ContentType == "" {
		record.ContentType = "application/octet-stream"
	}
	record.InputCategory = inputCategory.String
	record.ValidationStatus = validationStatus.String
	if record.ValidationStatus == "" {
		record.ValidationStatus = "pending"
	}
	if expiresAt.Valid {
		record.ExpiresAt = expiresAt.Time
	} else {
		record.ExpiresAt = record.CreatedAt.Add(uploadSessionTTL)
	}
	return record, true, nil
}

func (s *taskService) loadUploadByIdempotency(
	ctx *gin.Context, userID uint64, key string,
) (uploadRecord, bool, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM uploads WHERE created_by = ? AND idempotency_key = ?`,
		userID, key).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return uploadRecord{}, false, nil
	}
	if err != nil {
		return uploadRecord{}, false, err
	}
	return s.loadOwnedUpload(ctx, id, userID, false)
}

func (s *taskService) uploadedPartNumbers(ctx context.Context, uploadID string) ([]uint32, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT part_number FROM upload_parts WHERE upload_id = ? ORDER BY part_number`, uploadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]uint32, 0)
	for rows.Next() {
		var number uint32
		if err := rows.Scan(&number); err != nil {
			return nil, err
		}
		result = append(result, number)
	}
	return result, rows.Err()
}

func (s *taskService) loadUploadParts(ctx *gin.Context, uploadID string) ([]storedUploadPart, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT part_number, byte_offset, size_bytes, sha256
		FROM upload_parts WHERE upload_id = ? ORDER BY part_number`, uploadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	parts := make([]storedUploadPart, 0)
	for rows.Next() {
		var part storedUploadPart
		var digest []byte
		if err := rows.Scan(&part.Number, &part.Offset, &part.Size, &digest); err != nil {
			return nil, err
		}
		if len(digest) != sha256.Size {
			return nil, fmt.Errorf("upload part %d has invalid digest", part.Number)
		}
		copy(part.SHA256[:], digest)
		parts = append(parts, part)
	}
	return parts, rows.Err()
}

func (s *taskService) uploadDirectory(uploadID string) (string, error) {
	if !canonicalUUID(uploadID) {
		return "", fmt.Errorf("invalid upload id")
	}
	root, err := filepath.Abs(filepath.Join(s.storageRoot, "uploads"))
	if err != nil {
		return "", err
	}
	directory := filepath.Join(root, uploadID)
	if filepath.Dir(directory) != root {
		return "", fmt.Errorf("unsafe upload path")
	}
	return directory, nil
}

func canonicalUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func parseContentRange(value string) (contentRange, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "bytes ") {
		return contentRange{}, fmt.Errorf("content range must use bytes")
	}
	value = strings.TrimPrefix(value, "bytes ")
	rangeAndTotal := strings.Split(value, "/")
	if len(rangeAndTotal) != 2 || strings.Contains(rangeAndTotal[1], "*") {
		return contentRange{}, fmt.Errorf("invalid content range")
	}
	bounds := strings.Split(rangeAndTotal[0], "-")
	if len(bounds) != 2 {
		return contentRange{}, fmt.Errorf("invalid content range")
	}
	start, errStart := strconv.ParseInt(bounds[0], 10, 64)
	end, errEnd := strconv.ParseInt(bounds[1], 10, 64)
	total, errTotal := strconv.ParseInt(rangeAndTotal[1], 10, 64)
	if errStart != nil || errEnd != nil || errTotal != nil || start < 0 || end < start || total <= end {
		return contentRange{}, fmt.Errorf("invalid content range")
	}
	return contentRange{Start: start, End: end, Total: total}, nil
}

func parseSHA256Header(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	decoded, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(value)))
	if err != nil || len(decoded) != sha256.Size {
		return digest, fmt.Errorf("invalid SHA-256")
	}
	copy(digest[:], decoded)
	return digest, nil
}

func replaceUploadPart(temporaryPath, destination string) error {
	if err := os.Chmod(temporaryPath, 0o400); err != nil {
		return err
	}
	return os.Rename(temporaryPath, destination)
}

func verifyUploadPart(path string, part storedUploadPart) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != part.Size {
		return fmt.Errorf("upload part size mismatch")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}
	if !equalDigest(hasher.Sum(nil), part.SHA256[:]) {
		return fmt.Errorf("upload part digest mismatch")
	}
	return nil
}

func validateUploadParts(parts []storedUploadPart, total int64) error {
	if total <= 0 || len(parts) == 0 {
		return fmt.Errorf("upload has no parts")
	}
	expectedCount := int((total + uploadPartSize - 1) / uploadPartSize)
	if len(parts) != expectedCount {
		return fmt.Errorf("upload has %d of %d parts", len(parts), expectedCount)
	}
	var offset int64
	for index, part := range parts {
		expectedNumber := uint32(index + 1)
		expectedSize := uploadPartSize
		if remaining := total - offset; remaining < expectedSize {
			expectedSize = remaining
		}
		if part.Number != expectedNumber || part.Offset != offset || part.Size != expectedSize {
			return fmt.Errorf("upload part sequence is incomplete")
		}
		offset += part.Size
	}
	if offset != total {
		return fmt.Errorf("upload size mismatch")
	}
	return nil
}

type uploadPartsReader struct {
	directory string
	parts     []storedUploadPart
	index     int
	current   *os.File
}

func (r *uploadPartsReader) Read(buffer []byte) (int, error) {
	for {
		if r.current == nil {
			if r.index >= len(r.parts) {
				return 0, io.EOF
			}
			file, err := os.Open(uploadPartPath(r.directory, r.parts[r.index].Number))
			if err != nil {
				return 0, err
			}
			r.current = file
		}
		read, err := r.current.Read(buffer)
		if errors.Is(err, io.EOF) {
			_ = r.current.Close()
			r.current = nil
			r.index++
			if read != 0 {
				return read, nil
			}
			continue
		}
		return read, err
	}
}

func (r *uploadPartsReader) Close() error {
	if r.current == nil {
		return nil
	}
	err := r.current.Close()
	r.current = nil
	return err
}

func uploadPartPath(directory string, number uint32) string {
	return filepath.Join(directory, "parts", fmt.Sprintf("part-%06d", number))
}

func uploadAPIStatus(record uploadRecord) string {
	switch record.Status {
	case "complete":
		return "completed"
	case "failed":
		return "failed"
	case "aborted":
		return "cancelled"
	default:
		if record.AssemblyToken.Valid &&
			(!record.AssemblyStartedAt.Valid || record.AssemblyStartedAt.Time.After(time.Now().UTC().Add(-uploadAssemblyStale))) {
			return "assembling"
		}
		if !record.ExpiresAt.IsZero() && time.Now().UTC().After(record.ExpiresAt) {
			return "expired"
		}
		if record.ReceivedSize > 0 {
			return "uploading"
		}
		return "created"
	}
}

func validIdempotencyKey(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsRune(value, '\x00')
}

func validUploadText(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character == 0 || character == 127 || (character < 32 && character != '\t') {
			return false
		}
	}
	return true
}

func equalDigest(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
