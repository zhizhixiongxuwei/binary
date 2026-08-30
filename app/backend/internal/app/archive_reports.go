package app

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"binaryscan.local/backend/internal/identity"
	"binaryscan.local/backend/internal/storage"

	"github.com/gin-gonic/gin"
)

const (
	archiveBundleSchema              = "binaryscan-archive-report-bundle-v1"
	maxArchiveBundleRequestBytes     = 8 << 10
	maxArchiveBundleUncompressedSize = int64(4 << 30)
)

type archiveBundleOptions struct {
	Formats        []string `json:"formats"`
	IncludeSources bool     `json:"include_sources"`
}

type archiveBundleRecord struct {
	ID              string    `json:"id"`
	ArchiveImportID string    `json:"archive_import_id"`
	Status          string    `json:"status"`
	SchemaVersion   string    `json:"schema_version"`
	Formats         []string  `json:"formats"`
	IncludeSources  bool      `json:"include_sources"`
	IncludedTasks   int       `json:"included_tasks"`
	OmittedTasks    int       `json:"omitted_tasks"`
	ReportFiles     int       `json:"report_files"`
	SourceFiles     int       `json:"source_files"`
	SHA256          string    `json:"sha256"`
	SizeBytes       int64     `json:"size_bytes"`
	CreatedAt       time.Time `json:"created_at"`
	CompletedAt     time.Time `json:"completed_at"`
}

type archiveBundleManifest struct {
	Schema      string                       `json:"schema"`
	GeneratedAt time.Time                    `json:"generated_at"`
	Archive     archiveBundleManifestArchive `json:"archive"`
	Summary     archiveBundleManifestSummary `json:"summary"`
	Children    []archiveBundleManifestChild `json:"children"`
}

type archiveBundleManifestArchive struct {
	ImportID    string    `json:"import_id"`
	Filename    string    `json:"filename"`
	InputSHA256 string    `json:"input_sha256"`
	CreatedAt   time.Time `json:"created_at"`
}

type archiveBundleManifestSummary struct {
	CreatedTasks  int `json:"created_tasks"`
	IncludedTasks int `json:"included_tasks"`
	OmittedTasks  int `json:"omitted_tasks"`
	ReportFiles   int `json:"report_files"`
	SourceFiles   int `json:"source_files"`
}

type archiveBundleManifestChild struct {
	Ordinal         uint64                        `json:"ordinal"`
	ArchivePath     string                        `json:"archive_path"`
	InputSHA256     string                        `json:"input_sha256,omitempty"`
	TaskID          string                        `json:"task_id"`
	TaskName        string                        `json:"task_name,omitempty"`
	TaskStatus      string                        `json:"task_status,omitempty"`
	DetectedFormat  string                        `json:"detected_format,omitempty"`
	Included        bool                          `json:"included"`
	OmissionReason  string                        `json:"omission_reason,omitempty"`
	MissingFormats  []string                      `json:"missing_formats,omitempty"`
	Runs            []archiveBundleManifestRun    `json:"runs"`
	Reports         []archiveBundleManifestReport `json:"reports"`
	Sources         []archiveBundleManifestSource `json:"sources,omitempty"`
	BundleDirectory string                        `json:"bundle_directory,omitempty"`
}

type archiveBundleManifestRun struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Status      string    `json:"status"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

type archiveBundleManifestReport struct {
	ID             string    `json:"id"`
	Format         string    `json:"format"`
	SHA256         string    `json:"sha256"`
	SizeBytes      int64     `json:"size_bytes"`
	CreatedAt      time.Time `json:"created_at"`
	SelectedRunIDs []string  `json:"selected_run_ids"`
	BundlePath     string    `json:"bundle_path"`
}

type archiveBundleManifestSource struct {
	ProjectID  string `json:"project_id"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	SizeBytes  int64  `json:"size_bytes"`
	BundlePath string `json:"bundle_path"`
}

type archiveBundleReportFile struct {
	TaskID     string
	StorageKey string
	Manifest   archiveBundleManifestReport
}

type archiveBundleSourceFile struct {
	TaskID      string
	StorageKey  string
	LogicalPath string
	Manifest    archiveBundleManifestSource
}

// preparedArchiveBundle 是“选择哪些子任务制品”与“实际写 ZIP”之间的确定性计划，
// Manifest 同时记录包含、省略和缺失原因，让合集即使不完整也可解释。
type preparedArchiveBundle struct {
	Manifest   archiveBundleManifest
	Reports    []archiveBundleReportFile
	Sources    []archiveBundleSourceFile
	TotalBytes int64
}

type archiveBundleStored struct {
	Record  archiveBundleRecord
	Options archiveBundleOptions
}

var errNoArchiveReports = errors.New("archive has no completed reports for the requested formats")

// createArchiveReportBundle 为一次归档导入汇总子任务报告及可选源码。
// 排序后的格式集合与 IncludeSources 构成幂等意图；文件先原子发布、数据库后登记，
// 并发赢家和 Commit 结果不确定都通过唯一幂等记录回读收敛，未被引用的本次文件会被清理。
func (s *taskService) createArchiveReportBundle(c *gin.Context) {
	idempotencyKey := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if !validIdempotencyKey(idempotencyKey) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "idempotency_key_required"})
		return
	}
	var request archiveBundleOptions
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxArchiveBundleRequestBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		!canonicalArchiveBundleOptions(&request) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_archive_report_bundle_request"})
		return
	}
	user := mustCurrentUser(c)
	importID := c.Param("importID")
	existing, found, err := s.loadArchiveBundleByIntent(c, user.ID, importID, idempotencyKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_creation_failed"})
		return
	}
	if found {
		if !archiveBundleIntentMatches(existing.Options, request) {
			c.JSON(http.StatusConflict, gin.H{"error": "archive_report_bundle_idempotency_conflict"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"bundle": existing.Record})
		return
	}

	prepared, err := s.prepareArchiveBundle(c, importID, request)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			c.JSON(http.StatusNotFound, gin.H{"error": "archive_import_not_found"})
		case errors.Is(err, errNoArchiveReports):
			c.JSON(http.StatusConflict, gin.H{"error": "archive_reports_not_ready"})
		case errors.Is(err, errArchiveBundleTooLarge):
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "archive_report_bundle_too_large"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_creation_failed"})
		}
		return
	}
	bundleID, err := identity.UUID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_creation_failed"})
		return
	}
	relative, digest, sizeBytes, err := s.publishArchiveBundle(importID, bundleID, prepared)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_creation_failed"})
		return
	}
	keepPublished := false
	defer func() {
		if !keepPublished {
			_ = os.Remove(filepath.Join(s.reportRoot, filepath.FromSlash(relative)))
		}
	}()
	optionsJSON, _ := json.Marshal(request)
	manifestJSON, err := json.Marshal(prepared.Manifest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_creation_failed"})
		return
	}
	tx, err := s.db.BeginTx(c, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_creation_failed"})
		return
	}
	defer tx.Rollback()
	storageKey := filepath.ToSlash(filepath.Join("reports", relative))
	if _, err := tx.ExecContext(c, `INSERT INTO archive_report_bundles
		(id, import_run_id, created_by, idempotency_key, status, schema_version, storage_key,
		 sha256, size_bytes, options, manifest)
		VALUES (?, ?, ?, ?, 'ready', ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE id = id`, bundleID, importID, user.ID, idempotencyKey,
		archiveBundleSchema, storageKey, digest, sizeBytes, optionsJSON, manifestJSON); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_creation_failed"})
		return
	}
	actual, err := loadArchiveBundleStored(tx.QueryRowContext(c, archiveBundleSelect+`
		WHERE b.created_by = ? AND b.import_run_id = ? AND b.idempotency_key = ?`,
		user.ID, importID, idempotencyKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_creation_failed"})
		return
	}
	if actual.Record.ID != bundleID {
		if !archiveBundleIntentMatches(actual.Options, request) {
			c.JSON(http.StatusConflict, gin.H{"error": "archive_report_bundle_idempotency_conflict"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"bundle": actual.Record})
		return
	}
	if _, err := tx.ExecContext(c, `INSERT INTO audit_logs
		(actor_user_id, action, object_type, object_id, request_id, client_ip, outcome, details)
		VALUES (?, 'archive.report_bundle.create', 'archive_report_bundle', ?, ?, ?, 'success',
		 JSON_OBJECT('archiveImportId', ?, 'includedTasks', ?, 'omittedTasks', ?, 'reportFiles', ?, 'sourceFiles', ?))`,
		user.ID, bundleID, c.GetString("requestID"), c.ClientIP(), importID,
		prepared.Manifest.Summary.IncludedTasks, prepared.Manifest.Summary.OmittedTasks,
		prepared.Manifest.Summary.ReportFiles, prepared.Manifest.Summary.SourceFiles); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_creation_failed"})
		return
	}
	if err := tx.Commit(); err != nil {
		// 提交响应丢失时反查唯一记录；只有数据库确实引用本 bundleID 才保留本次磁盘文件。
		committed, found, queryErr := s.loadArchiveBundleByIntent(c, user.ID, importID, idempotencyKey)
		if queryErr == nil && found && archiveBundleIntentMatches(committed.Options, request) {
			if committed.Record.ID == bundleID {
				keepPublished = true
			}
			c.JSON(http.StatusOK, gin.H{"bundle": committed.Record})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_creation_failed"})
		return
	}
	keepPublished = true
	c.JSON(http.StatusCreated, gin.H{"bundle": actual.Record})
}

// canonicalArchiveBundleOptions 校验有限格式白名单并排序，使数组顺序差异不会改变幂等意图。
func canonicalArchiveBundleOptions(options *archiveBundleOptions) bool {
	if len(options.Formats) == 0 || len(options.Formats) > 3 {
		return false
	}
	seen := make(map[string]struct{}, len(options.Formats))
	for _, format := range options.Formats {
		if format != "json" && format != "html" && format != "docx" {
			return false
		}
		if _, duplicate := seen[format]; duplicate {
			return false
		}
		seen[format] = struct{}{}
	}
	sort.Strings(options.Formats)
	return true
}

func archiveBundleIntentMatches(left, right archiveBundleOptions) bool {
	if left.IncludeSources != right.IncludeSources || len(left.Formats) != len(right.Formats) {
		return false
	}
	for index := range left.Formats {
		if left.Formats[index] != right.Formats[index] {
			return false
		}
	}
	return true
}

const archiveBundleSelect = `SELECT b.id, b.import_run_id, b.status, b.schema_version,
	HEX(b.sha256), b.size_bytes, b.options, b.manifest, b.created_at
	FROM archive_report_bundles b `

func (s *taskService) loadArchiveBundleByIntent(
	ctx context.Context, userID uint64, importID, idempotencyKey string,
) (archiveBundleStored, bool, error) {
	stored, err := loadArchiveBundleStored(s.db.QueryRowContext(ctx, archiveBundleSelect+`
		WHERE b.created_by = ? AND b.import_run_id = ? AND b.idempotency_key = ?
		  AND b.deleted_at IS NULL`, userID, importID, idempotencyKey))
	if errors.Is(err, sql.ErrNoRows) {
		return archiveBundleStored{}, false, nil
	}
	return stored, err == nil, err
}

type archiveBundleRowScanner interface {
	Scan(dest ...any) error
}

func loadArchiveBundleStored(row archiveBundleRowScanner) (archiveBundleStored, error) {
	var stored archiveBundleStored
	var optionsJSON, manifestJSON []byte
	if err := row.Scan(&stored.Record.ID, &stored.Record.ArchiveImportID, &stored.Record.Status,
		&stored.Record.SchemaVersion, &stored.Record.SHA256, &stored.Record.SizeBytes,
		&optionsJSON, &manifestJSON, &stored.Record.CreatedAt); err != nil {
		return archiveBundleStored{}, err
	}
	if err := json.Unmarshal(optionsJSON, &stored.Options); err != nil || !canonicalArchiveBundleOptions(&stored.Options) {
		return archiveBundleStored{}, fmt.Errorf("decode archive bundle options")
	}
	var manifest archiveBundleManifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return archiveBundleStored{}, fmt.Errorf("decode archive bundle manifest: %w", err)
	}
	stored.Record.Formats = append([]string(nil), stored.Options.Formats...)
	stored.Record.IncludeSources = stored.Options.IncludeSources
	stored.Record.IncludedTasks = manifest.Summary.IncludedTasks
	stored.Record.OmittedTasks = manifest.Summary.OmittedTasks
	stored.Record.ReportFiles = manifest.Summary.ReportFiles
	stored.Record.SourceFiles = manifest.Summary.SourceFiles
	stored.Record.SHA256 = strings.ToLower(stored.Record.SHA256)
	stored.Record.CompletedAt = stored.Record.CreatedAt
	return stored, nil
}

func (s *taskService) listArchiveReportBundles(c *gin.Context) {
	importID := c.Param("importID")
	if _, err := s.loadArchiveImport(c, importID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "archive_import_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_query_failed"})
		}
		return
	}
	rows, err := s.db.QueryContext(c, archiveBundleSelect+`
		WHERE b.import_run_id = ? AND b.deleted_at IS NULL
		ORDER BY b.created_at DESC, b.id DESC LIMIT 100`, importID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_query_failed"})
		return
	}
	defer rows.Close()
	bundles := make([]archiveBundleRecord, 0)
	for rows.Next() {
		stored, err := loadArchiveBundleStored(rows)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_query_failed"})
			return
		}
		bundles = append(bundles, stored.Record)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_query_failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"bundles": bundles})
}

// downloadArchiveReportBundle 与单份报告共享完整性门禁：只传输 ready 且磁盘大小/SHA-256 仍匹配的 ZIP。
func (s *taskService) downloadArchiveReportBundle(c *gin.Context) {
	var importID, storageKey string
	var expectedSHA sql.NullString
	var expectedSize sql.NullInt64
	if err := s.db.QueryRowContext(c, `SELECT import_run_id, storage_key, HEX(sha256), size_bytes
		FROM archive_report_bundles WHERE id = ? AND status = 'ready' AND deleted_at IS NULL`,
		c.Param("bundleID")).Scan(&importID, &storageKey, &expectedSHA, &expectedSize); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "archive_report_bundle_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_query_failed"})
		}
		return
	}
	cleaned, err := storage.CleanRelativePath(storageKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "archive_report_bundle_storage_invalid"})
		return
	}
	filename := filepath.Join(s.storageRoot, filepath.FromSlash(cleaned))
	if err := verifyReportFile(filename, expectedSize, expectedSHA); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "archive_report_bundle_storage_corrupt"})
		return
	}
	c.Header("ETag", `"`+strings.ToLower(expectedSHA.String)+`"`)
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", fmt.Sprintf(
		"attachment; filename=\"binaryscan-archive-%s-%s.zip\"",
		shortIdentifier(importID), shortIdentifier(c.Param("bundleID")),
	))
	c.File(filename)
}

var errArchiveBundleTooLarge = errors.New("archive report bundle exceeds size limit")

// prepareArchiveBundle 为每个未删除子任务、每种请求格式选择最新 ready 报告；删除的子任务、
// 尚无所选报告及缺失格式都会保留在 manifest 中。只有至少有一份报告的子任务计为 included，
// 可选源码仅从这些任务的 ready 项目收集，并对报告与源码声明大小施加 4 GiB 未压缩总上限。
func (s *taskService) prepareArchiveBundle(
	ctx context.Context, importID string, options archiveBundleOptions,
) (preparedArchiveBundle, error) {
	var archiveName, archiveSHA string
	var archiveCreated time.Time
	if err := s.db.QueryRowContext(ctx, `SELECT t.display_name, HEX(b.sha256), r.created_at
		FROM runs r JOIN tasks t ON t.id = r.task_id JOIN blobs b ON b.id = t.blob_id
		WHERE r.id = ? AND r.kind = 'archive_import'
		  AND (t.deleted_at IS NULL OR EXISTS (SELECT 1 FROM archive_entries retained
			JOIN tasks child ON child.id = retained.created_task_id AND child.deleted_at IS NULL
			WHERE retained.import_run_id = r.id) OR EXISTS (SELECT 1 FROM archive_report_bundles bundle
			WHERE bundle.import_run_id = r.id AND bundle.status = 'ready' AND bundle.deleted_at IS NULL))`, importID).Scan(
		&archiveName, &archiveSHA, &archiveCreated,
	); err != nil {
		return preparedArchiveBundle{}, err
	}
	prepared := preparedArchiveBundle{Manifest: archiveBundleManifest{
		Schema: archiveBundleSchema, GeneratedAt: time.Now().UTC(),
		Archive: archiveBundleManifestArchive{ImportID: importID, Filename: archiveName,
			InputSHA256: strings.ToLower(archiveSHA), CreatedAt: archiveCreated},
		Children: make([]archiveBundleManifestChild, 0),
	}}
	rows, err := s.db.QueryContext(ctx, `SELECT ae.ordinal, ae.logical_path, COALESCE(HEX(b.sha256), ''),
		COALESCE(ae.created_task_id, ''), COALESCE(child.display_name, ''), COALESCE(child.status, ''),
		COALESCE(child.detected_format, ''), child.deleted_at
		FROM archive_entries ae
		LEFT JOIN blobs b ON b.id = ae.blob_id
		LEFT JOIN tasks child ON child.id = ae.created_task_id
		WHERE ae.import_run_id = ? AND ae.created_task_id IS NOT NULL
		ORDER BY ae.ordinal`, importID)
	if err != nil {
		return preparedArchiveBundle{}, err
	}
	childByTask := make(map[string]int)
	for rows.Next() {
		var child archiveBundleManifestChild
		var deleted sql.NullTime
		if err := rows.Scan(&child.Ordinal, &child.ArchivePath, &child.InputSHA256, &child.TaskID,
			&child.TaskName, &child.TaskStatus, &child.DetectedFormat, &deleted); err != nil {
			rows.Close()
			return preparedArchiveBundle{}, err
		}
		child.InputSHA256 = strings.ToLower(child.InputSHA256)
		child.Runs = make([]archiveBundleManifestRun, 0)
		child.Reports = make([]archiveBundleManifestReport, 0)
		if deleted.Valid {
			child.OmissionReason = "子任务已删除"
		}
		childByTask[child.TaskID] = len(prepared.Manifest.Children)
		prepared.Manifest.Children = append(prepared.Manifest.Children, child)
	}
	if err := rows.Close(); err != nil {
		return preparedArchiveBundle{}, err
	}
	prepared.Manifest.Summary.CreatedTasks = len(prepared.Manifest.Children)

	if len(prepared.Manifest.Children) > 0 {
		runRows, err := s.db.QueryContext(ctx, `SELECT runs.task_id, runs.id, runs.kind, runs.status, runs.completed_at
			FROM runs JOIN archive_entries ae ON ae.created_task_id = runs.task_id
			JOIN tasks child ON child.id = runs.task_id AND child.deleted_at IS NULL
			WHERE ae.import_run_id = ? ORDER BY runs.created_at, runs.id`, importID)
		if err != nil {
			return preparedArchiveBundle{}, err
		}
		for runRows.Next() {
			var taskID string
			var run archiveBundleManifestRun
			var completed sql.NullTime
			if err := runRows.Scan(&taskID, &run.ID, &run.Kind, &run.Status, &completed); err != nil {
				runRows.Close()
				return preparedArchiveBundle{}, err
			}
			if completed.Valid {
				run.CompletedAt = completed.Time
			}
			if index, ok := childByTask[taskID]; ok {
				prepared.Manifest.Children[index].Runs = append(prepared.Manifest.Children[index].Runs, run)
			}
		}
		if err := runRows.Close(); err != nil {
			return preparedArchiveBundle{}, err
		}
	}

	requestedFormats := make(map[string]struct{}, len(options.Formats))
	for _, format := range options.Formats {
		requestedFormats[format] = struct{}{}
	}
	chosen := make(map[string]map[string]archiveBundleReportFile)
	reportRows, err := s.db.QueryContext(ctx, `SELECT reports_by_task.task_id, reports_by_task.id,
		reports_by_task.format, reports_by_task.storage_key, HEX(reports_by_task.sha256),
		reports_by_task.size_bytes, reports_by_task.selected_run_ids, reports_by_task.created_at
		FROM reports reports_by_task
		JOIN archive_entries ae ON ae.created_task_id = reports_by_task.task_id
		JOIN tasks child ON child.id = reports_by_task.task_id AND child.deleted_at IS NULL
		WHERE ae.import_run_id = ? AND reports_by_task.status = 'ready'
		  AND reports_by_task.deleted_at IS NULL
		ORDER BY reports_by_task.created_at DESC, reports_by_task.id DESC`, importID)
	if err != nil {
		return preparedArchiveBundle{}, err
	}
	for reportRows.Next() {
		var report archiveBundleReportFile
		var selectedJSON []byte
		if err := reportRows.Scan(&report.TaskID, &report.Manifest.ID, &report.Manifest.Format,
			&report.StorageKey, &report.Manifest.SHA256, &report.Manifest.SizeBytes,
			&selectedJSON, &report.Manifest.CreatedAt); err != nil {
			reportRows.Close()
			return preparedArchiveBundle{}, err
		}
		if _, wanted := requestedFormats[report.Manifest.Format]; !wanted {
			continue
		}
		if err := json.Unmarshal(selectedJSON, &report.Manifest.SelectedRunIDs); err != nil {
			reportRows.Close()
			return preparedArchiveBundle{}, fmt.Errorf("decode selected report runs: %w", err)
		}
		report.Manifest.SHA256 = strings.ToLower(report.Manifest.SHA256)
		byFormat := chosen[report.TaskID]
		if byFormat == nil {
			byFormat = make(map[string]archiveBundleReportFile)
			chosen[report.TaskID] = byFormat
		}
		if _, exists := byFormat[report.Manifest.Format]; !exists {
			byFormat[report.Manifest.Format] = report
		}
	}
	if err := reportRows.Close(); err != nil {
		return preparedArchiveBundle{}, err
	}

	for index := range prepared.Manifest.Children {
		child := &prepared.Manifest.Children[index]
		if child.OmissionReason != "" {
			prepared.Manifest.Summary.OmittedTasks++
			continue
		}
		child.BundleDirectory = archiveBundleChildDirectory(child.Ordinal, child.ArchivePath, child.TaskID)
		byFormat := chosen[child.TaskID]
		for _, format := range options.Formats {
			report, exists := byFormat[format]
			if !exists {
				child.MissingFormats = append(child.MissingFormats, format)
				continue
			}
			report.Manifest.BundlePath = filepath.ToSlash(filepath.Join(
				"children", child.BundleDirectory, "reports", "report."+format,
			))
			child.Reports = append(child.Reports, report.Manifest)
			prepared.Reports = append(prepared.Reports, report)
			prepared.TotalBytes += report.Manifest.SizeBytes
		}
		if len(child.Reports) == 0 {
			child.OmissionReason = "没有已生成的所选格式报告"
			prepared.Manifest.Summary.OmittedTasks++
			continue
		}
		child.Included = true
		prepared.Manifest.Summary.IncludedTasks++
		prepared.Manifest.Summary.ReportFiles += len(child.Reports)
	}
	if prepared.Manifest.Summary.IncludedTasks == 0 {
		return preparedArchiveBundle{}, errNoArchiveReports
	}
	if prepared.TotalBytes > maxArchiveBundleUncompressedSize {
		return preparedArchiveBundle{}, errArchiveBundleTooLarge
	}

	if options.IncludeSources {
		sourceRows, err := s.db.QueryContext(ctx, `SELECT projects.task_id, projects.id,
			projects.source_kind, projects.root_storage_key, files.logical_path,
			HEX(files.sha256), files.size_bytes
			FROM source_projects projects
			JOIN source_files files ON files.source_project_id = projects.id AND files.state = 'ready'
			JOIN archive_entries ae ON ae.created_task_id = projects.task_id
			JOIN tasks child ON child.id = projects.task_id AND child.deleted_at IS NULL
			WHERE ae.import_run_id = ? AND projects.state = 'ready'
			ORDER BY projects.task_id, projects.created_at, files.logical_path`, importID)
		if err != nil {
			return preparedArchiveBundle{}, err
		}
		for sourceRows.Next() {
			var taskID string
			var project sourceProjectPath
			var source archiveBundleSourceFile
			if err := sourceRows.Scan(&taskID, &project.id, &project.sourceKind, &project.storageKey,
				&source.LogicalPath, &source.Manifest.SHA256, &source.Manifest.SizeBytes); err != nil {
				sourceRows.Close()
				return preparedArchiveBundle{}, err
			}
			index, exists := childByTask[taskID]
			if !exists || !prepared.Manifest.Children[index].Included {
				continue
			}
			cleaned, err := storage.CleanRelativePath(source.LogicalPath)
			if err != nil {
				sourceRows.Close()
				return preparedArchiveBundle{}, err
			}
			root, err := s.sourceProjectRoot(project)
			if err != nil {
				sourceRows.Close()
				return preparedArchiveBundle{}, err
			}
			source.TaskID = taskID
			source.StorageKey = filepath.Join(root, filepath.FromSlash(cleaned))
			source.Manifest.ProjectID = project.id
			source.Manifest.Path = filepath.ToSlash(cleaned)
			source.Manifest.SHA256 = strings.ToLower(source.Manifest.SHA256)
			portableSourcePath := portableArchiveSourcePath(source.Manifest.Path, source.Manifest.SHA256)
			source.Manifest.BundlePath = filepath.ToSlash(filepath.Join(
				"children", prepared.Manifest.Children[index].BundleDirectory,
				"sources", project.id, filepath.FromSlash(portableSourcePath),
			))
			prepared.Manifest.Children[index].Sources = append(
				prepared.Manifest.Children[index].Sources, source.Manifest,
			)
			prepared.Sources = append(prepared.Sources, source)
			prepared.Manifest.Summary.SourceFiles++
			prepared.TotalBytes += source.Manifest.SizeBytes
			if prepared.TotalBytes > maxArchiveBundleUncompressedSize {
				sourceRows.Close()
				return preparedArchiveBundle{}, errArchiveBundleTooLarge
			}
		}
		if err := sourceRows.Close(); err != nil {
			return preparedArchiveBundle{}, err
		}
	}
	return prepared, nil
}

// publishArchiveBundle 在写入 ZIP 时重新校验每份报告/源码的普通文件类型、大小和 SHA-256，
// 避免准备清单后磁盘内容被替换。ZIP 完成、fsync 并计算整体摘要后才以硬链接发布为只读文件；
// 数据库事务失败时由调用方删除，保持与单份报告一致的两阶段发布语义。
func (s *taskService) publishArchiveBundle(
	importID, bundleID string, prepared preparedArchiveBundle,
) (string, []byte, int64, error) {
	for _, value := range []string{importID, bundleID} {
		if _, err := storage.CleanRelativePath(value); err != nil {
			return "", nil, 0, err
		}
	}
	temporary, err := os.CreateTemp(filepath.Join(s.reportRoot, ".staging"), "archive-bundle-*")
	if err != nil {
		return "", nil, 0, err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	archive := zip.NewWriter(temporary)
	manifestBody, err := json.MarshalIndent(prepared.Manifest, "", "  ")
	if err == nil {
		err = writeArchiveBundleBytes(archive, "manifest.json", manifestBody)
	}
	if err == nil {
		err = writeArchiveBundleBytes(archive, "index.html", buildArchiveBundleIndex(prepared.Manifest))
	}
	for _, report := range prepared.Reports {
		if err != nil {
			break
		}
		cleaned, cleanErr := storage.CleanRelativePath(report.StorageKey)
		if cleanErr != nil {
			err = cleanErr
			break
		}
		filename := filepath.Join(s.storageRoot, filepath.FromSlash(cleaned))
		if verifyErr := verifyReportFile(filename,
			sql.NullInt64{Int64: report.Manifest.SizeBytes, Valid: true},
			sql.NullString{String: report.Manifest.SHA256, Valid: true}); verifyErr != nil {
			err = verifyErr
			break
		}
		err = writeArchiveBundleFile(archive, report.Manifest.BundlePath, filename,
			report.Manifest.SHA256, report.Manifest.SizeBytes)
	}
	for _, source := range prepared.Sources {
		if err != nil {
			break
		}
		err = writeArchiveBundleFile(archive, source.Manifest.BundlePath, source.StorageKey,
			source.Manifest.SHA256, source.Manifest.SizeBytes)
	}
	if closeErr := archive.Close(); err == nil {
		err = closeErr
	}
	if syncErr := temporary.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", nil, 0, err
	}
	file, err := os.Open(temporaryName)
	if err != nil {
		return "", nil, 0, err
	}
	hasher := sha256.New()
	sizeBytes, err := io.Copy(hasher, file)
	file.Close()
	if err != nil {
		return "", nil, 0, err
	}
	relative := filepath.Join("archive-bundles", importID, bundleID+".zip")
	destination := filepath.Join(s.reportRoot, relative)
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return "", nil, 0, err
	}
	if err := os.Link(temporaryName, destination); err != nil {
		return "", nil, 0, err
	}
	if err := os.Chmod(destination, 0o440); err != nil {
		_ = os.Remove(destination)
		return "", nil, 0, err
	}
	return filepath.ToSlash(relative), hasher.Sum(nil), sizeBytes, nil
}

func writeArchiveBundleBytes(archive *zip.Writer, name string, body []byte) error {
	writer, err := archive.Create(name)
	if err != nil {
		return err
	}
	_, err = writer.Write(body)
	return err
}

// writeArchiveBundleFile 在流式写入 ZIP 的同时复算摘要，并检查读取字节数，捕获导出期间的内容变化。
func writeArchiveBundleFile(
	archive *zip.Writer, name, filename, expectedSHA string, expectedSize int64,
) error {
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != expectedSize {
		return fmt.Errorf("archive bundle source is not a valid regular file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	writer, err := archive.Create(filepath.ToSlash(name))
	if err != nil {
		return err
	}
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(writer, hasher), file)
	if err != nil {
		return err
	}
	if written != expectedSize {
		return fmt.Errorf("archive bundle source size changed while exporting")
	}
	if expectedSHA != "" && !strings.EqualFold(fmt.Sprintf("%x", hasher.Sum(nil)), expectedSHA) {
		return fmt.Errorf("archive bundle source digest does not match")
	}
	return nil
}

func archiveBundleChildDirectory(ordinal uint64, archivePath, taskID string) string {
	base := filepath.Base(strings.ReplaceAll(archivePath, "\\", "/"))
	name := portableArchiveComponent(base)
	return fmt.Sprintf("%05d-%s-%s", ordinal, name, shortIdentifier(taskID))
}

// portableArchiveSourcePath 保留清洗后的目录层次，并给文件名附加内容摘要前缀，降低净化后重名风险。
func portableArchiveSourcePath(logicalPath, digest string) string {
	parts := strings.Split(filepath.ToSlash(logicalPath), "/")
	for index, part := range parts {
		parts[index] = portableArchiveComponent(part)
	}
	if len(digest) < 8 {
		value := sha256.Sum256([]byte(logicalPath))
		digest = fmt.Sprintf("%x", value[:])
	}
	last := parts[len(parts)-1]
	extension := filepath.Ext(last)
	base := strings.TrimSuffix(last, extension)
	parts[len(parts)-1] = base + "__" + digest[:8] + extension
	return strings.Join(parts, "/")
}

// portableArchiveComponent 将归档成员名收敛为跨平台安全片段：限制字符和长度、去掉尾随点/空格，
// 并避开 Windows 设备保留名，使同一 ZIP 可在主流桌面系统安全解压。
func portableArchiveComponent(value string) string {
	var cleaned strings.Builder
	for _, character := range value {
		switch {
		case unicode.IsLetter(character), unicode.IsDigit(character), character == '.', character == '-', character == '_':
			cleaned.WriteRune(character)
		case unicode.IsSpace(character):
			cleaned.WriteByte('_')
		default:
			cleaned.WriteByte('_')
		}
		if cleaned.Len() >= 80 {
			break
		}
	}
	name := strings.Trim(cleaned.String(), ". _")
	if name == "" {
		name = "member"
	}
	reserved := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	for _, value := range []string{"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"} {
		if reserved == value {
			name = "_" + name
			break
		}
	}
	return name
}

func shortIdentifier(value string) string {
	cleaned := strings.ReplaceAll(value, "-", "")
	if len(cleaned) > 12 {
		return cleaned[:12]
	}
	if cleaned == "" {
		return "unknown"
	}
	return cleaned
}

func buildArchiveBundleIndex(manifest archiveBundleManifest) []byte {
	var output strings.Builder
	output.WriteString(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">`)
	output.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	output.WriteString(`<title>BinaryScan 归档报告合集</title><style>`)
	output.WriteString(`body{font:14px/1.6 system-ui;margin:32px;color:#17212b}table{width:100%;border-collapse:collapse}`)
	output.WriteString(`th,td{padding:8px;border:1px solid #dce4e8;text-align:left;vertical-align:top}th{background:#f1f6f7}`)
	output.WriteString(`code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.ok{color:#176b57}.skip{color:#8a5700}`)
	output.WriteString(`</style></head><body><h1>BinaryScan 归档报告合集</h1>`)
	output.WriteString(`<p>归档：<strong>` + html.EscapeString(manifest.Archive.Filename) + `</strong></p>`)
	output.WriteString(`<p>SHA-256：<code>` + html.EscapeString(manifest.Archive.InputSHA256) + `</code></p>`)
	output.WriteString(`<p>已包含 ` + strconv.Itoa(manifest.Summary.IncludedTasks) + ` 个任务，省略 ` + strconv.Itoa(manifest.Summary.OmittedTasks) + ` 个任务；共 ` + strconv.Itoa(manifest.Summary.ReportFiles) + ` 份报告。</p>`)
	output.WriteString(`<table><thead><tr><th>归档成员</th><th>任务</th><th>状态</th><th>报告</th><th>源码</th></tr></thead><tbody>`)
	for _, child := range manifest.Children {
		output.WriteString(`<tr><td>` + html.EscapeString(child.ArchivePath) + `</td><td><code>` + html.EscapeString(child.TaskID) + `</code></td>`)
		if child.Included {
			output.WriteString(`<td class="ok">已包含</td><td>`)
			for index, report := range child.Reports {
				if index > 0 {
					output.WriteString(` · `)
				}
				output.WriteString(`<a href="` + html.EscapeString(report.BundlePath) + `">` + html.EscapeString(strings.ToUpper(report.Format)) + `</a>`)
			}
			output.WriteString(`</td><td>` + strconv.Itoa(len(child.Sources)) + ` 个文件</td>`)
		} else {
			output.WriteString(`<td class="skip">已省略</td><td colspan="2">` + html.EscapeString(child.OmissionReason) + `</td>`)
		}
		output.WriteString(`</tr>`)
	}
	output.WriteString(`</tbody></table><p>完整机器可读清单见 <a href="manifest.json">manifest.json</a>。</p></body></html>`)
	return []byte(output.String())
}
