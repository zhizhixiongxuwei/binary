package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"binaryscan.local/backend/internal/llm"
	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

type explanationRequest struct {
	Scope        string `json:"scope"`
	StartLine    *int   `json:"startLine,omitempty"`
	EndLine      *int   `json:"endLine,omitempty"`
	RequestID    string `json:"requestId"`
	Regenerate   bool   `json:"regenerate"`
	SourceSHA256 string `json:"sourceSha256,omitempty"`
}

type llmService struct {
	manager    *llm.Manager
	repository explanationRepository
	loadSource func(context.Context, explanationTarget) (explanationSource, error)
	stream     func(context.Context, llm.Snapshot, string, func(string) error) error
	mu         sync.Mutex
	active     int
}

func newLLMService(tasks *taskService) (*llmService, error) {
	manager, err := llm.New(tasks.storageRoot)
	if err != nil {
		return nil, err
	}
	repository := sqlExplanationRepository{tasks.db}
	// The deployment runs one App process. Migrations complete before NewServer;
	// no request can start until this recovery succeeds. Never perform recovery
	// from a history GET, where it could interfere with an active stream.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := repository.RecoverInterrupted(ctx); err != nil {
		return nil, fmt.Errorf("recover interrupted model explanations: %w", err)
	}
	return &llmService{manager: manager, repository: repository, loadSource: tasks.loadExplanationSource, stream: llm.Stream}, nil
}

func registerLLMRoutes(protected *gin.RouterGroup, auth *authService, models *llmService) {
	protected.GET("/llm/status", models.status)
	protected.GET("/admin/llm/settings", requireAdministrator(), models.settings)
	protected.PUT("/admin/llm/settings", auth.requireCSRF(), requireAdministrator(), models.updateSettings)
	protected.POST("/admin/llm/test", auth.requireCSRF(), requireAdministrator(), models.test)
	protected.GET("/tasks/:taskID/projects/:projectID/files/:fileID/explanations", models.list)
	protected.POST("/tasks/:taskID/projects/:projectID/files/:fileID/explanations", auth.requireCSRF(), requireOperator(), models.explain)
}

func llmFailure(code, message string, status int) error {
	return &llm.Error{Code: code, Message: message, HTTPStatus: status}
}

func safeLLMError(err error) *llm.Error {
	var known *llm.Error
	if errors.As(err, &known) {
		return known
	}
	if errors.Is(err, context.Canceled) {
		return &llm.Error{Code: "llm_cancelled", Message: "解释已取消。", HTTPStatus: 499}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &llm.Error{Code: "llm_timeout", Message: "模型响应超时，请稍后重试。", HTTPStatus: http.StatusGatewayTimeout}
	}
	return &llm.Error{Code: "llm_unavailable", Message: "暂时无法生成解释，请稍后重试。", HTTPStatus: http.StatusBadGateway}
}

func writeLLMError(c *gin.Context, err error) {
	failure := safeLLMError(err)
	c.JSON(failure.HTTPStatus, gin.H{"error": failure.Code, "message": failure.Message})
}

func (s *llmService) status(c *gin.Context) {
	settings := s.manager.Get()
	c.JSON(http.StatusOK, gin.H{"enabled": settings.Enabled, "configured": settings.Configured,
		"provider": settings.Provider, "baseUrl": settings.BaseURL, "model": settings.Model,
		"maxInputChars": settings.MaxInputChars, "timeoutSeconds": settings.TimeoutSeconds})
}

func (s *llmService) settings(c *gin.Context) { c.JSON(http.StatusOK, s.manager.Get()) }

func decodeLLMJSON(c *gin.Context, value any) error {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8192)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

func (s *llmService) updateSettings(c *gin.Context) {
	var request llm.UpdateSettings
	if err := decodeLLMJSON(c, &request); err != nil {
		writeLLMError(c, llmFailure("invalid_request", "配置格式不正确。", http.StatusBadRequest))
		return
	}
	settings, err := s.manager.Update(request)
	if err != nil {
		writeLLMError(c, err)
		return
	}
	c.JSON(http.StatusOK, settings)
}

func (s *llmService) acquire(limit int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active >= limit {
		return false
	}
	s.active++
	return true
}
func (s *llmService) release() { s.mu.Lock(); s.active--; s.mu.Unlock() }

func (s *llmService) test(c *gin.Context) {
	settings := s.manager.Get()
	if !s.acquire(settings.MaxConcurrent) {
		writeLLMError(c, llmFailure("llm_busy", "模型请求较多，请稍后重试。", http.StatusTooManyRequests))
		return
	}
	defer s.release()
	// A saved provider may take longer than the normal HTTP write deadline.
	_ = http.NewResponseController(c.Writer).SetWriteDeadline(time.Now().Add(time.Duration(settings.TimeoutSeconds+10) * time.Second))
	if err := s.manager.Test(c.Request.Context()); err != nil {
		writeLLMError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "模型连接测试成功。"})
}

func targetFromContext(c *gin.Context) explanationTarget {
	return explanationTarget{TaskID: c.Param("taskID"), ProjectID: c.Param("projectID"), FileID: c.Param("fileID")}
}

func (s *llmService) list(c *gin.Context) {
	target := targetFromContext(c)
	source, err := s.loadSource(c.Request.Context(), target)
	if err != nil {
		writeLLMError(c, err)
		return
	}
	items, err := s.repository.List(c.Request.Context(), target)
	if err != nil {
		writeLLMError(c, llmFailure("llm_history_unavailable", "暂时无法读取解释历史。", http.StatusInternalServerError))
		return
	}
	for index := range items {
		items[index].Stale = !strings.EqualFold(items[index].SourceSHA256, source.SHA256)
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (s *llmService) explain(c *gin.Context) {
	var request explanationRequest
	if err := decodeLLMJSON(c, &request); err != nil {
		writeLLMError(c, llmFailure("invalid_request", "解释请求格式不正确。", http.StatusBadRequest))
		return
	}
	id, err := uuid.Parse(request.RequestID)
	if err != nil || len(request.RequestID) != 36 || id == uuid.Nil {
		writeLLMError(c, llmFailure("invalid_request", "requestId 必须是有效 UUID。", http.StatusBadRequest))
		return
	}
	request.RequestID = id.String()
	settings := s.manager.Snapshot()
	if !settings.Enabled {
		writeLLMError(c, llmFailure("llm_disabled", "模型解释尚未启用，请联系管理员。", http.StatusServiceUnavailable))
		return
	}
	if !settings.Configured {
		writeLLMError(c, llmFailure("llm_not_configured", "请先由管理员配置模型连接。", http.StatusServiceUnavailable))
		return
	}
	target := targetFromContext(c)
	source, err := s.loadSource(c.Request.Context(), target)
	if err != nil {
		writeLLMError(c, err)
		return
	}
	if request.SourceSHA256 != "" && !strings.EqualFold(request.SourceSHA256, source.SHA256) {
		writeLLMError(c, llmFailure("llm_source_changed", "源码已变化，请刷新源码后重新选择。", http.StatusConflict))
		return
	}
	prompt, start, end, err := explanationInput(source, request, settings.MaxInputChars)
	if err != nil {
		writeLLMError(c, err)
		return
	}
	key := explanationCacheKey(source, settings, request.Scope, start, end)
	existing, err := s.repository.FindRequest(c.Request.Context(), target, request.RequestID)
	if err == nil {
		if existing.Status == "completed" && existing.CacheKey == key {
			existing.CacheHit = true
			s.cached(c, existing)
			return
		}
		writeLLMError(c, llmFailure("llm_request_conflict", "此请求已处理或正在生成，请使用新的请求标识重试。", http.StatusConflict))
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		writeLLMError(c, llmFailure("llm_history_unavailable", "暂时无法读取解释历史。", http.StatusInternalServerError))
		return
	}
	if !request.Regenerate {
		existing, err = s.repository.FindCache(c.Request.Context(), target, key)
		if err == nil {
			existing.CacheHit = true
			s.cached(c, existing)
			return
		}
		if !errors.Is(err, sql.ErrNoRows) {
			writeLLMError(c, llmFailure("llm_history_unavailable", "暂时无法读取解释历史。", http.StatusInternalServerError))
			return
		}
	}
	if !s.acquire(settings.MaxConcurrent) {
		writeLLMError(c, llmFailure("llm_busy", "模型请求较多，请稍后重试。", http.StatusTooManyRequests))
		return
	}
	defer s.release()
	record := explanationRecord{ID: request.RequestID, TaskID: target.TaskID, ProjectID: target.ProjectID, FileID: target.FileID,
		SourceSHA256: source.SHA256, Scope: request.Scope, StartLine: start, EndLine: end, Provider: settings.Provider, Model: settings.Model,
		Status: "generating", CreatedAt: time.Now().UTC(), CacheKey: key, CreatedBy: mustCurrentUser(c).ID}
	if err := s.repository.Insert(c.Request.Context(), record); err != nil {
		var dbError *mysql.MySQLError
		if errors.Is(err, sql.ErrNoRows) {
			writeLLMError(c, llmFailure("llm_source_changed", "源码状态已变化，请刷新后重试。", http.StatusConflict))
		} else if errors.As(err, &dbError) && dbError.Number == 1062 {
			writeLLMError(c, llmFailure("llm_request_conflict", "此请求已处理或正在生成。", http.StatusConflict))
		} else {
			writeLLMError(c, llmFailure("llm_history_unavailable", "无法保存解释记录，请稍后重试。", http.StatusInternalServerError))
		}
		return
	}
	startExplanationSSE(c, settings.TimeoutSeconds)
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(settings.TimeoutSeconds)*time.Second)
	defer cancel()
	streamErr := sendExplanationEvent(c, "meta", record)
	var text strings.Builder
	outputChars := 0
	if streamErr == nil {
		streamErr = s.stream(ctx, settings, prompt, func(delta string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			outputChars += utf8.RuneCountInString(delta)
			if outputChars > llm.MaxOutputChars {
				return llmFailure("llm_output_too_large", "模型输出达到上限，请缩小源码范围后重试。", http.StatusBadGateway)
			}
			text.WriteString(delta)
			return sendExplanationEvent(c, "delta", gin.H{"text": delta})
		})
	}
	if streamErr == nil && ctx.Err() != nil {
		streamErr = ctx.Err()
	}
	record.Text = text.String()
	record.Status = "completed"
	if streamErr != nil {
		record.Status = "failed"
		if errors.Is(streamErr, context.Canceled) || errors.Is(c.Request.Context().Err(), context.Canceled) {
			record.Status = "cancelled"
		}
		record.ErrorCode = safeLLMError(streamErr).Code
	}
	// A disconnected client cancels the upstream immediately, but the bounded
	// independent save preserves the partial result and cancellation in history.
	saveCtx, saveCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer saveCancel()
	if err := s.repository.Finish(saveCtx, record); err != nil {
		_ = sendExplanationEvent(c, "error", gin.H{"code": "llm_history_save_failed", "message": "解释记录未能保存，请刷新确认。"})
		return
	}
	if streamErr != nil {
		failure := safeLLMError(streamErr)
		_ = sendExplanationEvent(c, "error", gin.H{"code": failure.Code, "message": failure.Message})
		return
	}
	_ = sendExplanationEvent(c, "done", record)
}

func startExplanationSSE(c *gin.Context, timeoutSeconds int) {
	_ = http.NewResponseController(c.Writer).SetWriteDeadline(time.Now().Add(time.Duration(timeoutSeconds+10) * time.Second))
	c.Header("Content-Type", "text/event-stream; charset=utf-8")
	c.Header("Cache-Control", "no-cache, no-transform")
	c.Header("X-Accel-Buffering", "no")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Status(http.StatusOK)
}

func sendExplanationEvent(c *gin.Context, event string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if _, err = fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event, encoded); err != nil {
		return err
	}
	return http.NewResponseController(c.Writer).Flush()
}

func (s *llmService) cached(c *gin.Context, record explanationRecord) {
	startExplanationSSE(c, 10)
	if err := sendExplanationEvent(c, "meta", record); err != nil {
		return
	}
	_ = sendExplanationEvent(c, "done", record)
}
