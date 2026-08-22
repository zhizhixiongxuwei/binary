package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"binaryscan.local/backend/internal/identity"

	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

const (
	adminJSONMaxBytes  = 64 << 10
	adminUserListLimit = 500
	auditDefaultLimit  = 100
	auditMaxLimit      = 500
	adminAuditRecorded = "adminAuditRecorded"
)

var adminUsernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

type adminService struct {
	db   *sql.DB
	auth *authService
}

type adminUser struct {
	ID                 string    `json:"id"`
	Username           string    `json:"username"`
	Role               string    `json:"role"`
	Active             bool      `json:"active"`
	MustChangePassword bool      `json:"mustChangePassword"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

type adminUserRecord struct {
	InternalID uint64
	User       adminUser
}

type createAdminUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type patchAdminUserRequest struct {
	Role     *string `json:"role"`
	Active   *bool   `json:"active"`
	Password *string `json:"password"`
}

type auditEntry struct {
	ID            uint64    `json:"id"`
	ActorID       any       `json:"actorId"`
	ActorUsername any       `json:"actorUsername"`
	Action        string    `json:"action"`
	ObjectType    any       `json:"objectType"`
	ObjectID      any       `json:"objectId"`
	RequestID     any       `json:"requestId"`
	ClientIP      any       `json:"clientIp"`
	Outcome       string    `json:"outcome"`
	Details       any       `json:"details"`
	CreatedAt     time.Time `json:"createdAt"`
}

type auditExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func newAdminService(db *sql.DB, auth *authService) *adminService {
	return &adminService{db: db, auth: auth}
}

func (s *adminService) listUsers(c *gin.Context) {
	rows, err := s.db.QueryContext(c, `SELECT public_id, username, role, active,
        must_change_password, created_at, updated_at
        FROM users ORDER BY username, id LIMIT ?`, adminUserListLimit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user_query_failed"})
		return
	}
	defer rows.Close()
	users := make([]adminUser, 0)
	for rows.Next() {
		var user adminUser
		if err := rows.Scan(&user.ID, &user.Username, &user.Role, &user.Active,
			&user.MustChangePassword, &user.CreatedAt, &user.UpdatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user_query_failed"})
			return
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user_query_failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

func (s *adminService) createUser(c *gin.Context) {
	const action = "admin.user.create"
	var request createAdminUserRequest
	if err := bindAdminJSON(c, &request); err != nil {
		s.rejectChange(c, http.StatusBadRequest, action, "", "invalid_user_request")
		return
	}
	username, err := normalizeAdminUsername(request.Username)
	if err != nil {
		s.rejectChange(c, http.StatusBadRequest, action, "", "invalid_username")
		return
	}
	role, ok := normalizeAdminRole(request.Role)
	if !ok {
		s.rejectChange(c, http.StatusBadRequest, action, username, "invalid_role")
		return
	}
	if err := validateAdminPassword(request.Password); err != nil {
		s.rejectChange(c, http.StatusBadRequest, action, username, "invalid_password")
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		s.failChange(c, action, username, "user_creation_failed", err)
		return
	}
	publicID, err := identity.UUID()
	if err != nil {
		s.failChange(c, action, username, "user_creation_failed", err)
		return
	}

	tx, err := s.db.BeginTx(c, nil)
	if err != nil {
		s.failChange(c, action, username, "user_creation_failed", err)
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(c, `INSERT INTO users
        (public_id, username, password_hash, role, active, must_change_password)
        VALUES (?, ?, ?, ?, TRUE, TRUE)`, publicID, username, string(passwordHash), role); err != nil {
		_ = tx.Rollback()
		if duplicateKey(err) {
			s.rejectChange(c, http.StatusConflict, action, username, "user_already_exists")
		} else {
			s.failChange(c, action, username, "user_creation_failed", err)
		}
		return
	}
	var user adminUser
	if err := tx.QueryRowContext(c, `SELECT public_id, username, role, active,
        must_change_password, created_at, updated_at FROM users WHERE public_id = ?`, publicID).Scan(
		&user.ID, &user.Username, &user.Role, &user.Active, &user.MustChangePassword,
		&user.CreatedAt, &user.UpdatedAt,
	); err != nil {
		_ = tx.Rollback()
		s.failChange(c, action, publicID, "user_creation_failed", err)
		return
	}
	actor := mustCurrentUser(c)
	if err := insertAdminAudit(c, tx, &actor.ID, action, "user", publicID, "success", map[string]any{
		"username": username, "role": role, "active": true, "mustChangePassword": true,
	}); err != nil {
		_ = tx.Rollback()
		s.failChange(c, action, publicID, "user_creation_failed", err)
		return
	}
	if err := tx.Commit(); err != nil {
		s.failChange(c, action, publicID, "user_creation_failed", err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"user": user})
}

func (s *adminService) patchUser(c *gin.Context) {
	const action = "admin.user.update"
	userID := strings.TrimSpace(c.Param("userID"))
	if len(userID) != 36 || strings.ContainsRune(userID, '\x00') {
		s.rejectChange(c, http.StatusBadRequest, action, "", "invalid_user_id")
		return
	}
	var request patchAdminUserRequest
	if err := bindAdminJSON(c, &request); err != nil ||
		(request.Role == nil && request.Active == nil && request.Password == nil) {
		s.rejectChange(c, http.StatusBadRequest, action, userID, "invalid_user_update")
		return
	}
	var requestedRole string
	if request.Role != nil {
		role, ok := normalizeAdminRole(*request.Role)
		if !ok {
			s.rejectChange(c, http.StatusBadRequest, action, userID, "invalid_role")
			return
		}
		requestedRole = role
	}
	var passwordHash []byte
	if request.Password != nil {
		if err := validateAdminPassword(*request.Password); err != nil {
			s.rejectChange(c, http.StatusBadRequest, action, userID, "invalid_password")
			return
		}
		var err error
		passwordHash, err = bcrypt.GenerateFromPassword([]byte(*request.Password), bcrypt.DefaultCost)
		if err != nil {
			s.failChange(c, action, userID, "user_update_failed", err)
			return
		}
	}

	tx, err := s.db.BeginTx(c, nil)
	if err != nil {
		s.failChange(c, action, userID, "user_update_failed", err)
		return
	}
	defer tx.Rollback()
	activeAdministrators, err := lockActiveAdministrators(c, tx)
	if err != nil {
		_ = tx.Rollback()
		s.failChange(c, action, userID, "user_update_failed", err)
		return
	}
	target, err := loadAdminUserForUpdate(c, tx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		s.rejectChange(c, http.StatusNotFound, action, userID, "user_not_found")
		return
	}
	if err != nil {
		_ = tx.Rollback()
		s.failChange(c, action, userID, "user_update_failed", err)
		return
	}
	actor := mustCurrentUser(c)
	newRole := target.User.Role
	if request.Role != nil {
		newRole = requestedRole
	}
	newActive := target.User.Active
	if request.Active != nil {
		newActive = *request.Active
	}
	if target.InternalID == actor.ID && (!newActive || newRole != "administrator") {
		_ = tx.Rollback()
		s.rejectChange(c, http.StatusConflict, action, userID, "self_protection")
		return
	}
	if resultingActiveAdministrators(activeAdministrators, target.User.Role, target.User.Active, newRole, newActive) < 1 {
		_ = tx.Rollback()
		s.rejectChange(c, http.StatusConflict, action, userID, "last_active_administrator")
		return
	}

	query := "UPDATE users SET role = ?, active = ?"
	arguments := []any{newRole, newActive}
	if request.Password != nil {
		query += ", password_hash = ?, must_change_password = TRUE"
		arguments = append(arguments, string(passwordHash))
	}
	query += " WHERE id = ?"
	arguments = append(arguments, target.InternalID)
	if _, err := tx.ExecContext(c, query, arguments...); err != nil {
		_ = tx.Rollback()
		s.failChange(c, action, userID, "user_update_failed", err)
		return
	}
	if _, err := tx.ExecContext(c, "DELETE FROM sessions WHERE user_id = ?", target.InternalID); err != nil {
		_ = tx.Rollback()
		s.failChange(c, action, userID, "user_update_failed", err)
		return
	}
	details := map[string]any{
		"previousRole":    target.User.Role,
		"role":            newRole,
		"previousActive":  target.User.Active,
		"active":          newActive,
		"passwordReset":   request.Password != nil,
		"sessionsRevoked": true,
	}
	if err := insertAdminAudit(c, tx, &actor.ID, action, "user", userID, "success", details); err != nil {
		_ = tx.Rollback()
		s.failChange(c, action, userID, "user_update_failed", err)
		return
	}
	updated, err := loadAdminUser(c, tx, userID)
	if err != nil {
		_ = tx.Rollback()
		s.failChange(c, action, userID, "user_update_failed", err)
		return
	}
	if err := tx.Commit(); err != nil {
		s.failChange(c, action, userID, "user_update_failed", err)
		return
	}
	if target.InternalID == actor.ID {
		s.auth.clearSessionCookie(c)
	}
	c.JSON(http.StatusOK, gin.H{"user": updated.User})
}

func (s *adminService) listAudit(c *gin.Context) {
	limit, beforeID, err := parseAuditPage(c.Request.URL.Query())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_audit_page"})
		return
	}
	rows, err := s.db.QueryContext(c, `SELECT a.id, u.public_id, u.username, a.action,
        a.object_type, a.object_id, a.request_id, a.client_ip, a.outcome, a.details, a.created_at
        FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id
        WHERE (? = 0 OR a.id < ?) ORDER BY a.id DESC LIMIT ?`, beforeID, beforeID, limit+1)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "audit_query_failed"})
		return
	}
	defer rows.Close()
	entries := make([]auditEntry, 0, limit)
	for rows.Next() {
		var entry auditEntry
		var actorID, actorUsername, objectType, objectID, requestID, clientIP sql.NullString
		var details []byte
		if err := rows.Scan(&entry.ID, &actorID, &actorUsername, &entry.Action, &objectType,
			&objectID, &requestID, &clientIP, &entry.Outcome, &details, &entry.CreatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "audit_query_failed"})
			return
		}
		entry.ActorID = nullableString(actorID)
		entry.ActorUsername = nullableString(actorUsername)
		entry.ObjectType = nullableString(objectType)
		entry.ObjectID = nullableString(objectID)
		entry.RequestID = nullableString(requestID)
		entry.ClientIP = nullableString(clientIP)
		if len(details) != 0 {
			_ = json.Unmarshal(details, &entry.Details)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "audit_query_failed"})
		return
	}
	var nextBeforeID any
	if len(entries) > limit {
		entries = entries[:limit]
		nextBeforeID = entries[len(entries)-1].ID
	}
	c.JSON(http.StatusOK, gin.H{"entries": entries, "nextBeforeId": nextBeforeID})
}

func requireAdministrator() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := mustCurrentUser(c)
		if user.MustChangePassword {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "password_change_required"})
			return
		}
		if user.Role != "administrator" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "operation_not_allowed"})
			return
		}
		c.Next()
	}
}

func (s *adminService) auditRejectedMutation(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if c.Writer.Status() < http.StatusBadRequest || c.GetBool(adminAuditRecorded) {
			return
		}
		actor := mustCurrentUser(c)
		objectID := ""
		if action == "admin.user.update" {
			objectID = c.Param("userID")
		}
		outcome := "denied"
		reason := "request_rejected_before_handler"
		if c.Writer.Status() >= http.StatusInternalServerError {
			outcome = "failed"
			reason = "request_failed_before_handler"
		}
		if err := insertAdminAudit(c, s.db, &actor.ID, action, "user", objectID, outcome,
			map[string]string{"reason": reason}); err != nil {
			slog.Error("record rejected administrator request", "request_id", c.GetString("requestID"), "error", err)
		}
	}
}

func bindAdminJSON(c *gin.Context, destination any) error {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, adminJSONMaxBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("request contains trailing JSON")
	}
	return nil
}

func normalizeAdminUsername(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !adminUsernamePattern.MatchString(value) {
		return "", fmt.Errorf("username must use 3-64 lowercase ASCII characters")
	}
	return value, nil
}

func normalizeAdminRole(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "reader", "operator", "administrator":
		return value, true
	default:
		return "", false
	}
}

func validateAdminPassword(value string) error {
	if len(value) < 12 || len(value) > 72 {
		return fmt.Errorf("password must contain 12-72 bytes")
	}
	return nil
}

func parseAuditPage(values url.Values) (int, uint64, error) {
	limit := auditDefaultLimit
	if raw := strings.TrimSpace(values.Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > auditMaxLimit {
			return 0, 0, fmt.Errorf("invalid audit limit")
		}
		limit = value
	}
	var beforeID uint64
	if raw := strings.TrimSpace(values.Get("beforeId")); raw != "" {
		value, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || value == 0 {
			return 0, 0, fmt.Errorf("invalid audit cursor")
		}
		beforeID = value
	}
	return limit, beforeID, nil
}

func lockActiveAdministrators(ctx context.Context, tx *sql.Tx) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM users
        WHERE role = 'administrator' AND active = TRUE ORDER BY id FOR UPDATE`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		count++
	}
	return count, rows.Err()
}

func loadAdminUserForUpdate(ctx context.Context, tx *sql.Tx, publicID string) (adminUserRecord, error) {
	return loadAdminUserQuery(ctx, tx, publicID, true)
}

func loadAdminUser(ctx context.Context, tx *sql.Tx, publicID string) (adminUserRecord, error) {
	return loadAdminUserQuery(ctx, tx, publicID, false)
}

func loadAdminUserQuery(ctx context.Context, tx *sql.Tx, publicID string, forUpdate bool) (adminUserRecord, error) {
	query := `SELECT id, public_id, username, role, active, must_change_password, created_at, updated_at
        FROM users WHERE public_id = ?`
	if forUpdate {
		query += " FOR UPDATE"
	}
	var record adminUserRecord
	err := tx.QueryRowContext(ctx, query, publicID).Scan(&record.InternalID, &record.User.ID,
		&record.User.Username, &record.User.Role, &record.User.Active, &record.User.MustChangePassword,
		&record.User.CreatedAt, &record.User.UpdatedAt)
	return record, err
}

func resultingActiveAdministrators(current int, oldRole string, oldActive bool, newRole string, newActive bool) int {
	if oldRole == "administrator" && oldActive {
		current--
	}
	if newRole == "administrator" && newActive {
		current++
	}
	return current
}

func insertAdminAudit(
	ctx *gin.Context,
	executor auditExecutor,
	actor *uint64,
	action, objectType, objectID, outcome string,
	details any,
) error {
	var encoded any
	if details != nil {
		body, err := json.Marshal(details)
		if err != nil {
			return err
		}
		encoded = body
	}
	_, err := executor.ExecContext(ctx, `INSERT INTO audit_logs
        (actor_user_id, action, object_type, object_id, request_id, client_ip, outcome, details)
        VALUES (?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?)`, actor, action, objectType,
		truncateString(objectID, 64), ctx.GetString("requestID"), ctx.ClientIP(), outcome, encoded)
	if err == nil {
		ctx.Set(adminAuditRecorded, true)
	}
	return err
}

func (s *adminService) rejectChange(c *gin.Context, status int, action, objectID, code string) {
	actor := mustCurrentUser(c)
	if err := insertAdminAudit(c, s.db, &actor.ID, action, "user", objectID, "denied",
		map[string]string{"reason": code}); err != nil {
		slog.Error("record denied administrator change", "request_id", c.GetString("requestID"), "error", err)
	}
	c.JSON(status, gin.H{"error": code})
}

func (s *adminService) failChange(c *gin.Context, action, objectID, code string, cause error) {
	actor := mustCurrentUser(c)
	if err := insertAdminAudit(c, s.db, &actor.ID, action, "user", objectID, "failed",
		map[string]string{"reason": code}); err != nil {
		slog.Error("record failed administrator change", "request_id", c.GetString("requestID"), "error", err)
	}
	slog.Error("administrator change failed", "request_id", c.GetString("requestID"), "action", action, "error", cause)
	c.JSON(http.StatusInternalServerError, gin.H{"error": code})
}

func duplicateKey(err error) bool {
	var mysqlError *mysql.MySQLError
	return errors.As(err, &mysqlError) && mysqlError.Number == 1062
}
