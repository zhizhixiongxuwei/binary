package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const sessionCookieName = "binary_session"

type currentUser struct {
	ID                 uint64 `json:"-"`
	PublicID           string `json:"id"`
	Username           string `json:"username"`
	Role               string `json:"role"`
	MustChangePassword bool   `json:"mustChangePassword"`
	CSRFToken          string `json:"csrfToken"`
}

type authService struct {
	db           *sql.DB
	secureCookie bool
}

func newAuthService(db *sql.DB, secureCookie bool) *authService {
	return &authService{db: db, secureCookie: secureCookie}
}

func (a *authService) login(c *gin.Context) {
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || request.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "credentials_required"})
		return
	}
	scope := strings.ToLower(request.Username) + "|" + c.ClientIP()
	blocked, err := a.isBlocked(c, scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authentication_unavailable"})
		return
	}
	if blocked {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "login_rate_limited"})
		return
	}

	var user currentUser
	var passwordHash string
	var active bool
	err = a.db.QueryRowContext(c, `SELECT id, public_id, username, password_hash, role, active, must_change_password
        FROM users WHERE username = ?`, request.Username).Scan(
		&user.ID, &user.PublicID, &user.Username, &passwordHash, &user.Role, &active, &user.MustChangePassword,
	)
	if err != nil || !active || bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(request.Password)) != nil {
		_ = a.recordFailure(c, scope)
		_ = a.audit(c, nil, "auth.login", "user", request.Username, "denied", nil)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
		return
	}
	_ = a.clearFailures(c, scope)

	token, tokenHash, err := secureToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session_creation_failed"})
		return
	}
	csrf, _, err := secureToken(24)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session_creation_failed"})
		return
	}
	sessionID, _, err := secureToken(18)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session_creation_failed"})
		return
	}
	expiresAt := time.Now().UTC().Add(12 * time.Hour)
	_, err = a.db.ExecContext(c, `INSERT INTO sessions
        (id, user_id, token_hash, csrf_token, client_ip, user_agent, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sessionID, user.ID, tokenHash[:], csrf, c.ClientIP(), truncateString(c.Request.UserAgent(), 512), expiresAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session_creation_failed"})
		return
	}
	user.CSRFToken = csrf
	a.setSessionCookie(c, token, expiresAt)
	_ = a.audit(c, &user.ID, "auth.login", "user", user.PublicID, "success", nil)
	c.JSON(http.StatusOK, gin.H{"user": user})
}

func (a *authService) logout(c *gin.Context) {
	user := mustCurrentUser(c)
	token, _ := c.Cookie(sessionCookieName)
	hash := sha256.Sum256([]byte(token))
	_, _ = a.db.ExecContext(c, "DELETE FROM sessions WHERE token_hash = ?", hash[:])
	a.clearSessionCookie(c)
	_ = a.audit(c, &user.ID, "auth.logout", "user", user.PublicID, "success", nil)
	c.Status(http.StatusNoContent)
}

func (a *authService) me(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"user": mustCurrentUser(c)})
}

func (a *authService) changePassword(c *gin.Context) {
	user := mustCurrentUser(c)
	var request struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || len(request.NewPassword) < 12 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_password_change"})
		return
	}
	var currentHash string
	if err := a.db.QueryRowContext(c, "SELECT password_hash FROM users WHERE id = ?", user.ID).Scan(&currentHash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "password_change_failed"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(request.CurrentPassword)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_current_password"})
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "password_change_failed"})
		return
	}
	tx, err := a.db.BeginTx(c, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "password_change_failed"})
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(c, `UPDATE users
        SET password_hash = ?, must_change_password = FALSE WHERE id = ?`, string(newHash), user.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "password_change_failed"})
		return
	}
	if _, err := tx.ExecContext(c, "DELETE FROM sessions WHERE user_id = ?", user.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "password_change_failed"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "password_change_failed"})
		return
	}
	a.clearSessionCookie(c)
	_ = a.audit(c, &user.ID, "auth.password.change", "user", user.PublicID, "success", nil)
	c.Status(http.StatusNoContent)
}

func (a *authService) authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie(sessionCookieName)
		if err != nil || token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication_required"})
			return
		}
		hash := sha256.Sum256([]byte(token))
		var user currentUser
		err = a.db.QueryRowContext(c, `SELECT u.id, u.public_id, u.username, u.role, u.must_change_password, s.csrf_token
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ? AND s.expires_at > UTC_TIMESTAMP(6) AND u.active = TRUE`, hash[:]).Scan(
			&user.ID, &user.PublicID, &user.Username, &user.Role, &user.MustChangePassword, &user.CSRFToken,
		)
		if err != nil {
			a.clearSessionCookie(c)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_session"})
			return
		}
		_, _ = a.db.ExecContext(context.Background(), `UPDATE sessions
            SET last_seen_at = UTC_TIMESTAMP(6) WHERE token_hash = ?`, hash[:])
		c.Set("currentUser", user)
		c.Next()
	}
}

func (a *authService) requireCSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := mustCurrentUser(c)
		if c.GetHeader("X-CSRF-Token") == "" || c.GetHeader("X-CSRF-Token") != user.CSRFToken {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "csrf_validation_failed"})
			return
		}
		c.Next()
	}
}

func (a *authService) isBlocked(ctx context.Context, scope string) (bool, error) {
	var blocked bool
	err := a.db.QueryRowContext(ctx, `SELECT blocked_until IS NOT NULL AND blocked_until > UTC_TIMESTAMP(6)
        FROM auth_limits WHERE scope_key = ?`, scope).Scan(&blocked)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return blocked, err
}

func (a *authService) recordFailure(ctx context.Context, scope string) error {
	_, err := a.db.ExecContext(ctx, `INSERT INTO auth_limits (scope_key, failure_count, blocked_until)
        VALUES (?, 1, NULL)
        ON DUPLICATE KEY UPDATE
          failure_count = IF(blocked_until IS NULL OR blocked_until <= UTC_TIMESTAMP(6), failure_count + 1, failure_count),
          blocked_until = IF(failure_count + 1 >= 5, DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 15 MINUTE), blocked_until)`, scope)
	return err
}

func (a *authService) clearFailures(ctx context.Context, scope string) error {
	_, err := a.db.ExecContext(ctx, "DELETE FROM auth_limits WHERE scope_key = ?", scope)
	return err
}

func (a *authService) audit(
	ctx context.Context,
	actor *uint64,
	action, objectType, objectID, outcome string,
	details any,
) error {
	_, err := a.db.ExecContext(ctx, `INSERT INTO audit_logs
        (actor_user_id, action, object_type, object_id, request_id, client_ip, outcome, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, actor, action, objectType, objectID,
		requestIDFromContext(ctx), clientIPFromContext(ctx), outcome, details)
	return err
}

func (a *authService) setSessionCookie(c *gin.Context, token string, expires time.Time) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *authService) clearSessionCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

func secureToken(size int) (string, [32]byte, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", [32]byte{}, fmt.Errorf("generate secure token: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(value)
	return encoded, sha256.Sum256([]byte(encoded)), nil
}

func mustCurrentUser(c *gin.Context) currentUser {
	value, exists := c.Get("currentUser")
	if !exists {
		panic("current user middleware is missing")
	}
	return value.(currentUser)
}

func truncateString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func requestIDFromContext(ctx context.Context) string {
	if c, ok := ctx.(*gin.Context); ok {
		return c.GetString("requestID")
	}
	return ""
}

func clientIPFromContext(ctx context.Context) string {
	if c, ok := ctx.(*gin.Context); ok {
		return c.ClientIP()
	}
	return ""
}
