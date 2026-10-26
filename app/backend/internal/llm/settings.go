// Package llm holds server-side LLM configuration and the bounded streaming client.
package llm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
)

const (
	MaxInputChars    = 200000
	MaxOutputChars   = 24000
	maxSettingsBytes = 64 << 10
)

// Error contains only messages safe to return to clients. Provider response bodies
// and request headers are deliberately never included.
type Error struct {
	Code       string
	Message    string
	HTTPStatus int
	cause      error
}

func (e *Error) Error() string { return e.Message }
func (e *Error) Unwrap() error { return e.cause }

func fail(code, message string, status int) *Error {
	return &Error{Code: code, Message: message, HTTPStatus: status}
}

type Settings struct {
	Enabled         bool   `json:"enabled"`
	Configured      bool   `json:"configured"`
	Provider        string `json:"provider"`
	BaseURL         string `json:"baseUrl"`
	Model           string `json:"model"`
	MaxInputChars   int    `json:"maxInputChars"`
	TimeoutSeconds  int    `json:"timeoutSeconds"`
	MaxConcurrent   int    `json:"maxConcurrent"`
	MaxOutputTokens int    `json:"maxOutputTokens"`
	APIKeyMasked    string `json:"apiKeyMasked"`
}

// Snapshot is for backend use only. Encoding it as JSON never exposes the key.
type Snapshot struct {
	Settings
	APIKey string `json:"-"`
}

// Pointer fields make a partial settings update preserve omitted values.
type UpdateSettings struct {
	Enabled         *bool   `json:"enabled"`
	Provider        *string `json:"provider"`
	BaseURL         *string `json:"baseUrl"`
	Model           *string `json:"model"`
	MaxInputChars   *int    `json:"maxInputChars"`
	TimeoutSeconds  *int    `json:"timeoutSeconds"`
	MaxConcurrent   *int    `json:"maxConcurrent"`
	MaxOutputTokens *int    `json:"maxOutputTokens"`
	APIKey          *string `json:"apiKey"`
	ClearAPIKey     bool    `json:"clearApiKey"`
}

type Manager struct {
	mu       sync.RWMutex
	dir      string
	settings Settings
	apiKey   string
}

type savedSettings struct {
	Version         int      `json:"version"`
	Settings        Settings `json:"settings"`
	EncryptedAPIKey string   `json:"encryptedApiKey,omitempty"`
}

func defaults() Settings {
	return Settings{Provider: "deepseek", BaseURL: "https://api.deepseek.com", Model: "deepseek-flash", MaxInputChars: 30000, TimeoutSeconds: 90, MaxConcurrent: 2, MaxOutputTokens: 4096}
}

func New(storageRoot string) (*Manager, error) {
	if strings.TrimSpace(storageRoot) == "" {
		return nil, fail("llm_settings_unavailable", "大模型配置存储目录无效", 500)
	}
	m := &Manager{dir: filepath.Join(storageRoot, ".settings"), settings: defaults()}
	if err := os.MkdirAll(m.dir, 0700); err != nil {
		return nil, storageError()
	}
	if err := regularPath(m.dir, true); err != nil {
		return nil, storageError()
	}
	if err := os.Chmod(m.dir, 0700); err != nil {
		return nil, storageError()
	}
	path := filepath.Join(m.dir, "llm.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	data, err := readPrivateFile(path, maxSettingsBytes)
	if err != nil {
		return nil, storageError()
	}
	var saved savedSettings
	if json.Unmarshal(data, &saved) != nil || saved.Version != 1 {
		return nil, storageError()
	}
	if err := validateSettings(&saved.Settings); err != nil {
		return nil, storageError()
	}
	if saved.EncryptedAPIKey != "" {
		key, err := m.masterKey(false)
		if err != nil {
			return nil, storageError()
		}
		m.apiKey, err = decryptSecret(key, saved.EncryptedAPIKey)
		if err != nil {
			return nil, storageError()
		}
		if !validAPIKey(m.apiKey) {
			return nil, storageError()
		}
	}
	m.settings = saved.Settings
	return m, nil
}

func storageError() *Error {
	return fail("llm_settings_unavailable", "大模型配置无法安全读取或保存，请检查服务存储目录权限", 500)
}

func publicSettings(s Settings, key string) Settings {
	s.Configured = key != ""
	s.APIKeyMasked = ""
	if s.Configured {
		s.APIKeyMasked = "********"
	}
	return s
}

func (m *Manager) Get() Settings {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return publicSettings(m.settings, m.apiKey)
}

func (m *Manager) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Snapshot{Settings: publicSettings(m.settings, m.apiKey), APIKey: m.apiKey}
}

func (m *Manager) Update(u UpdateSettings) (Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, key := m.settings, m.apiKey
	if u.Enabled != nil {
		s.Enabled = *u.Enabled
	}
	if u.Provider != nil {
		s.Provider = *u.Provider
	}
	if u.BaseURL != nil {
		s.BaseURL = *u.BaseURL
	}
	if u.Model != nil {
		s.Model = *u.Model
	}
	if u.MaxInputChars != nil {
		s.MaxInputChars = *u.MaxInputChars
	}
	if u.TimeoutSeconds != nil {
		s.TimeoutSeconds = *u.TimeoutSeconds
	}
	if u.MaxConcurrent != nil {
		s.MaxConcurrent = *u.MaxConcurrent
	}
	if u.MaxOutputTokens != nil {
		s.MaxOutputTokens = *u.MaxOutputTokens
	}
	if err := validateSettings(&s); err != nil {
		return Settings{}, err
	}
	if u.ClearAPIKey && u.APIKey != nil && strings.TrimSpace(*u.APIKey) != "" {
		return Settings{}, fail("llm_invalid_settings", "不能同时清空和设置 API Key", 400)
	}
	if u.ClearAPIKey {
		key = ""
	}
	if u.APIKey != nil && strings.TrimSpace(*u.APIKey) != "" {
		key = strings.TrimSpace(*u.APIKey)
		if !validAPIKey(key) {
			return Settings{}, fail("llm_invalid_settings", "API Key 格式无效", 400)
		}
	}
	saved := savedSettings{Version: 1, Settings: s}
	saved.Settings.Configured = false
	saved.Settings.APIKeyMasked = ""
	if key != "" {
		master, err := m.masterKey(true)
		if err != nil {
			return Settings{}, storageError()
		}
		secret, err := encryptSecret(master, key)
		if err != nil {
			return Settings{}, storageError()
		}
		saved.EncryptedAPIKey = secret
	}
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return Settings{}, storageError()
	}
	if err := writePrivateFile(m.dir, "llm.json", data); err != nil {
		return Settings{}, storageError()
	}
	m.settings, m.apiKey = s, key
	return publicSettings(s, key), nil
}

func validateSettings(s *Settings) error {
	s.Provider = strings.ToLower(strings.TrimSpace(s.Provider))
	s.Model = strings.TrimSpace(s.Model)
	s.BaseURL = strings.TrimRight(strings.TrimSpace(s.BaseURL), "/")
	if s.Provider != "deepseek" && s.Provider != "openai-compatible" && s.Provider != "openai" {
		return fail("llm_invalid_settings", "不支持的大模型服务类型", 400)
	}
	u, err := url.Parse(s.BaseURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return fail("llm_invalid_settings", "API 地址必须是无凭证、查询参数和片段的 HTTP(S) 地址", 400)
	}
	if len(s.BaseURL) > 2048 || strings.IndexFunc(s.BaseURL, unicode.IsControl) >= 0 || s.Model == "" || len(s.Model) > 200 || strings.IndexFunc(s.Model, unicode.IsControl) >= 0 {
		return fail("llm_invalid_settings", "API 地址或模型名称无效", 400)
	}
	if s.MaxInputChars < 256 || s.MaxInputChars > MaxInputChars {
		return fail("llm_invalid_settings", "输入字符限制必须在 256 到 200000 之间", 400)
	}
	if s.TimeoutSeconds < 5 || s.TimeoutSeconds > 600 {
		return fail("llm_invalid_settings", "超时必须在 5 到 600 秒之间", 400)
	}
	if s.MaxConcurrent < 1 || s.MaxConcurrent > 8 {
		return fail("llm_invalid_settings", "并发限制必须在 1 到 8 之间", 400)
	}
	if s.MaxOutputTokens < 128 || s.MaxOutputTokens > 16384 {
		return fail("llm_invalid_settings", "输出 token 限制必须在 128 到 16384 之间", 400)
	}
	return nil
}

func validAPIKey(key string) bool {
	return key != "" && len(key) <= 4096 && strings.IndexFunc(key, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) < 0
}

func regularPath(path string, dir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || (dir && !info.IsDir()) || (!dir && !info.Mode().IsRegular()) {
		return fmt.Errorf("unsafe settings path")
	}
	return nil
}

func readPrivateFile(path string, limit int64) ([]byte, error) {
	if err := regularPath(path, false); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("settings file too large")
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return data, nil
}

func writePrivateFile(dir, name string, data []byte) error {
	if err := regularPath(dir, true); err != nil {
		return err
	}
	dst := filepath.Join(dir, name)
	if _, err := os.Lstat(dst); err == nil {
		if err := regularPath(dst, false); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(dir, ".llm-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), dst)
}

func (m *Manager) masterKey(create bool) ([]byte, error) {
	if err := regularPath(m.dir, true); err != nil {
		return nil, err
	}
	path := filepath.Join(m.dir, "llm-master.key")
	key, err := readPrivateFile(path, 32)
	if err == nil {
		if len(key) != 32 {
			return nil, fmt.Errorf("invalid master key")
		}
		return key, nil
	}
	if !create || !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return m.masterKey(false)
	}
	if err != nil {
		return nil, err
	}
	_, writeErr := f.Write(key)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return key, nil
}

func aead(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func encryptSecret(key []byte, secret string) (string, error) {
	c, err := aead(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, c.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	data := c.Seal(nonce, nonce, []byte(secret), []byte("binaryscan/llm/v1"))
	return base64.StdEncoding.EncodeToString(data), nil
}

func decryptSecret(key []byte, value string) (string, error) {
	c, err := aead(key)
	if err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(data) < c.NonceSize() {
		return "", fmt.Errorf("invalid encrypted key")
	}
	plain, err := c.Open(nil, data[:c.NonceSize()], data[c.NonceSize():], []byte("binaryscan/llm/v1"))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
