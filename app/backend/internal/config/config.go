package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Database struct {
	Host     string
	Port     string
	Name     string
	User     string
	Password string
}

type App struct {
	ListenAddr           string
	PublicBaseURL        string
	TLSMode              string
	TLSCertFile          string
	TLSKeyFile           string
	TrustedProxyCIDRs    []string
	AllowedOrigins       []string
	InitialAdminUser     string
	InitialAdminPassword string
	StorageRoot          string
	UploadMaxBytes       int64
}

type Worker struct {
	WorkRoot         string
	BlobRoot         string
	ProjectRoot      string
	Lease            time.Duration
	Heartbeat        time.Duration
	Poll             time.Duration
	CCheckerURL      string
	JavaCheckerURL   string
	PythonCheckerURL string
	SlotCounts       map[string]int
}

type Config struct {
	Version  string
	Role     string
	Database Database
	App      App
	Worker   Worker
}

func Load(role string) (Config, error) {
	if role == "" {
		role = strings.TrimSpace(os.Getenv("BINARY_ROLE"))
	}
	if role == "" {
		return Config{}, errors.New("BINARY_ROLE is required")
	}

	cfg := Config{
		Version: valueOr("BINARY_VERSION", "dev"),
		Role:    role,
		Database: Database{
			Host:     valueOr("BINARY_DB_HOST", "mysql"),
			Port:     valueOr("BINARY_DB_PORT", "3306"),
			Name:     strings.TrimSpace(os.Getenv("BINARY_DB_NAME")),
			User:     strings.TrimSpace(os.Getenv("BINARY_DB_USER")),
			Password: os.Getenv("BINARY_DB_PASSWORD"),
		},
		App: App{
			ListenAddr:           valueOr("BINARY_LISTEN_ADDR", ":8443"),
			PublicBaseURL:        strings.TrimSpace(os.Getenv("BINARY_PUBLIC_BASE_URL")),
			TLSMode:              valueOr("BINARY_TLS_MODE", "direct"),
			TLSCertFile:          strings.TrimSpace(os.Getenv("BINARY_TLS_CERT_FILE")),
			TLSKeyFile:           strings.TrimSpace(os.Getenv("BINARY_TLS_KEY_FILE")),
			TrustedProxyCIDRs:    csv("BINARY_TRUSTED_PROXY_CIDRS"),
			AllowedOrigins:       csv("BINARY_ALLOWED_ORIGINS"),
			InitialAdminUser:     strings.TrimSpace(os.Getenv("BINARY_INITIAL_ADMIN_USERNAME")),
			InitialAdminPassword: os.Getenv("BINARY_INITIAL_ADMIN_PASSWORD"),
			StorageRoot:          valueOr("BINARY_STORAGE_ROOT", "/data/storage"),
			UploadMaxBytes:       int64Value("BINARY_UPLOAD_MAX_BYTES", 2<<30),
		},
		Worker: Worker{
			WorkRoot:         valueOr("BINARY_WORK_ROOT", "/data/work"),
			BlobRoot:         valueOr("BINARY_BLOB_ROOT", "/data/storage/blobs"),
			ProjectRoot:      valueOr("BINARY_PROJECT_ROOT", "/data/storage/projects"),
			Lease:            durationSeconds("BINARY_JOB_LEASE_SECONDS", 60),
			Heartbeat:        durationSeconds("BINARY_JOB_HEARTBEAT_SECONDS", 15),
			Poll:             durationMilliseconds("BINARY_JOB_POLL_MILLISECONDS", 1000),
			CCheckerURL:      strings.TrimSpace(os.Getenv("BINARY_C_CHECKER_URL")),
			JavaCheckerURL:   strings.TrimSpace(os.Getenv("BINARY_JAVA_CHECKER_URL")),
			PythonCheckerURL: strings.TrimSpace(os.Getenv("BINARY_PYTHON_CHECKER_URL")),
			SlotCounts: map[string]int{
				"scanner":      intValue("BINARY_SLOT_SCANNER", 1),
				"trivy":        intValue("BINARY_SLOT_TRIVY", 1),
				"native":       intValue("BINARY_SLOT_NATIVE", 1),
				"jvm":          intValue("BINARY_SLOT_JVM", 1),
				"pyc":          intValue("BINARY_SLOT_PYC", 1),
				"c-check":      intValue("BINARY_SLOT_C_CHECK", 1),
				"java-check":   intValue("BINARY_SLOT_JAVA_CHECK", 1),
				"python-check": intValue("BINARY_SLOT_PYTHON_CHECK", 1),
			},
		},
	}

	if cfg.Database.Name == "" || cfg.Database.User == "" || cfg.Database.Password == "" {
		return Config{}, errors.New("database configuration is incomplete")
	}
	if role == "app" {
		if err := cfg.validateApp(); err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

func (c Config) validateApp() error {
	if c.App.PublicBaseURL == "" {
		return errors.New("BINARY_PUBLIC_BASE_URL is required")
	}
	if c.App.InitialAdminUser == "" || len(c.App.InitialAdminPassword) < 16 {
		return errors.New("initial administrator credentials are invalid")
	}
	switch c.App.TLSMode {
	case "direct":
		if c.App.TLSCertFile == "" || c.App.TLSKeyFile == "" {
			return errors.New("direct TLS requires certificate and key paths")
		}
	case "proxy", "http":
	default:
		return fmt.Errorf("unsupported BINARY_TLS_MODE %q", c.App.TLSMode)
	}
	return nil
}

func valueOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func csv(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func intValue(key string, fallback int) int {
	value, err := strconv.Atoi(valueOr(key, strconv.Itoa(fallback)))
	if err != nil || value < 0 {
		return fallback
	}
	return value
}

func int64Value(key string, fallback int64) int64 {
	value, err := strconv.ParseInt(valueOr(key, strconv.FormatInt(fallback, 10)), 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func durationSeconds(key string, fallback int) time.Duration {
	return time.Duration(intValue(key, fallback)) * time.Second
}

func durationMilliseconds(key string, fallback int) time.Duration {
	return time.Duration(intValue(key, fallback)) * time.Millisecond
}
