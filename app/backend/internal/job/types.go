package job

import (
	"errors"
	"time"
)

type Kind string

const (
	// Kind 是跨进程持久化协议的一部分；每个值都映射到唯一资源池和具备对应工具能力的 Worker。
	KindScan            Kind = "scan"
	KindArchiveImport   Kind = "archive_import"
	KindTrivyScan       Kind = "trivy_scan"
	KindNativeDecompile Kind = "native_decompile"
	KindJVMDecompile    Kind = "jvm_decompile"
	KindPYCDecompile    Kind = "pyc_decompile"
	KindCCheck          Kind = "c_check"
	KindJavaCheck       Kind = "java_check"
	KindPythonCheck     Kind = "python_check"
)

var ErrFenceLost = errors.New("job lease or fencing token is no longer valid")

type RetryableError struct {
	Err   error
	Delay time.Duration
}

func (e *RetryableError) Error() string { return e.Err.Error() }
func (e *RetryableError) Unwrap() error { return e.Err }

func Retryable(err error, delay time.Duration) error {
	return &RetryableError{Err: err, Delay: delay}
}

// Claim 是某次租约的不可变凭据。FencingToken 每次重新领取都会递增，旧 Worker 即使迟到
// 也无法完成或发布新一代任务；ResourcePool 记录本次同时占用的持久化并发槽。
type Claim struct {
	ID           uint64
	RunID        string
	Kind         Kind
	FencingToken uint64
	AttemptCount uint32
	MaxAttempts  uint32
	CreatedAt    time.Time
	ResourcePool string
}

type Completion struct {
	RunStatus     string
	JobStatus     string
	AttemptStatus string
	ErrorCode     string
	ErrorMessage  string
}

// PoolForKind 把业务任务映射到独立并发预算。归档与普通识别共享 scanner 池，Trivy、
// 三个反编译工具及三种源码检查分别限流，避免一种重任务耗尽整个系统。
func PoolForKind(kind Kind) (string, bool) {
	switch kind {
	case KindScan, KindArchiveImport:
		return "scanner", true
	case KindTrivyScan:
		return "trivy", true
	case KindNativeDecompile:
		return "native", true
	case KindJVMDecompile:
		return "jvm", true
	case KindPYCDecompile:
		return "pyc", true
	case KindCCheck:
		return "c-check", true
	case KindJavaCheck:
		return "java-check", true
	case KindPythonCheck:
		return "python-check", true
	default:
		return "", false
	}
}
