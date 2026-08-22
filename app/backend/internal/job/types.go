package job

import "errors"

type Kind string

const (
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

type Claim struct {
	ID           uint64
	RunID        string
	Kind         Kind
	FencingToken uint64
	AttemptCount uint32
	MaxAttempts  uint32
	ResourcePool string
}

type Completion struct {
	RunStatus     string
	JobStatus     string
	AttemptStatus string
	ErrorCode     string
	ErrorMessage  string
}

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
