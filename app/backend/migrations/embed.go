package migrations

import "embed"

// FS contains the immutable SQL migration sequence.
//
//go:embed *.sql
var FS embed.FS
