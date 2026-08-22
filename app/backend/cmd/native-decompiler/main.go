package main

import (
	"context"
	"log"

	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/worker"
)

func main() {
	executor := worker.ExecutorFunc(func(context.Context, job.Claim) error {
		return worker.ErrCapabilityPending
	})
	if err := worker.Run("native-decompiler", []job.Kind{job.KindNativeDecompile}, executor); err != nil {
		log.Fatal(err)
	}
}
