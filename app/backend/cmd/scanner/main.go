package main

import (
	"context"
	"log"

	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/worker"
)

func main() {
	kinds := []job.Kind{
		job.KindScan,
		job.KindArchiveImport,
		job.KindTrivyScan,
		job.KindCCheck,
		job.KindJavaCheck,
		job.KindPythonCheck,
	}
	executor := worker.ExecutorFunc(func(context.Context, job.Claim) error {
		return worker.ErrCapabilityPending
	})
	if err := worker.Run("scanner", kinds, executor); err != nil {
		log.Fatal(err)
	}
}
