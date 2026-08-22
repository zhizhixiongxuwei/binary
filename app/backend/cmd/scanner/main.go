package main

import (
	"log"

	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/scanner"
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
	if err := worker.Run("scanner", kinds, scanner.New); err != nil {
		log.Fatal(err)
	}
}
