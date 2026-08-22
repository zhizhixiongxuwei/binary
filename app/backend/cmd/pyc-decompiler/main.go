package main

import (
	"log"

	"binaryscan.local/backend/internal/decompiler"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/worker"
)

func main() {
	if err := worker.Run("pyc-decompiler", []job.Kind{job.KindPYCDecompile}, decompiler.PYC); err != nil {
		log.Fatal(err)
	}
}
