package main

import (
	"log"

	"binaryscan.local/backend/internal/decompiler"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/worker"
)

func main() {
	if err := worker.Run("jvm-decompiler", []job.Kind{job.KindJVMDecompile}, decompiler.JVM); err != nil {
		log.Fatal(err)
	}
}
