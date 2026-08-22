package main

import (
	"log"

	"binaryscan.local/backend/internal/decompiler"
	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/worker"
)

func main() {
	if err := worker.Run("native-decompiler", []job.Kind{job.KindNativeDecompile}, decompiler.Native); err != nil {
		log.Fatal(err)
	}
}
