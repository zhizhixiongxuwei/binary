package decompiler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"binaryscan.local/backend/internal/jvmarchive"
)

// Boot's libraries may include first-party code. Publish each selected module
// under a distinct prefix, rather than silently analyzing only BOOT-INF/classes.
func (e *Executor) runJVMArchive(ctx context.Context, workRoot, inputPath, format, inputSHA string) (toolResult, error) {
	if format != "jar" {
		return e.runJVM(ctx, workRoot, inputPath, format)
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	prepared, err := jvmarchive.Prepare(ctx, inputPath, filepath.Join(workRoot, "archive"), jvmarchive.Options{ExpectedSHA256: inputSHA, ApplicationGroups: jvmarchive.GroupsFromEnvironment()})
	if err != nil {
		return toolResult{}, err
	}
	if prepared == nil {
		return e.runJVM(ctx, workRoot, inputPath, format)
	}
	output := filepath.Join(workRoot, "modules-source")
	if err := os.MkdirAll(output, 0o700); err != nil {
		return toolResult{}, err
	}
	quality := "source"
	for index, target := range prepared.Targets {
		if err := ctx.Err(); err != nil {
			return toolResult{}, err
		}
		moduleWork := filepath.Join(workRoot, fmt.Sprintf("decompile-%04d", index))
		if err := os.MkdirAll(moduleWork, 0o700); err != nil {
			return toolResult{}, err
		}
		result, err := e.runJVM(ctx, moduleWork, target.Path, "jar")
		if err != nil {
			if ctx.Err() != nil {
				return toolResult{}, ctx.Err()
			}
			prepared.Scope.Diagnostics = append(prepared.Scope.Diagnostics, "Module decompilation failed: "+target.EntryPath)
			quality = "partial_source"
			for moduleIndex := range prepared.Scope.Modules {
				if prepared.Scope.Modules[moduleIndex].EntryPath == target.EntryPath {
					prepared.Scope.Modules[moduleIndex].SourceStatus = "failed"
				}
			}
			continue
		}
		for moduleIndex := range prepared.Scope.Modules {
			if prepared.Scope.Modules[moduleIndex].EntryPath == target.EntryPath {
				prepared.Scope.Modules[moduleIndex].SourceStatus = result.quality
				prepared.Scope.Modules[moduleIndex].Decompiler = result.toolName
			}
		}
		if result.quality != "source" {
			quality = "partial_source"
		}
		destination := filepath.Join(output, filepath.FromSlash(target.SourcePrefix))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return toolResult{}, err
		}
		if err := os.Rename(result.outputRoot, destination); err != nil {
			return toolResult{}, err
		}
	}
	if len(prepared.Scope.Diagnostics) > 0 {
		quality = "partial_source"
	}
	// Per-module maps use overlapping JVM identities in some real archives. Until
	// a module-qualified map is available, retain bytecode findings as bytecode
	// locations instead of guessing which generated source they belong to.
	return toolResult{outputRoot: output, toolName: "vineflower", quality: quality, extension: ".java", jvmArchive: &prepared.Scope}, nil
}
