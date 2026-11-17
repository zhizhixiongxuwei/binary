package decompiler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"binaryscan.local/backend/internal/job"
	"binaryscan.local/backend/internal/jvmarchive"
)

// Boot's libraries may include first-party code. Publish each selected module
// under a distinct prefix, rather than silently analyzing only BOOT-INF/classes.
func (e *Executor) runJVMArchive(ctx context.Context, workRoot, inputPath, format, inputSHA string) (toolResult, error) {
	if format != "jar" {
		result, err := e.runJVM(ctx, workRoot, inputPath, format)
		if err == nil && (format == "class" || format == "java-class") {
			if contextErr := jvmarchive.StageClassContext(inputPath, result.outputRoot, inputSHA); contextErr != nil {
				return toolResult{}, contextErr
			}
		}
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	prepared, err := jvmarchive.Prepare(ctx, inputPath, filepath.Join(workRoot, "archive"), jvmarchive.Options{
		ExpectedSHA256: inputSHA, ApplicationGroups: jvmarchive.GroupsFromEnvironment(),
		OnProgress: func(done, total int) {
			job.ReportProgress(ctx, "preparing", int64(done), int64(total), "modules")
		},
	})
	if err != nil {
		return toolResult{}, err
	}
	if prepared == nil {
		result, err := e.runJVM(ctx, workRoot, inputPath, format)
		if err != nil {
			return result, err
		}
		if err := jvmarchive.StageStandaloneContext(ctx, inputPath, result.outputRoot, inputSHA); err != nil {
			return toolResult{}, err
		}
		return result, nil
	}
	output := filepath.Join(workRoot, "modules-source")
	if err := os.MkdirAll(output, 0o700); err != nil {
		return toolResult{}, err
	}
	quality := "source"
	job.ReportProgress(ctx, "decompiling", 0, int64(len(prepared.Targets)), "modules")
	for index, target := range prepared.Targets {
		if err := ctx.Err(); err != nil {
			return toolResult{}, err
		}
		moduleWork := filepath.Join(workRoot, fmt.Sprintf("decompile-%04d", index))
		if err := os.MkdirAll(moduleWork, 0o700); err != nil {
			return toolResult{}, err
		}
		moduleCtx := job.WithModuleProgress(ctx, int64(index), int64(len(prepared.Targets)), target.EntryPath)
		libraries := make([]string, 0, len(prepared.Dependencies)+len(prepared.Targets))
		for _, unit := range append(append([]jvmarchive.Unit{}, prepared.Dependencies...), prepared.Targets...) {
			if unit.Path != target.Path {
				libraries = append(libraries, unit.Path)
			}
		}
		result, err := e.runJVM(moduleCtx, moduleWork, target.Path, "jar", libraries...)
		if err != nil {
			if ctx.Err() != nil {
				return toolResult{}, ctx.Err()
			}
			prepared.Scope.Diagnostics = append(prepared.Scope.Diagnostics, "Module decompilation failed: "+target.EntryPath)
			noteToolDiagnostic(ctx, "Module decompilation failed: "+target.EntryPath+": "+err.Error())
			quality = "partial_source"
			for moduleIndex := range prepared.Scope.Modules {
				if prepared.Scope.Modules[moduleIndex].EntryPath == target.EntryPath {
					prepared.Scope.Modules[moduleIndex].SourceStatus = "failed"
				}
			}
			job.ReportProgress(ctx, "decompiling", int64(index+1), int64(len(prepared.Targets)), "modules")
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
		job.ReportProgress(ctx, "decompiling", int64(index+1), int64(len(prepared.Targets)), "modules")
	}
	if len(prepared.Scope.Diagnostics) > 0 {
		quality = "partial_source"
	}
	if err := prepared.StageContext(ctx, inputPath, output); err != nil {
		return toolResult{}, fmt.Errorf("stage Java source context: %w", err)
	}
	// Per-module maps use overlapping JVM identities in some real archives. Until
	// a module-qualified map is available, retain bytecode findings as bytecode
	// locations instead of guessing which generated source they belong to.
	return toolResult{outputRoot: output, toolName: "vineflower", quality: quality, extension: ".java", jvmArchive: &prepared.Scope}, nil
}
