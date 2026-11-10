package scanner

import (
	"maps"
	"strings"

	"binaryscan.local/backend/internal/storage"
)

type jvmInstruction struct {
	className, methodName, methodDescriptor string
	offset                                  int
}

type decompiledLine struct {
	path string
	line int
}

type mappedDereference struct {
	decompiledLine
	kind, member string
}

type spotBugsSourceCorrelation struct {
	lines       []decompiledLine
	merged      []bool
	mergedCount int
}

// Correlate only exact instructions within this one verified decompilation.
// A line can contain both compiler-generated instructions and several source
// expressions. Merging also requires a unique source instruction and expression
// of the matching kind and member.
func correlateSpotBugsFindings(source []validatedCheckerFinding, bytecode spotBugsResponse, locations []storage.JVMSourceLocation) spotBugsSourceCorrelation {
	if len(locations) == 0 {
		return spotBugsSourceCorrelation{}
	}
	instructions := make(map[jvmInstruction]mappedDereference, len(locations))
	instructionCounts := make(map[mappedDereference]int)
	for _, location := range locations {
		instruction := jvmInstruction{
			location.ClassName, location.MethodName, location.MethodDescriptor, location.BytecodeOffset,
		}
		site := mappedDereference{decompiledLine{location.Path, location.Line}, location.DereferenceKind, location.MemberName}
		if _, duplicate := instructions[instruction]; duplicate {
			instructions[instruction] = mappedDereference{}
		} else {
			instructions[instruction] = site
		}
		instructionCounts[site]++
	}

	sourceByLine := make(map[decompiledLine]int)
	for index, candidate := range source {
		if candidate.finding.RuleID != javaNullDereferenceRuleID {
			continue
		}
		line := decompiledLine{candidate.finding.Path, candidate.startLine}
		if _, duplicate := sourceByLine[line]; duplicate {
			sourceByLine[line] = -1
		} else {
			sourceByLine[line] = index + 1
		}
	}

	bytecodeSites := make([]mappedDereference, len(bytecode.Findings))
	bytecodeCounts := make(map[mappedDereference]int)
	result := spotBugsSourceCorrelation{
		lines:  make([]decompiledLine, len(bytecode.Findings)),
		merged: make([]bool, len(bytecode.Findings)),
	}
	for index, candidate := range bytecode.Findings {
		if candidate.BytecodeOffset == nil {
			continue
		}
		instruction := jvmInstruction{
			strings.ReplaceAll(candidate.ClassName, ".", "/"), candidate.MethodName, candidate.MethodDescriptor, *candidate.BytecodeOffset,
		}
		site := instructions[instruction]
		if site.path != "" {
			bytecodeSites[index] = site
			bytecodeCounts[site]++
			if candidate.confirmedDereference() {
				result.lines[index] = site.decompiledLine
			}
		}
	}

	for index, site := range bytecodeSites {
		sourceIndex := sourceByLine[site.decompiledLine] - 1
		if sourceIndex < 0 || instructionCounts[site] != 1 || bytecodeCounts[site] != 1 || result.lines[index].path == "" {
			continue
		}
		candidate := &source[sourceIndex].finding
		if !site.matches(*candidate) {
			continue
		}
		// Clone before enrichment so the raw Checker response remains independent
		// in the evidence artifact.
		evidence := maps.Clone(candidate.Evidence)
		evidence["engine"] = "java-checker"
		evidence["engines"] = []string{"java-checker", "spotbugs"}
		bug := bytecode.Findings[index]
		bytecodeEvidence := bug.evidence(bytecode.ToolVersion)
		bytecodeEvidence["message"] = bug.Message
		evidence["spotbugs"] = bytecodeEvidence
		candidate.Evidence = evidence
		result.merged[index] = true
		result.mergedCount++
	}
	return result
}

func (correlation spotBugsSourceCorrelation) addDecompiledLocation(evidence map[string]any, index int, sources map[string]checkerSourceEvidence) {
	if index >= len(correlation.lines) {
		return
	}
	location := correlation.lines[index]
	source, ok := sources[location.path]
	if ok && location.line >= 1 && location.line <= len(source.lines) {
		evidence["decompiledLocation"] = map[string]any{"path": location.path, "line": location.line}
	}
}

func (site mappedDereference) matches(finding checkerFinding) bool {
	unique, _ := finding.Evidence["uniqueDereferenceOnLine"].(bool)
	kind, _ := finding.Evidence["dereferenceKind"].(string)
	member, _ := finding.Evidence["dereferenceMember"].(string)
	if !unique || finding.CWE != "CWE-476" || kind != site.kind || member != site.member {
		return false
	}
	switch kind {
	case "instance-method", "instance-field":
		return member != ""
	case "array-access", "array-length", "monitor":
		return member == ""
	default:
		return false
	}
}

func (finding spotBugsFinding) confirmedDereference() bool {
	if finding.LocationRole != "SOURCE_LINE_DEREF" {
		return false
	}
	switch finding.Pattern {
	case "NP_ALWAYS_NULL", "NP_ALWAYS_NULL_EXCEPTION", "NP_NULL_ON_SOME_PATH", "NP_NULL_ON_SOME_PATH_EXCEPTION",
		"NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE", "NP_CLOSING_NULL":
		return true
	default:
		return false
	}
}
