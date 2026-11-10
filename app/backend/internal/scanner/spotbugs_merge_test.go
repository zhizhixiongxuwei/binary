package scanner

import (
	"reflect"
	"testing"

	"binaryscan.local/backend/internal/storage"
)

func spotBugsMergeFixture() ([]validatedCheckerFinding, spotBugsResponse, []storage.JVMSourceLocation) {
	source := []validatedCheckerFinding{{
		finding: checkerFinding{
			RuleID: javaNullDereferenceRuleID, CWE: "CWE-476", Path: "example/Probe.java",
			Evidence: map[string]any{
				"ruleFamily": javaNullDereferenceRuleID, "dereferenceKind": "instance-method",
				"dereferenceMember": "length", "uniqueDereferenceOnLine": true,
			},
		},
		startLine: 10, startColumn: 16,
	}}
	offset := 0
	bytecode := spotBugsResponse{ToolVersion: spotBugsVersion, Findings: []spotBugsFinding{{
		Pattern: "NP_ALWAYS_NULL", ClassName: "example.Probe", MethodName: "run", MethodDescriptor: "()I",
		BytecodeOffset: &offset, LocationRole: "SOURCE_LINE_DEREF", Message: "Null pointer dereference", Priority: 1,
	}}}
	locations := []storage.JVMSourceLocation{{
		Path: "example/Probe.java", ClassName: "example/Probe", MethodName: "run", MethodDescriptor: "()I",
		BytecodeOffset: 0, Line: 10, DereferenceKind: "instance-method", MemberName: "length",
	}}
	return source, bytecode, locations
}

func TestMergeSpotBugsUsesOnlyExactSinkAndKeepsBothEvidences(t *testing.T) {
	source, bytecode, locations := spotBugsMergeFixture()
	rawEvidence := source[0].finding.Evidence
	// An implicit instruction for a different member on the same line does not
	// make the matching method invocation ambiguous.
	otherInstruction := locations[0]
	otherInstruction.BytecodeOffset = 3
	otherInstruction.MemberName = "intValue"
	locations = append(locations, otherInstruction)

	result := correlateSpotBugsFindings(source, bytecode, locations)
	if result.mergedCount != 1 || !reflect.DeepEqual(result.merged, []bool{true}) {
		t.Fatalf("expected one match, got %d %v", result.mergedCount, result.merged)
	}
	evidence := source[0].finding.Evidence
	nested, ok := evidence["spotbugs"].(map[string]any)
	if !ok || nested["bytecodeOffset"] != 0 || nested["message"] != bytecode.Findings[0].Message ||
		nested["methodDescriptor"] != "()I" || nested["locationRole"] != "SOURCE_LINE_DEREF" ||
		evidence["engine"] != "java-checker" || evidence["ruleFamily"] != javaNullDereferenceRuleID ||
		!reflect.DeepEqual(evidence["engines"], []string{"java-checker", "spotbugs"}) ||
		source[0].startLine != 10 || source[0].startColumn != 16 {
		t.Fatalf("unexpected canonical finding: %+v", source[0])
	}
	if _, changed := rawEvidence["spotbugs"]; changed {
		t.Fatal("the merge must not modify the raw AST response")
	}
}

func TestSpotBugsOnlyFindingGetsVerifiedLineWithoutSourceRange(t *testing.T) {
	_, bytecode, locations := spotBugsMergeFixture()
	locations[0].MemberName = "intValue"
	path := locations[0].Path
	sources := map[string]checkerSourceEvidence{path: {lines: make([]string, 10)}}

	result := correlateSpotBugsFindings(nil, bytecode, locations)
	evidence := bytecode.Findings[0].evidence(bytecode.ToolVersion)
	result.addDecompiledLocation(evidence, 0, sources)
	if result.mergedCount != 0 || !reflect.DeepEqual(evidence["decompiledLocation"], map[string]any{"path": path, "line": 10}) ||
		evidence["locationKind"] != "bytecode" {
		t.Fatalf("unexpected bytecode-only location: %+v", evidence)
	}

	for _, test := range []struct {
		name    string
		role    string
		sources map[string]checkerSourceEvidence
	}{
		{"primary role", "", sources},
		{"missing verified file", "SOURCE_LINE_DEREF", nil},
		{"out of range", "SOURCE_LINE_DEREF", map[string]checkerSourceEvidence{path: {lines: make([]string, 9)}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			bytecode.Findings[0].LocationRole = test.role
			result := correlateSpotBugsFindings(nil, bytecode, locations)
			evidence := bytecode.Findings[0].evidence(bytecode.ToolVersion)
			result.addDecompiledLocation(evidence, 0, test.sources)
			if _, present := evidence["decompiledLocation"]; present {
				t.Fatalf("unexpected decompiled location: %+v", evidence)
			}
		})
	}
}

func TestMergeSpotBugsKeepsUncorroboratedFindingsSeparate(t *testing.T) {
	tests := []struct {
		name string
		edit func(*[]validatedCheckerFinding, *spotBugsResponse, *[]storage.JVMSourceLocation)
	}{
		{"legacy project", func(_ *[]validatedCheckerFinding, _ *spotBugsResponse, locations *[]storage.JVMSourceLocation) {
			*locations = nil
		}},
		{"missing BCI", func(_ *[]validatedCheckerFinding, bytecode *spotBugsResponse, _ *[]storage.JVMSourceLocation) {
			bytecode.Findings[0].BytecodeOffset = nil
		}},
		{"primary location only", func(_ *[]validatedCheckerFinding, bytecode *spotBugsResponse, _ *[]storage.JVMSourceLocation) {
			bytecode.Findings[0].LocationRole = ""
		}},
		{"unsafe pattern", func(_ *[]validatedCheckerFinding, bytecode *spotBugsResponse, _ *[]storage.JVMSourceLocation) {
			bytecode.Findings[0].Pattern = "NP_GUARANTEED_DEREF"
		}},
		{"wrong class", func(_ *[]validatedCheckerFinding, _ *spotBugsResponse, locations *[]storage.JVMSourceLocation) {
			(*locations)[0].ClassName = "different/Probe"
		}},
		{"wrong method descriptor", func(_ *[]validatedCheckerFinding, _ *spotBugsResponse, locations *[]storage.JVMSourceLocation) {
			(*locations)[0].MethodDescriptor = "(I)I"
		}},
		{"wrong BCI", func(_ *[]validatedCheckerFinding, _ *spotBugsResponse, locations *[]storage.JVMSourceLocation) {
			(*locations)[0].BytecodeOffset = 1
		}},
		{"wrong source file", func(_ *[]validatedCheckerFinding, _ *spotBugsResponse, locations *[]storage.JVMSourceLocation) {
			(*locations)[0].Path = "other/Probe.java"
		}},
		{"wrong source line", func(_ *[]validatedCheckerFinding, _ *spotBugsResponse, locations *[]storage.JVMSourceLocation) {
			(*locations)[0].Line = 11
		}},
		{"wrong kind", func(_ *[]validatedCheckerFinding, _ *spotBugsResponse, locations *[]storage.JVMSourceLocation) {
			(*locations)[0].DereferenceKind = "instance-field"
		}},
		{"wrong member", func(_ *[]validatedCheckerFinding, _ *spotBugsResponse, locations *[]storage.JVMSourceLocation) {
			(*locations)[0].MemberName = "hashCode"
		}},
		{"ambiguous AST site", func(source *[]validatedCheckerFinding, _ *spotBugsResponse, _ *[]storage.JVMSourceLocation) {
			(*source)[0].finding.Evidence["uniqueDereferenceOnLine"] = false
		}},
		{"multiple AST findings", func(source *[]validatedCheckerFinding, _ *spotBugsResponse, _ *[]storage.JVMSourceLocation) {
			*source = append(*source, (*source)[0])
		}},
		{"multiple SpotBugs findings", func(_ *[]validatedCheckerFinding, bytecode *spotBugsResponse, _ *[]storage.JVMSourceLocation) {
			bytecode.Findings = append(bytecode.Findings, bytecode.Findings[0])
		}},
		{"ambiguous instruction site", func(_ *[]validatedCheckerFinding, _ *spotBugsResponse, locations *[]storage.JVMSourceLocation) {
			other := (*locations)[0]
			other.BytecodeOffset = 3
			*locations = append(*locations, other)
		}},
		{"duplicate mapping key", func(_ *[]validatedCheckerFinding, _ *spotBugsResponse, locations *[]storage.JVMSourceLocation) {
			other := (*locations)[0]
			other.Line = 11
			*locations = append(*locations, other)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source, bytecode, locations := spotBugsMergeFixture()
			test.edit(&source, &bytecode, &locations)
			result := correlateSpotBugsFindings(source, bytecode, locations)
			if result.mergedCount != 0 {
				t.Fatalf("unexpected merge: %d %v", result.mergedCount, result.merged)
			}
			for _, candidate := range source {
				if _, changed := candidate.finding.Evidence["engines"]; changed {
					t.Fatal("unmatched source finding was changed")
				}
			}
		})
	}
}
