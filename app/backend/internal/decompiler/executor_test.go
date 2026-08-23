package decompiler

import "testing"

func TestJVMInputExtension(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"class":      "class",
		"java-class": "class",
		"jar":        "jar",
		"war":        "war",
		"ear":        "ear",
		"dex":        "dex",
		"apk":        "apk",
		"unknown":    "bin",
	}
	for format, want := range tests {
		format, want := format, want
		t.Run(format, func(t *testing.T) {
			t.Parallel()
			if got := jvmInputExtension(format); got != want {
				t.Fatalf("jvmInputExtension(%q) = %q, want %q", format, got, want)
			}
		})
	}
}
