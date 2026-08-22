package storage

import (
	"fmt"
	"path"
	"strings"
)

func CleanRelativePath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsRune(value, '\x00') || strings.Contains(value, "\\") {
		return "", fmt.Errorf("invalid relative path")
	}
	cleaned := path.Clean(value)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("path escapes the workspace")
	}
	if len(cleaned) > 1024 {
		return "", fmt.Errorf("path exceeds 1024 characters")
	}
	return cleaned, nil
}

func cleanIdentifier(value string) (string, error) {
	if value == "" || len(value) > 64 {
		return "", fmt.Errorf("invalid identifier")
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return "", fmt.Errorf("invalid identifier")
	}
	return value, nil
}
