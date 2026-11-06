package app

import (
	"binaryscan.local/backend/internal/checkrules"
	"encoding/json"
	"strings"
)

func reportRuleSelectionText(run map[string]any) string {
	if !strings.HasSuffix(reportText(run["kind"]), "_check") && !strings.HasSuffix(reportText(run["kind"]), "_sast") {
		return "不适用"
	}
	body, err := json.Marshal(map[string]any{"selection": run["selection"]})
	if err != nil {
		return checkrules.Describe(nil)
	}
	selection, err := checkrules.FromRequest(body)
	if err != nil {
		return checkrules.Describe(nil)
	}
	return checkrules.Describe(selection)
}
