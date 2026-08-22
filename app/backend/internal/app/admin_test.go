package app

import (
	"net/url"
	"testing"
)

func TestNormalizeAdminUsername(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{name: "canonicalizes", input: "  Alice.Admin  ", want: "alice.admin", ok: true},
		{name: "allows separators", input: "ops_user-1", want: "ops_user-1", ok: true},
		{name: "too short", input: "ab", ok: false},
		{name: "leading separator", input: "_admin", ok: false},
		{name: "unicode", input: "管理员", ok: false},
		{name: "space", input: "alice admin", ok: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := normalizeAdminUsername(test.input)
			if (err == nil) != test.ok {
				t.Fatalf("normalizeAdminUsername(%q) error = %v", test.input, err)
			}
			if actual != test.want {
				t.Fatalf("normalizeAdminUsername(%q) = %q, want %q", test.input, actual, test.want)
			}
		})
	}
}

func TestAdminValidation(t *testing.T) {
	t.Parallel()
	for _, role := range []string{"reader", "operator", "administrator"} {
		if actual, ok := normalizeAdminRole(role); !ok || actual != role {
			t.Fatalf("role %q was rejected", role)
		}
	}
	if _, ok := normalizeAdminRole("owner"); ok {
		t.Fatal("unsupported role was accepted")
	}
	if err := validateAdminPassword("123456789012"); err != nil {
		t.Fatalf("12-byte password was rejected: %v", err)
	}
	if err := validateAdminPassword("short"); err == nil {
		t.Fatal("short password was accepted")
	}
}

func TestResultingActiveAdministrators(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                 string
		current              int
		oldRole, newRole     string
		oldActive, newActive bool
		want                 int
	}{
		{name: "demote last", current: 1, oldRole: "administrator", oldActive: true, newRole: "operator", newActive: true, want: 0},
		{name: "disable one of two", current: 2, oldRole: "administrator", oldActive: true, newRole: "administrator", newActive: false, want: 1},
		{name: "promote active", current: 1, oldRole: "operator", oldActive: true, newRole: "administrator", newActive: true, want: 2},
		{name: "activate administrator", current: 0, oldRole: "administrator", oldActive: false, newRole: "administrator", newActive: true, want: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := resultingActiveAdministrators(test.current, test.oldRole, test.oldActive, test.newRole, test.newActive)
			if actual != test.want {
				t.Fatalf("resultingActiveAdministrators() = %d, want %d", actual, test.want)
			}
		})
	}
}

func TestParseAuditPage(t *testing.T) {
	t.Parallel()
	limit, beforeID, err := parseAuditPage(url.Values{"limit": {"250"}, "beforeId": {"9001"}})
	if err != nil || limit != 250 || beforeID != 9001 {
		t.Fatalf("parseAuditPage() = %d, %d, %v", limit, beforeID, err)
	}
	limit, beforeID, err = parseAuditPage(url.Values{})
	if err != nil || limit != auditDefaultLimit || beforeID != 0 {
		t.Fatalf("default parseAuditPage() = %d, %d, %v", limit, beforeID, err)
	}
	for _, values := range []url.Values{
		{"limit": {"0"}},
		{"limit": {"501"}},
		{"beforeId": {"0"}},
		{"beforeId": {"not-a-number"}},
	} {
		if _, _, err := parseAuditPage(values); err == nil {
			t.Fatalf("invalid pagination was accepted: %v", values)
		}
	}
}
