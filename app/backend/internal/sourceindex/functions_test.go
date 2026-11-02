package sourceindex

import "testing"

func TestFunctions(t *testing.T) {
	cases := []struct {
		language, source, name string
		start, end             int
	}{
		{"python", "# comment\ndef query(conn):\n    return conn.execute('select * from users')\n\ndef other():\n    pass\n", "query", 2, 4},
		{"c", "int query(sqlite3 *db) {\n  // {\n  return sqlite3_exec(db, \"select * from users\", 0, 0, 0);\n}\n", "query", 1, 4},
		{"java", "public String query() {\n  return \"{\";\n}\n", "query", 1, 3},
	}
	for _, tc := range cases {
		functions := Functions(tc.language, tc.source)
		if len(functions) == 0 || functions[0].Name != tc.name || functions[0].StartLine != tc.start || functions[0].EndLine != tc.end {
			t.Errorf("%s: got %+v", tc.language, functions)
		}
	}
}
