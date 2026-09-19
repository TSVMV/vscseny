package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanPythonCommandInjection(t *testing.T) {
	dir := t.TempDir()
	code := "import os\nos.system('ls ' + user_input)\n"
	path := filepath.Join(dir, "app.py")
	if err := os.WriteFile(path, []byte(code), 0644); err != nil {
		t.Fatal(err)
	}
	findings, _, err := scanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	matched := false
	for _, f := range findings {
		if f.RuleID == "CME-001" {
			matched = true
			if f.File != "app.py" {
				t.Errorf("file = %q", f.File)
			}
			if f.Line != 2 {
				t.Errorf("line = %d", f.Line)
			}
		}
	}
	if !matched {
		t.Fatalf("expected CME-001, got %+v", findings)
	}
}

func TestScanSQLConcat(t *testing.T) {
	code := "SELECT * FROM users WHERE id = " + "\" + user_id"
	dir := t.TempDir()
	path := filepath.Join(dir, "db.js")
	if err := os.WriteFile(path, []byte(code), 0644); err != nil {
		t.Fatal(err)
	}
	findings, _, _ := scanDir(dir)
	if !containsRule(findings, "SQL-001") {
		t.Fatalf("expected SQL-001, got %+v", findings)
	}
}

func TestSecretDetection(t *testing.T) {
	code := "const apiKey = \"abcdef0123456789abcdef0123456789\";\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "x.js")
	if err := os.WriteFile(path, []byte(code), 0644); err != nil {
		t.Fatal(err)
	}
	findings, _, _ := scanDir(dir)
	if !containsRule(findings, "SEC-001") {
		t.Fatalf("expected SEC-001, got %+v", findings)
	}
}

func TestCSkipsUnsupportedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("os.system('rm -rf /')"), 0644); err != nil {
		t.Fatal(err)
	}
	findings, _, err := scanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for txt, got %+v", findings)
	}
}

func TestSkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "node_modules")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "a.js"), []byte("eval(user_input)"), 0644); err != nil {
		t.Fatal(err)
	}
	findings, _, err := scanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("node_modules should be skipped, got %+v", findings)
	}
}

func TestSeveritySortingInTextReport(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.py"), []byte("os.system('x')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.py"), []byte("import hashlib\nhashlib.md5(b'x')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	findings, _, _ := scanDir(dir)
	var buf bytes.Buffer
	writeText(&buf, dir, findings, summarize(findings))
	out := buf.String()
	// critical CME-001 should appear before medium CRY-001
	ci := strings.Index(out, "CME-001")
	mi := strings.Index(out, "CRY-001")
	if ci < 0 || mi < 0 || ci > mi {
		t.Fatalf("sort order wrong:\n%s", out)
	}
}

func TestJSONReportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.js"), []byte("const t = 'x' + input;\nelem.innerHTML = t;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	findings, _, _ := scanDir(dir)
	var buf bytes.Buffer
	if err := writeJSON(&buf, dir, findings, summarize(findings)); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["scanned_path"] != dir {
		t.Fatalf("scanned_path = %v", payload["scanned_path"])
	}
	if payload["findings"] == nil {
		t.Fatal("findings missing from JSON")
	}
}

func TestEmptyScanReportsZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.go"), []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	findings, _, err := scanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	writeText(&buf, dir, findings, summarize(findings))
	if !strings.Contains(buf.String(), "no issues") {
		t.Fatalf("expected no-issues message, got:\n%s", buf.String())
	}
}

func containsRule(findings []Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}
