package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func sampleFindings() []Finding {
	return []Finding{
		{File: "a.py", Line: 2, RuleID: "CME-001", Rule: "os.system", Severity: SevCritical, Category: "command-execution", Code: "os.system(cmd)", Message: "shell", Fix: "use subprocess"},
		{File: "b.js", Line: 10, RuleID: "SQL-001", Rule: "sql concat", Severity: SevHigh, Category: "injection", Code: "query + id", Message: "sql", Fix: "bind params"},
		{File: "c.py", Line: 4, RuleID: "SEC-001", Rule: "hardcoded secret", Severity: SevMedium, Category: "secret", Code: "password = 'x'", Message: "secret", Fix: "env var"},
		{File: "d.c", Line: 8, RuleID: "MEM-001", Rule: "strcpy", Severity: SevLow, Category: "memory-unsafe", Code: "strcpy(dst, src)", Message: "overflow", Fix: "strncpy"},
	}
}

func TestFilterBySeverity(t *testing.T) {
	got := filterFindings(sampleFindings(), uiFilters{severity: "high"})
	if len(got) != 1 || got[0].RuleID != "SQL-001" {
		t.Fatalf("got %+v", got)
	}
}

func TestFilterMinSeverity(t *testing.T) {
	got := filterFindings(sampleFindings(), uiFilters{minSev: SevHigh})
	if len(got) != 2 {
		t.Fatalf("want 2 (critical+high), got %d", len(got))
	}
}

func TestFilterKeyword(t *testing.T) {
	got := filterFindings(sampleFindings(), uiFilters{keyword: "strcpy"})
	if len(got) != 1 || got[0].RuleID != "MEM-001" {
		t.Fatalf("got %+v", got)
	}
}

func TestPagination(t *testing.T) {
	var many []Finding
	for i := 0; i < 40; i++ {
		many = append(many, Finding{File: "f.py", Line: i + 1, RuleID: "CME-001", Severity: SevHigh, Category: "command-execution"})
	}
	c := newUI(".", many, false)
	c.writer = &bytes.Buffer{}
	if c.pages() != 3 {
		t.Fatalf("pages = %d", c.pages())
	}
	if len(c.pageItems()) != pageRows {
		t.Fatalf("page 1 size = %d", len(c.pageItems()))
	}
	c.handleInput("n", "n")
	if c.page != 2 {
		t.Fatalf("page after n = %d", c.page)
	}
	c.handleInput("top", "top")
	if c.page != 1 {
		t.Fatalf("page after top = %d", c.page)
	}
}

func TestInspectAndBack(t *testing.T) {
	c := newUI(".", sampleFindings(), false)
	c.writer = &bytes.Buffer{}
	c.handleInput("1", "1")
	if c.detail != 0 {
		t.Fatalf("detail = %d", c.detail)
	}
	c.handleInput("b", "b")
	if c.detail != -1 {
		t.Fatalf("detail after back = %d", c.detail)
	}
}

func TestTUISessionNoEmoji(t *testing.T) {
	c := newUI("/tmp/proj", sampleFindings(), false)
	var buf bytes.Buffer
	c.writer = &buf
	c.reader = bufio.NewReader(strings.NewReader("h\n1\nb\nf critical\ns\nq\n"))
	runDriven(c)
	out := buf.String()
	if strings.Contains(out, "\U0001F600") || strings.ContainsAny(out, "⚠✓✗●◆★") {
		t.Fatalf("emoji leaked into TUI output")
	}
	if !strings.Contains(out, "VSCSENY") {
		t.Fatalf("missing title:\n%s", out)
	}
	if !strings.Contains(out, "commands") {
		t.Fatalf("help not rendered")
	}
}

func runDriven(c *ui) {
	c.render()
	for {
		cmd := c.readLine()
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		lower := strings.ToLower(cmd)
		if lower == "q" || lower == "quit" || lower == "exit" {
			break
		}
		if c.handleInput(cmd, lower) {
			break
		}
		c.render()
	}
}

func TestRenderDetailEmptyVisible(t *testing.T) {
	c := newUI(".", []Finding{}, false)
	c.writer = &bytes.Buffer{}
	c.detail = 0
	c.renderDetail()
	if c.detail != -1 {
		t.Fatalf("detail after empty render = %d", c.detail)
	}
}

func TestReorderFlags(t *testing.T) {
	got := reorderFlags([]string{"dir", "--json", "--no-color", "-", "x.py"})
	want := []string{"--json", "--no-color", "dir", "-", "x.py"}
	if len(got) != len(want) {
		t.Fatalf("reorderFlags(%v) = %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reorderFlags = %v, want %v", got, want)
		}
	}
}

func TestSortToggle(t *testing.T) {
	c := newUI(".", sampleFindings(), false)
	c.writer = &bytes.Buffer{}
	if !c.sortBySev {
		t.Fatal("default sort should be severity")
	}
	c.handleInput("sort file", "sort file")
	if c.sortBySev {
		t.Fatal("expected file sort")
	}
	if c.visible[0].File != "a.py" {
		t.Fatalf("first after file sort = %s", c.visible[0].File)
	}
}
