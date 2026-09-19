package main

import (
	"bufio"
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// extLanguage maps file extensions to a canonical language name.
var extLanguage = map[string]string{
	".py":   "python",
	".js":   "javascript",
	".ts":   "javascript",
	".jsx":  "javascript",
	".tsx":  "javascript",
	".go":   "go",
	".java": "java",
	".c":    "c",
	".h":    "c",
	".cs":   "csharp",
	".php":  "php",
	".rb":   "ruby",
}

// skipDirs are directories that are never scanned.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, ".bzr": true,
	"node_modules": true, "vendor": true, "bower_components": true,
	"__pycache__": true, ".venv": true, "venv": true, "env": true,
	"dist": true, "build": true, "out": true, "target": true,
	".idea": true, ".vscode": true, ".tox": true, ".eggs": true,
}

// Finding is one rule match inside a file.
type Finding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	RuleID   string `json:"rule_id"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Fix      string `json:"fix"`
}

// Progress is called after each source file is scanned.
type Progress func(filesScanned int, findingsSoFar int)

// scanDir walks root and returns every finding plus a per-file counter.
func scanDir(root string) ([]Finding, map[string]int, error) {
	return scanDirProgress(root, nil)
}

// scanDirProgress is scanDir with an optional progress callback for UIs.
func scanDirProgress(root string, progress Progress) ([]Finding, map[string]int, error) {
	var findings []Finding
	byExt := map[string]int{}
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		lang, ok := extLanguage[ext]
		if !ok {
			return nil
		}
		rel := path
		if root != "." {
			if r, err := filepath.Rel(root, path); err == nil {
				rel = r
			}
		}
		byExt[lang]++
		found, err := scanFile(path, rel, lang)
		if err != nil {
			return nil // unreadable file, skip silently
		}
		files++
		findings = append(findings, found...)
		if progress != nil {
			progress(files, len(findings))
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return findings, byExt, nil
}

// scanFile applies the rules for lang line by line.
func scanFile(path, rel, lang string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rules := rulesFor([]string{lang})
	var findings []Finding
	reader := bufio.NewReaderSize(f, 64*1024)
	lineNo := 0
	for {
		line, err := readLine(reader)
		// A final line without a trailing newline still carries content, so
		// process it before honoring the EOF sentinel.
		if len(line) > 0 {
			lineNo++
			findings = append(findings, scanLine(line, rel, lineNo, rules)...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return findings, err
		}
	}
	return findings, nil
}

// scanLine matches every applicable rule against one line of source.
func scanLine(line []byte, rel string, lineNo int, rules []*Rule) []Finding {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return nil
	}
	var findings []Finding
	lineStr := string(line)
	for _, r := range rules {
		loc := r.Pattern.FindStringIndex(lineStr)
		if loc == nil {
			continue
		}
		code := bytes.TrimSpace(trimmed)
		if len(code) > 180 {
			code = code[:180]
		}
		col := runeIndex(lineStr, loc[0]) + 1
		findings = append(findings, Finding{
			File:     rel,
			Line:     lineNo,
			Column:   col,
			RuleID:   r.ID,
			Rule:     r.Name,
			Severity: r.Severity,
			Category: r.Category,
			Code:     string(code),
			Message:  r.Message,
			Fix:      r.Fix,
		})
	}
	return findings
}

// readLine reads a single line including its newline, splitting very long
// lines to avoid unbounded memory.
func readLine(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		chunk, err := r.ReadSlice('\n')
		out = append(out, chunk...)
		if err == nil {
			return out, nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return out, err // io.EOF or real error
	}
}

func runeIndex(s string, byteIdx int) int {
	if byteIdx <= 0 {
		return 0
	}
	n := 0
	for i := range s {
		if i >= byteIdx {
			break
		}
		n++
	}
	return n
}
