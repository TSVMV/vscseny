package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

var sevOrder = map[string]int{
	SevCritical: 0,
	SevHigh:     1,
	SevMedium:   2,
	SevLow:      3,
}

type reportStats struct {
	Total      int            `json:"total"`
	Critical   int            `json:"critical"`
	High       int            `json:"high"`
	Medium     int            `json:"medium"`
	Low        int            `json:"low"`
	ByCategory map[string]int `json:"by_category"`
	ByRule     map[string]int `json:"by_rule"`
}

func summarize(findings []Finding) reportStats {
	s := reportStats{ByCategory: map[string]int{}, ByRule: map[string]int{}}
	for _, f := range findings {
		s.Total++
		switch f.Severity {
		case SevCritical:
			s.Critical++
		case SevHigh:
			s.High++
		case SevMedium:
			s.Medium++
		case SevLow:
			s.Low++
		}
		s.ByCategory[f.Category]++
		s.ByRule[f.RuleID]++
	}
	return s
}

// writeText renders an ASCII report to w. No emoji, no unicode box drawing.
func writeText(w io.Writer, root string, findings []Finding, stats reportStats) {
	ordered := make([]Finding, len(findings))
	copy(ordered, findings)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := sevOrder[ordered[i].Severity], sevOrder[ordered[j].Severity]
		if a != b {
			return a < b
		}
		if ordered[i].File != ordered[j].File {
			return ordered[i].File < ordered[j].File
		}
		return ordered[i].Line < ordered[j].Line
	})

	fmt.Fprintf(w, "vscseny: static analysis of %s\n", root)
	fmt.Fprintf(w, "found %d issue(s) across %d category type(s)\n\n", stats.Total, len(stats.ByCategory))

	if stats.Total == 0 {
		fmt.Fprintln(w, "no issues detected. review still recommended for logic and design concerns.")
		return
	}

	perSev := map[string]int{}
	for _, f := range ordered {
		perSev[f.Severity]++
	}

	curSev := ""
	curFile := ""
	for _, f := range ordered {
		if f.Severity != curSev {
			curSev = f.Severity
			curFile = ""
			fmt.Fprintf(w, "===== %s (%d) =====\n\n", strings.ToUpper(curSev), perSev[curSev])
		}
		if f.File != curFile {
			curFile = f.File
			fmt.Fprintf(w, "--- %s\n", f.File)
		}
		fmt.Fprintf(w, "[%s] %s\n", f.RuleID, f.Rule)
		fmt.Fprintf(w, "    at line %d: %s\n", f.Line, f.Code)
		fmt.Fprintf(w, "    %s\n", f.Message)
		fmt.Fprintf(w, "    fix: %s\n", f.Fix)
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "--- summary ---")
	fmt.Fprintf(w, "critical: %d   high: %d   medium: %d   low: %d\n",
		stats.Critical, stats.High, stats.Medium, stats.Low)
	if len(stats.ByCategory) > 0 {
		fmt.Fprintf(w, "by category:\n")
		for _, c := range sortedKeys(stats.ByCategory) {
			fmt.Fprintf(w, "  %-20s %d\n", c, stats.ByCategory[c])
		}
	}
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// writeJSON emits a machine-readable report.
func writeJSON(w io.Writer, root string, findings []Finding, stats reportStats) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	payload := map[string]any{
		"scanned_path": root,
		"stats":        stats,
		"findings":     findings,
	}
	return enc.Encode(payload)
}
