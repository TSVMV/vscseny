package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const version = "0.1.0"

func main() {
	fs := flag.NewFlagSet("vscseny", flag.ContinueOnError)
	var (
		showVersion = fs.Bool("v", false, "print version")
		listRules   = fs.Bool("list-rules", false, "print all rule IDs and names")
		asJSON      = fs.Bool("json", false, "emit a JSON report and exit")
		plainReport = fs.Bool("report", false, "print the plain text report")
		interactive = fs.Bool("tui", false, "launch the interactive terminal UI")
		noColor     = fs.Bool("no-color", false, "disable ANSI colors in the UI")
		showHelp    = fs.Bool("h", false, "show help")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "vscseny "+version)
		fmt.Fprintln(os.Stderr, "usage: vscseny [options] <path>")
		fmt.Fprintln(os.Stderr, "  path can be a project directory or a single source file.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  When stdout is a terminal the interactive UI starts automatically.")
		fmt.Fprintln(os.Stderr, "  Use --report for the plain text report and --json for CI output.")
		fmt.Fprintln(os.Stderr, "options:")
		fs.PrintDefaults()
	}
	// flag.Parse stops at the first non-flag argument, so a documented call
	// like "vscseny <path> --json" would silently drop every flag after the
	// path.  Move flags to the front first; every flag here is a boolean
	// without a value, so reordering is safe.
	if err := fs.Parse(reorderFlags(os.Args[1:])); err != nil {
		os.Exit(2)
	}
	if *showHelp {
		fs.Usage()
		os.Exit(0)
	}
	if *showVersion {
		fmt.Println("vscseny " + version)
		os.Exit(0)
	}
	if *listRules {
		for _, r := range allRules {
			fmt.Printf("%-10s %-8s %-34s %s\n", r.ID, r.Severity, r.Name, strings.Join(r.Languages, ","))
		}
		os.Exit(0)
	}

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}
	target := fs.Arg(0)
	info, err := os.Stat(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vscseny: cannot access %s: %v\n", target, err)
		os.Exit(2)
	}

	mode := "report"
	switch {
	case *interactive:
		mode = "tui"
	case *plainReport:
		mode = "report"
	default:
		if isTerminal(os.Stdout) {
			mode = "tui"
		}
	}

	var findings []Finding
	progress := progressPrinter(mode == "tui")
	if info.IsDir() {
		findings, _, err = scanDirProgress(target, progress)
	} else {
		lang, ok := extLanguage[strings.ToLower(filepath.Ext(target))]
		if !ok {
			fmt.Fprintf(os.Stderr, "vscseny: unsupported file type %s\n", filepath.Ext(target))
			os.Exit(2)
		}
		findings, err = scanFile(target, target, lang)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "vscseny: scan failed: %v\n", err)
		os.Exit(1)
	}
	if progress != nil {
		fmt.Fprintln(os.Stderr)
	}

	stats := summarize(findings)
	if *asJSON {
		if err := writeJSON(os.Stdout, target, findings, stats); err != nil {
			fmt.Fprintf(os.Stderr, "vscseny: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if mode == "tui" {
		runTUI(target, findings, !*noColor)
		return
	}
	writeText(os.Stdout, target, findings, stats)
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// reorderFlags moves every flag argument ahead of the positional arguments so
// flag.Parse still sees them after a path, e.g. "vscseny dir --json".  A lone
// "-" is kept in place as it conventionally means stdin.
func reorderFlags(args []string) []string {
	flags := make([]string, 0, len(args))
	rest := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
		} else {
			rest = append(rest, a)
		}
	}
	return append(flags, rest...)
}

func progressPrinter(enabled bool) Progress {
	if !enabled {
		return nil
	}
	return func(files, found int) {
		fmt.Fprintf(os.Stderr, "\rscanning %d file(s)   %d issue(s) found   ", files, found)
	}
}
