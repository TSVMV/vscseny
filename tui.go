package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

const (
	pageRows = 18
	barWidth = 28
	colWidth = 92
)

var colWidths = []int{4, 8, 10, 28, 5, 27}

type uiFilters struct {
	severity string
	category string
	keyword  string
	minSev   string
}

func (f uiFilters) describe() string {
	if f.severity == "" && f.category == "" && f.keyword == "" && f.minSev == "" {
		return "all"
	}
	var parts []string
	if f.severity != "" {
		parts = append(parts, "sev="+f.severity)
	}
	if f.minSev != "" {
		parts = append(parts, "min="+f.minSev)
	}
	if f.category != "" {
		parts = append(parts, "cat="+f.category)
	}
	if f.keyword != "" {
		parts = append(parts, "match="+f.keyword)
	}
	return strings.Join(parts, " ")
}

func filterFindings(findings []Finding, f uiFilters) []Finding {
	rank := -1
	if f.minSev != "" {
		if v, ok := sevOrder[f.minSev]; ok {
			rank = v
		}
	}
	out := make([]Finding, 0, len(findings))
	kw := strings.ToLower(f.keyword)
	sev := strings.ToLower(f.severity)
	cat := strings.ToLower(f.category)
	for _, x := range findings {
		if sev != "" && strings.ToLower(x.Severity) != sev {
			continue
		}
		if cat != "" && strings.ToLower(x.Category) != cat {
			continue
		}
		if kw != "" {
			hay := strings.ToLower(x.File + " " + x.RuleID + " " + x.Rule + " " + x.Code + " " + x.Message)
			if !strings.Contains(hay, kw) {
				continue
			}
		}
		if rank >= 0 && sevOrder[x.Severity] > rank {
			continue
		}
		out = append(out, x)
	}
	return out
}

func orderFindings(list []Finding, bySeverity bool) {
	sort.SliceStable(list, func(i, j int) bool {
		if bySeverity {
			a, b := sevOrder[list[i].Severity], sevOrder[list[j].Severity]
			if a != b {
				return a < b
			}
		}
		if list[i].File != list[j].File {
			return list[i].File < list[j].File
		}
		return list[i].Line < list[j].Line
	})
}

type ui struct {
	root       string
	findings   []Finding
	visible    []Finding
	filters    uiFilters
	sortBySev  bool
	page       int
	detail     int
	help       bool
	color      bool
	writer     io.Writer
	reader     *bufio.Reader
	stats      reportStats
	categories []string
}

func newUI(root string, findings []Finding, color bool) *ui {
	cats := map[string]int{}
	for _, f := range findings {
		cats[f.Category]++
	}
	c := &ui{
		root:       root,
		findings:   findings,
		stats:      summarize(findings),
		writer:     os.Stdout,
		reader:     bufio.NewReader(os.Stdin),
		sortBySev:  true,
		color:      color,
		categories: sortedKeys(cats),
		page:       1,
		detail:     -1,
	}
	c.refresh()
	return c
}

func (c *ui) refresh() {
	c.visible = filterFindings(c.findings, c.filters)
	orderFindings(c.visible, c.sortBySev)
	last := maxPageOf(c.visible)
	if c.page < 1 {
		c.page = 1
	}
	if c.page > last {
		c.page = last
	}
	if c.detail >= len(c.visible) {
		c.detail = -1
	}
}

func runTUI(root string, findings []Finding, useColor bool) {
	if useColor {
		enableVT()
	}
	c := newUI(root, findings, useColor)
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
	fmt.Fprintln(c.writer)
}

func (c *ui) readLine() string {
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return "quit"
	}
	return strings.TrimRight(line, "\r\n")
}

func (c *ui) render() {
	if c.help {
		c.renderHelp()
		return
	}
	if c.detail >= 0 {
		c.renderDetail()
		return
	}
	c.renderList()
}

func clearScreen(w io.Writer) {
	fmt.Fprint(w, "\033[2J\033[H")
}

func (c *ui) paint(seq, s string) string {
	if !c.color {
		return s
	}
	return seq + s + "\033[0m"
}

func (c *ui) sortName() string {
	if c.sortBySev {
		return "severity"
	}
	return "file"
}

func colorOf(sev string) string {
	switch sev {
	case SevCritical:
		return "\033[31;1m"
	case SevHigh:
		return "\033[33;1m"
	case SevMedium:
		return "\033[36;1m"
	default:
		return "\033[34m"
	}
}

func (c *ui) severityBar() string {
	total := len(c.visible)
	if total == 0 {
		return "no issue matches the current filter"
	}
	counts := map[string]int{}
	for _, f := range c.visible {
		counts[f.Severity]++
	}
	labels := map[string]string{
		SevCritical: "C", SevHigh: "H", SevMedium: "M", SevLow: "L",
	}
	var b strings.Builder
	for _, k := range []string{SevCritical, SevHigh, SevMedium, SevLow} {
		n := counts[k]
		if n == 0 {
			continue
		}
		width := barWidth * n / total
		if width < 1 {
			width = 1
		}
		b.WriteString(c.paint(colorOf(k), strings.Repeat(labels[k], width)))
	}
	return b.String()
}

func (c *ui) tableHeader() string {
	return formatCols([]string{"#", "SEV", "RULE", "FILE", "LINE", "CODE"}, colWidths)
}

func (c *ui) tableRow(f Finding, idx int) string {
	return formatCols([]string{
		strconv.Itoa(idx),
		c.paint(colorOf(f.Severity), strings.ToUpper(f.Severity)),
		f.RuleID,
		filepath.Base(f.File),
		strconv.Itoa(f.Line),
		clipRunes(oneLine(f.Code), 27),
	}, colWidths)
}

func (c *ui) renderList() {
	clearScreen(c.writer)
	fmt.Fprintf(c.writer, "%s   %s\n", c.paint("\033[1m", "VSCSENY "+version), c.root)
	fmt.Fprintf(c.writer, "%d issue(s)   %s\n\n", len(c.visible), c.severityBar())
	fmt.Fprintln(c.writer, c.paint("\033[1m", "filter: ")+c.filters.describe()+
		"   "+c.paint("\033[1m", "sort: ")+c.sortName()+
		"   "+c.paint("\033[1m", "page: ")+fmt.Sprintf("%d/%d", c.page, c.pages()))
	fmt.Fprintln(c.writer, strings.Repeat("-", colWidth))
	fmt.Fprintln(c.writer, c.tableHeader())
	fmt.Fprintln(c.writer, strings.Repeat("-", colWidth))
	items := c.pageItems()
	if len(items) == 0 {
		fmt.Fprintln(c.writer, "  (no issues match the current filter)")
	}
	startIdx := (c.page-1)*pageRows + 1
	for i, f := range items {
		fmt.Fprintln(c.writer, c.tableRow(f, startIdx+i))
	}
	fmt.Fprintln(c.writer)
	c.footer()
	c.prompt()
}

func (c *ui) renderDetail() {
	clearScreen(c.writer)
	if c.detail < 0 || c.detail >= len(c.visible) {
		c.detail = 0
	}
	f := c.visible[c.detail]
	fmt.Fprintln(c.writer, c.paint("\033[1m", "VSCSENY "+version)+"   detail "+fmt.Sprintf("(%d/%d)", c.detail+1, len(c.visible)))
	fmt.Fprintln(c.writer, strings.Repeat("-", colWidth))
	fmt.Fprintf(c.writer, "  rule     %s   %s\n", c.paint(colorOf(f.Severity), f.RuleID), f.Rule)
	fmt.Fprintf(c.writer, "  severity %s\n", strings.ToUpper(f.Severity))
	fmt.Fprintf(c.writer, "  category %s\n", f.Category)
	fmt.Fprintf(c.writer, "  location %s:%d\n\n", f.File, f.Line)
	fmt.Fprintf(c.writer, "  code     %s\n\n", f.Code)
	fmt.Fprintf(c.writer, "  why      %s\n\n", wrapText(f.Message, 80))
	fmt.Fprintf(c.writer, "  fix      %s\n\n", wrapText(f.Fix, 80))
	fmt.Fprintln(c.writer, strings.Repeat("-", colWidth))
	fmt.Fprintln(c.writer, "  b / l    back to list   n / p  next / previous issue")
	fmt.Fprintln(c.writer, "  o        open in $EDITOR   h help   q quit")
	c.prompt()
}

func (c *ui) footer() {
	fmt.Fprintln(c.writer, strings.Repeat("-", colWidth))
	fmt.Fprintln(c.writer, "  f <sev>   filter severity    c <cat>   filter category    m <text>  match")
	fmt.Fprintln(c.writer, "  sev high  critical+high      s         clear filters      sort sev|file")
	fmt.Fprintln(c.writer, "  n / p     next / prev page   <number>  inspect issue      h help   q quit")
}

func (c *ui) prompt() {
	fmt.Fprint(c.writer, "\n> ")
}

func (c *ui) handleInput(cmd, lower string) bool {
	c.help = false
	fields := strings.Fields(lower)
	if len(fields) == 0 {
		return false
	}
	head := fields[0]

	switch head {
	case "h", "help":
		c.help = true
		return false
	case "f":
		if len(fields) < 2 || fields[1] == "all" {
			c.filters.severity = ""
		} else {
			c.filters.severity = fields[1]
		}
		c.page = 1
		c.detail = -1
		c.refresh()
		return false
	case "c":
		if len(fields) < 2 {
			fmt.Fprintln(c.writer, "  category: "+strings.Join(c.categories, " "))
			c.prompt()
			return false
		}
		if fields[1] == "all" {
			c.filters.category = ""
		} else {
			c.filters.category = fields[1]
		}
		c.page = 1
		c.detail = -1
		c.refresh()
		return false
	case "m":
		if len(fields) < 2 {
			c.filters.keyword = ""
		} else {
			c.filters.keyword = strings.TrimSpace(cmd[len(fields[0]):])
		}
		c.page = 1
		c.detail = -1
		c.refresh()
		return false
	case "sev":
		if len(fields) < 2 || fields[1] == "all" {
			c.filters.minSev = ""
		} else {
			c.filters.minSev = fields[1]
		}
		c.page = 1
		c.detail = -1
		c.refresh()
		return false
	case "s", "all":
		c.filters = uiFilters{}
		c.page = 1
		c.detail = -1
		c.refresh()
		return false
	case "sort":
		if len(fields) >= 2 {
			c.sortBySev = fields[1] != "file"
		} else {
			c.sortBySev = !c.sortBySev
		}
		c.refresh()
		return false
	case "o":
		c.openFile()
		return false
	case "n", "next", "down":
		if c.detail >= 0 {
			if c.detail < len(c.visible)-1 {
				c.detail++
			}
			return false
		}
		if c.page < c.pages() {
			c.page++
		}
		return false
	case "p", "prev", "up":
		if c.detail > 0 {
			c.detail--
			return false
		}
		c.detail = -1
		if c.page > 1 {
			c.page--
		}
		return false
	case "top":
		c.detail = -1
		c.page = 1
		return false
	case "b", "back", "l", "list":
		c.detail = -1
		return false
	}

	if n, err := strconv.Atoi(head); err == nil {
		if n >= 1 && n <= len(c.visible) {
			c.detail = n - 1
		}
	}
	return false
}

func (c *ui) renderHelp() {
	clearScreen(c.writer)
	fmt.Fprintln(c.writer, c.paint("\033[1m", "VSCSENY "+version)+"   commands")
	fmt.Fprintln(c.writer, strings.Repeat("-", colWidth))
	fmt.Fprintln(c.writer, "  filtering")
	fmt.Fprintln(c.writer, "    f critical   filter by severity       c <category>   filter by category")
	fmt.Fprintln(c.writer, "    m <text>     match file / rule / code          sev high   show critical+high")
	fmt.Fprintln(c.writer, "    s            clear every filter")
	fmt.Fprintln(c.writer, "  navigation")
	fmt.Fprintln(c.writer, "    n / p        next page or issue / previous")
	fmt.Fprintln(c.writer, "    top          first page               sort sev|file  change sort order")
	fmt.Fprintln(c.writer, "    <number>     show issue N             o              open in $EDITOR")
	fmt.Fprintln(c.writer, "  view")
	fmt.Fprintln(c.writer, "    h            this help                q              quit")
	c.prompt()
}

func (c *ui) openFile() {
	if c.detail < 0 || c.detail >= len(c.visible) {
		return
	}
	f := c.visible[c.detail]
	path := f.File
	if !filepath.IsAbs(path) {
		path = filepath.Join(c.root, f.File)
	}
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintln(c.writer, "  path not accessible")
		return
	}
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		editor = defaultEditor()
	}
	parts := strings.Fields(editor)
	if len(parts) == 0 {
		fmt.Fprintln(c.writer, "  no editor configured, set $EDITOR")
		return
	}
	args := append(append([]string{}, parts[1:]...), fmt.Sprintf("+%d", f.Line), path)
	cmd := exec.Command(parts[0], args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(c.writer, "  editor failed: %v\n", err)
	}
}

func defaultEditor() string {
	if runtime.GOOS == "windows" {
		return "notepad"
	}
	for _, e := range []string{"vi", "vim", "nano", "less"} {
		if _, err := exec.LookPath(e); err == nil {
			return e
		}
	}
	return "vi"
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

func wrapText(s string, width int) string {
	s = strings.ReplaceAll(s, "\r", "")
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	cur := ""
	for _, w := range words {
		if cur == "" {
			cur = w
			continue
		}
		if len(cur)+1+len(w) <= width {
			cur += " " + w
			continue
		}
		lines = append(lines, cur)
		cur = w
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return strings.Join(lines, "\n           ")
}

func clipRunes(s string, width int) string {
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	if width <= 1 {
		return string(r[:width])
	}
	return string(r[:width-1]) + ">"
}

func formatCols(cols []string, widths []int) string {
	parts := make([]string, 0, len(cols))
	for i, col := range cols {
		w := 0
		if i < len(widths) {
			w = widths[i]
		}
		plain := stripANSI(col)
		pad := w - runeLen(plain)
		if pad < 0 {
			col = clipRunes(plain, w)
			pad = 0
		}
		parts = append(parts, col+strings.Repeat(" ", pad))
	}
	return strings.Join(parts, "  ")
}

func stripANSI(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < '@' || s[j] > '~') {
				j++
			}
			if j < len(s) {
				i = j + 1
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func runeLen(s string) int {
	return len([]rune(s))
}

func maxPageOf(items []Finding) int {
	if len(items) == 0 {
		return 1
	}
	return (len(items) + pageRows - 1) / pageRows
}

func (c *ui) pages() int {
	return maxPageOf(c.visible)
}

func (c *ui) pageItems() []Finding {
	if len(c.visible) == 0 {
		return nil
	}
	start := (c.page - 1) * pageRows
	if start >= len(c.visible) {
		return nil
	}
	end := start + pageRows
	if end > len(c.visible) {
		end = len(c.visible)
	}
	return c.visible[start:end]
}
