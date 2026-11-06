// OTreeMap — Disk Usage Treemap Analyzer
// Part of the OWL security suite.  Author: khaled.s.haddad   Site: owlsec.org
// Language: Go (stdlib only, CGO disabled, static single-file build).
//
// OTreeMap is a professional, offline-first Disk Usage Treemap Analyzer with an interactive red/black
// TUI and a full CLI (flag-based) supporting txt|md|json|csv|sarif exports, MITRE
// ATT&CK tagging on findings where meaningful, and A+..F posture grading.

package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	APPNAME = "OTreeMap"
	TAGLINE = "Disk Usage Treemap Analyzer"
	VERSION = "2.0"
)

const BANNER = `
 ██████╗ ████████╗██████╗ ███████╗███████╗███╗   ███╗ █████╗ ██████╗ 
██╔═══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝████╗ ████║██╔══██╗██╔══██╗
██║   ██║   ██║   ██████╔╝█████╗  █████╗  ██╔████╔██║███████║██████╔╝
██║   ██║   ██║   ██╔══██╗██╔══╝  ██╔══╝  ██║╚██╔╝██║██╔══██║██╔═══╝ 
╚██████╔╝   ██║   ██║  ██║███████╗███████╗██║ ╚═╝ ██║██║  ██║██║     
 ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
`

// ---- OWL UI KIT (red/black) — stdlib only ----
const (
	R   = "\033[91m"
	DR  = "\033[96m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
)

const (
	SUITE   = "Owl Disk Suite"
	AUTHOR  = "khaled.s.haddad"
	WEBSITE = "owlsec.org"
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear() {
	if !noColor {
		fmt.Print("\033[H\033[2J")
	}
}
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }
func header(title string) {
	fmt.Println()
	rule()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	rule()
	fmt.Println()
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := stdin.ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	stdin.ReadString('\n')
}
func stripANSI(s string) string {
	out := []rune{}
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
func visw(s string) int { return len([]rune(stripANSI(s))) }
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), B+CY))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DIM))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DIM))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DIM))
			}
		}
		fmt.Println("  " + rb.String())
	}
}
func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(TAGLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}
func menu(title string, items []string) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Println("  " + col(pad(fmt.Sprintf("[%d]", i+1), 4), CY+B) + "  " + col(it, W))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col("Help & Usage", W))
	fmt.Println("  " + col(pad("[0]", 4), R+B) + "  " + col("Exit", W))
	fmt.Println()
	rule()
	return prompt("Select option")
}

// ---- OWL house help (shared layout) ----
type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	out := []string{}
	cur := ""
	for _, w := range words {
		if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
			out = append(out, cur)
			cur = w
		} else if cur == "" {
			cur = w
		} else {
			cur += " " + w
		}
	}
	out = append(out, cur)
	return out
}
func owlHelpTitle(t string) { fmt.Println(); fmt.Println("  " + col("▸ "+t, B+CY)) }
func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}
func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}
func tuiHelp() {
	clear()
	banner()
	rule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	rule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	rule()
	fmt.Println("  " + col("Next page: command-line flags & examples", DIM))
	pause()
	clear()
	usage()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

// ---- shared finding model, grading, and 5-format export engine ----
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	ATTCK       []string `json:"attck,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Location    string   `json:"location,omitempty"`
	Score       float64  `json:"score"`
}

type KV struct {
	K string `json:"key"`
	V string `json:"value"`
}

type Report struct {
	Tool      string    `json:"tool"`
	Tagline   string    `json:"tagline"`
	Version   string    `json:"version"`
	Target    string    `json:"target"`
	Generated string    `json:"generated"`
	Findings  []Finding `json:"findings"`
	Stats     []KV      `json:"stats"`
	Notes     []string  `json:"notes,omitempty"`
	Grade     string    `json:"grade"`
	Score     float64   `json:"score"`
}

var sevOrder = map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

func sevRank(s string) int {
	if v, ok := sevOrder[strings.ToUpper(s)]; ok {
		return v
	}
	return 0
}
func sevColor(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return R + B
	case "HIGH":
		return R
	case "MEDIUM":
		return YLW
	case "LOW":
		return GRN
	default:
		return GY
	}
}
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if sevRank(fs[i].Severity) != sevRank(fs[j].Severity) {
			return sevRank(fs[i].Severity) > sevRank(fs[j].Severity)
		}
		return fs[i].Score > fs[j].Score
	})
}
func gradeFromScore(f float64) string {
	switch {
	case f >= 97:
		return "A+"
	case f >= 93:
		return "A"
	case f >= 90:
		return "A-"
	case f >= 87:
		return "B+"
	case f >= 83:
		return "B"
	case f >= 80:
		return "B-"
	case f >= 77:
		return "C+"
	case f >= 73:
		return "C"
	case f >= 70:
		return "C-"
	case f >= 65:
		return "D+"
	case f >= 60:
		return "D"
	default:
		return "F"
	}
}
func computePosture(fs []Finding) (string, float64) {
	score := 100.0
	for _, f := range fs {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			score -= 22
		case "HIGH":
			score -= 13
		case "MEDIUM":
			score -= 6
		case "LOW":
			score -= 2.5
		case "INFO":
			score -= 0.3
		}
	}
	if score < 0 {
		score = 0
	}
	return gradeFromScore(score), score
}
func sevCounts(fs []Finding) map[string]int {
	m := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	for _, f := range fs {
		m[strings.ToUpper(f.Severity)]++
	}
	return m
}
func newReport(target string) *Report {
	g, s := "", 0.0
	_ = g
	_ = s
	return &Report{
		Tool:      APPNAME,
		Tagline:   TAGLINE,
		Version:   VERSION,
		Target:    target,
		Generated: time.Now().Format("2006-01-02 15:04:05 -0700"),
	}
}
func (r *Report) finalize() {
	sortFindings(r.Findings)
	r.Grade, r.Score = computePosture(r.Findings)
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func exportJSON(r *Report) string {
	r.finalize()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(r)
	return buf.String()
}

func exportCSV(r *Report) string {
	r.finalize()
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"id", "severity", "score", "category", "title", "attck", "cwe", "location", "description", "remediation"})
	for _, f := range r.Findings {
		w.Write([]string{f.ID, f.Severity, strconv.FormatFloat(f.Score, 'f', 1, 64), f.Category, f.Title, strings.Join(f.ATTCK, " "), f.CWE, f.Location, oneLine(f.Description), oneLine(f.Remediation)})
	}
	w.Flush()
	return buf.String()
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}

func exportTXT(r *Report) string {
	r.finalize()
	var b strings.Builder
	bar := strings.Repeat("=", 72)
	b.WriteString(bar + "\n")
	b.WriteString("  " + r.Tool + " — " + r.Tagline + "\n")
	b.WriteString("  Author: khaled.s.haddad    Site: owlsec.org    Version: " + r.Version + "\n")
	b.WriteString(bar + "\n")
	b.WriteString("Target    : " + r.Target + "\n")
	b.WriteString("Generated : " + r.Generated + "\n")
	b.WriteString(fmt.Sprintf("Posture   : %s (%.1f/100)\n", r.Grade, r.Score))
	c := sevCounts(r.Findings)
	b.WriteString(fmt.Sprintf("Findings  : %d  [CRIT %d | HIGH %d | MED %d | LOW %d | INFO %d]\n",
		len(r.Findings), c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"], c["INFO"]))
	if len(r.Stats) > 0 {
		b.WriteString("\n-- Statistics --\n")
		for _, kv := range r.Stats {
			b.WriteString(fmt.Sprintf("  %-28s : %s\n", kv.K, kv.V))
		}
	}
	if len(r.Findings) > 0 {
		b.WriteString("\n-- Findings --\n")
		for i, f := range r.Findings {
			b.WriteString(fmt.Sprintf("\n[%d] %s  (%s, score %.1f)\n", i+1, f.Title, f.Severity, f.Score))
			b.WriteString("    id         : " + f.ID + "\n")
			b.WriteString("    category   : " + f.Category + "\n")
			if len(f.ATTCK) > 0 {
				b.WriteString("    att&ck     : " + annotateATTCK(f.ATTCK) + "\n")
			}
			if f.CWE != "" {
				b.WriteString("    cwe        : " + f.CWE + "\n")
			}
			if f.Location != "" {
				b.WriteString("    location   : " + f.Location + "\n")
			}
			if f.Description != "" {
				b.WriteString("    detail     : " + f.Description + "\n")
			}
			if f.Evidence != "" {
				b.WriteString("    evidence   : " + oneLine(f.Evidence) + "\n")
			}
			if f.Remediation != "" {
				b.WriteString("    fix        : " + f.Remediation + "\n")
			}
		}
	}
	if len(r.Notes) > 0 {
		b.WriteString("\n-- Notes --\n")
		for _, n := range r.Notes {
			b.WriteString("  * " + n + "\n")
		}
	}
	b.WriteString("\n" + bar + "\n")
	return b.String()
}

func exportMD(r *Report) string {
	r.finalize()
	var b strings.Builder
	b.WriteString("# " + r.Tool + " Report\n\n")
	b.WriteString("*" + r.Tagline + "*\n\n")
	b.WriteString("| Field | Value |\n|---|---|\n")
	b.WriteString("| Target | " + mdEsc(r.Target) + " |\n")
	b.WriteString("| Generated | " + r.Generated + " |\n")
	b.WriteString("| Version | " + r.Version + " |\n")
	b.WriteString(fmt.Sprintf("| Posture | **%s** (%.1f/100) |\n", r.Grade, r.Score))
	c := sevCounts(r.Findings)
	b.WriteString(fmt.Sprintf("| Findings | %d (C%d/H%d/M%d/L%d/I%d) |\n\n",
		len(r.Findings), c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"], c["INFO"]))
	if len(r.Stats) > 0 {
		b.WriteString("## Statistics\n\n| Metric | Value |\n|---|---|\n")
		for _, kv := range r.Stats {
			b.WriteString("| " + mdEsc(kv.K) + " | " + mdEsc(kv.V) + " |\n")
		}
		b.WriteString("\n")
	}
	if len(r.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		for i, f := range r.Findings {
			b.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, mdEsc(f.Title)))
			b.WriteString("- **Severity:** " + f.Severity + fmt.Sprintf(" (score %.1f)\n", f.Score))
			b.WriteString("- **ID:** `" + f.ID + "`\n")
			b.WriteString("- **Category:** " + mdEsc(f.Category) + "\n")
			if len(f.ATTCK) > 0 {
				b.WriteString("- **ATT&CK:** " + annotateATTCK(f.ATTCK) + "\n")
			}
			if f.CWE != "" {
				b.WriteString("- **CWE:** " + f.CWE + "\n")
			}
			if f.Location != "" {
				b.WriteString("- **Location:** `" + f.Location + "`\n")
			}
			if f.Description != "" {
				b.WriteString("- **Detail:** " + mdEsc(f.Description) + "\n")
			}
			if f.Evidence != "" {
				b.WriteString("- **Evidence:** `" + oneLine(f.Evidence) + "`\n")
			}
			if f.Remediation != "" {
				b.WriteString("- **Fix:** " + mdEsc(f.Remediation) + "\n")
			}
			b.WriteString("\n")
		}
	}
	if len(r.Notes) > 0 {
		b.WriteString("## Notes\n\n")
		for _, n := range r.Notes {
			b.WriteString("- " + mdEsc(n) + "\n")
		}
	}
	return b.String()
}

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

func sarifLevel(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW", "INFO":
		return "note"
	default:
		return "none"
	}
}

func exportSARIF(r *Report) string {
	r.finalize()
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription sarifMsg          `json:"shortDescription"`
		FullDescription  sarifMsg          `json:"fullDescription"`
		HelpURI          string            `json:"helpUri,omitempty"`
		Properties       map[string]any    `json:"properties,omitempty"`
		DefaultConfig    map[string]string `json:"defaultConfiguration,omitempty"`
	}
	type sarifArtifact struct {
		URI string `json:"uri"`
	}
	type sarifRegion struct {
		StartLine int `json:"startLine,omitempty"`
	}
	type sarifPhys struct {
		ArtifactLocation sarifArtifact `json:"artifactLocation"`
		Region           *sarifRegion  `json:"region,omitempty"`
	}
	type sarifLoc struct {
		PhysicalLocation sarifPhys `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID    string         `json:"ruleId"`
		Level     string         `json:"level"`
		Message   sarifMsg       `json:"message"`
		Locations []sarifLoc     `json:"locations,omitempty"`
		Props     map[string]any `json:"properties,omitempty"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifDoc struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}
	ruleSeen := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult
	for _, f := range r.Findings {
		if !ruleSeen[f.ID] {
			ruleSeen[f.ID] = true
			props := map[string]any{"severity": f.Severity, "category": f.Category}
			if len(f.ATTCK) > 0 {
				props["attck"] = f.ATTCK
			}
			if f.CWE != "" {
				props["cwe"] = f.CWE
			}
			rules = append(rules, sarifRule{
				ID:               f.ID,
				Name:             f.Title,
				ShortDescription: sarifMsg{Text: f.Title},
				FullDescription:  sarifMsg{Text: nonEmpty(f.Description, f.Title)},
				HelpURI:          "https://owlsec.org",
				Properties:       props,
				DefaultConfig:    map[string]string{"level": sarifLevel(f.Severity)},
			})
		}
		loc := nonEmpty(f.Location, r.Target)
		res := sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMsg{Text: nonEmpty(f.Description, f.Title)},
			Props:   map[string]any{"score": f.Score, "severity": f.Severity},
			Locations: []sarifLoc{{PhysicalLocation: sarifPhys{
				ArtifactLocation: sarifArtifact{URI: loc},
			}}},
		}
		results = append(results, res)
	}
	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           r.Tool,
				Version:        r.Version,
				InformationURI: "https://owlsec.org",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(doc)
	return buf.String()
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func renderReport(r *Report, format string) string {
	switch strings.ToLower(format) {
	case "json":
		return exportJSON(r)
	case "csv":
		return exportCSV(r)
	case "md", "markdown":
		return exportMD(r)
	case "sarif":
		return exportSARIF(r)
	default:
		return exportTXT(r)
	}
}

func emit(r *Report, format, output string) error {
	content := renderReport(r, format)
	if output == "" || output == "-" {
		fmt.Print(content)
		if !strings.HasSuffix(content, "\n") {
			fmt.Println()
		}
		return nil
	}
	if err := os.WriteFile(output, []byte(content), 0644); err != nil {
		return err
	}
	okMsg("wrote " + format + " report to " + output)
	return nil
}

func showFindingsTUI(r *Report) {
	r.finalize()
	if len(r.Findings) == 0 {
		okMsg("no findings")
		return
	}
	rows := [][]string{}
	for _, f := range r.Findings {
		at := strings.Join(f.ATTCK, ",")
		if at == "" {
			at = "-"
		}
		rows = append(rows, []string{f.ID, f.Severity, fmt.Sprintf("%.1f", f.Score), f.Title, at})
	}
	table([]string{"ID", "SEV", "SCORE", "TITLE", "ATT&CK"}, rows)
	fmt.Println()
	info(fmt.Sprintf("posture grade %s (%.1f/100)", r.Grade, r.Score))
}

// ---- shared utility helpers (hexdump, entropy, histograms, formatting) ----
func hexDump(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		sb.WriteString(fmt.Sprintf("%08x  ", i))
		for j := 0; j < 16; j++ {
			if i+j < len(b) {
				sb.WriteString(fmt.Sprintf("%02x ", b[i+j]))
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteString(" ")
			}
		}
		sb.WriteString(" |")
		for j := 0; j < 16 && i+j < len(b); j++ {
			c := b[i+j]
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

func entropyOf(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	var h float64
	n := float64(len(b))
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * mathLog2(p)
	}
	return h
}

func mathLog2(x float64) float64 { return lnApprox(x) / 0.6931471805599453 }

func lnApprox(x float64) float64 {
	if x <= 0 {
		return 0
	}
	k := 0
	for x > 2 {
		x /= 2
		k++
	}
	for x < 0.5 {
		x *= 2
		k--
	}
	y := (x - 1) / (x + 1)
	y2 := y * y
	sum := 0.0
	term := y
	for i := 1; i <= 19; i += 2 {
		sum += term / float64(i)
		term *= y2
	}
	return 2*sum + float64(k)*0.6931471805599453
}

func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for x := n / u; x >= u; x /= u {
		div *= u
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB", "EB"}
	return fmt.Sprintf("%.2f %s", float64(n)/float64(div), units[exp])
}

func commaInt(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

func asciiBar(frac float64, width int) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	fill := int(frac * float64(width))
	if fill > width {
		fill = width
	}
	return strings.Repeat("\u2588", fill) + strings.Repeat("\u2591", width-fill)
}

func byteHistogram(b []byte) [256]int {
	var h [256]int
	for _, c := range b {
		h[c]++
	}
	return h
}

func truncStr(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	if n < 1 {
		return ""
	}
	return string(r[:n-1]) + "\u2026"
}

func minI(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func absI(a int) int {
	if a < 0 {
		return -a
	}
	return a
}
func clampF(x, lo, hi float64) float64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

func kvTable(pairs []KV) {
	rows := [][]string{}
	for _, kv := range pairs {
		rows = append(rows, []string{kv.K, kv.V})
	}
	table([]string{"METRIC", "VALUE"}, rows)
}

func printHelpSection(title string, lines []string) {
	fmt.Println(col("  "+title, R+B))
	for _, l := range lines {
		fmt.Println("    " + l)
	}
	fmt.Println()
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		out = append(out, l)
	}
	return out, nil
}

func wrapText(s string, width int) []string {
	words := strings.Fields(s)
	var lines []string
	cur := ""
	for _, w := range words {
		if len(cur)+len(w)+1 > width {
			lines = append(lines, cur)
			cur = w
		} else if cur == "" {
			cur = w
		} else {
			cur += " " + w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// atoiSafe parses an int, returning def on error.
func atoiSafe(s string, def int) int {
	s = strings.TrimSpace(s)
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

// splitCSVLine does minimal CSV field splitting on a single line.
func splitCSVLine(s string) []string {
	var out []string
	var cur strings.Builder
	inq := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inq = !inq
		case c == ',' && !inq:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out
}

// ---- shared MITRE ATT&CK + CWE reference (used by finding renderers) ----
var attckNames = map[string]string{
	"T1003":     "OS Credential Dumping",
	"T1003.001": "LSASS Memory",
	"T1005":     "Data from Local System",
	"T1016":     "System Network Configuration Discovery",
	"T1018":     "Remote System Discovery",
	"T1021":     "Remote Services",
	"T1021.001": "Remote Desktop Protocol",
	"T1021.002": "SMB/Windows Admin Shares",
	"T1033":     "System Owner/User Discovery",
	"T1036":     "Masquerading",
	"T1040":     "Network Sniffing",
	"T1046":     "Network Service Discovery",
	"T1048":     "Exfiltration Over Alternative Protocol",
	"T1055":     "Process Injection",
	"T1057":     "Process Discovery",
	"T1059":     "Command and Scripting Interpreter",
	"T1068":     "Exploitation for Privilege Escalation",
	"T1070":     "Indicator Removal",
	"T1070.002": "Clear Linux or Mac System Logs",
	"T1071":     "Application Layer Protocol",
	"T1071.001": "Web Protocols",
	"T1071.004": "DNS",
	"T1078":     "Valid Accounts",
	"T1082":     "System Information Discovery",
	"T1083":     "File and Directory Discovery",
	"T1090":     "Proxy",
	"T1095":     "Non-Application Layer Protocol",
	"T1098":     "Account Manipulation",
	"T1110":     "Brute Force",
	"T1110.001": "Password Guessing",
	"T1110.003": "Password Spraying",
	"T1133":     "External Remote Services",
	"T1135":     "Network Share Discovery",
	"T1136":     "Create Account",
	"T1190":     "Exploit Public-Facing Application",
	"T1203":     "Exploitation for Client Execution",
	"T1210":     "Exploitation of Remote Services",
	"T1211":     "Exploitation for Defense Evasion",
	"T1217":     "Browser Information Discovery",
	"T1222":     "File and Directory Permissions Modification",
	"T1222.001": "Windows File and Directory Permissions Modification",
	"T1222.002": "Linux and Mac File and Directory Permissions Modification",
	"T1480":     "Execution Guardrails",
	"T1485":     "Data Destruction",
	"T1486":     "Data Encrypted for Impact",
	"T1489":     "Service Stop",
	"T1498":     "Network Denial of Service",
	"T1499":     "Endpoint Denial of Service",
	"T1518":     "Software Discovery",
	"T1543":     "Create or Modify System Process",
	"T1543.002": "Systemd Service",
	"T1547":     "Boot or Logon Autostart Execution",
	"T1548":     "Abuse Elevation Control Mechanism",
	"T1548.001": "Setuid and Setgid",
	"T1552":     "Unsecured Credentials",
	"T1552.001": "Credentials In Files",
	"T1552.004": "Private Keys",
	"T1553":     "Subvert Trust Controls",
	"T1557":     "Adversary-in-the-Middle",
	"T1557.001": "LLMNR/NBT-NS Poisoning and SMB Relay",
	"T1562":     "Impair Defenses",
	"T1562.001": "Disable or Modify Tools",
	"T1565":     "Data Manipulation",
	"T1565.001": "Stored Data Manipulation",
	"T1570":     "Lateral Tool Transfer",
	"T1571":     "Non-Standard Port",
	"T1572":     "Protocol Tunneling",
	"T1573":     "Encrypted Channel",
	"T1573.001": "Symmetric Cryptography",
	"T1574":     "Hijack Execution Flow",
	"T1589":     "Gather Victim Identity Information",
	"T1590":     "Gather Victim Network Information",
	"T1595":     "Active Scanning",
	"T1599":     "Network Boundary Bridging",
	"T1600":     "Weaken Encryption",
	"T1602":     "Data from Configuration Repository",
	"T1610":     "Deploy Container",
	"T1611":     "Escape to Host",
}

var cweNames = map[string]string{
	"CWE-22":   "Path Traversal",
	"CWE-78":   "OS Command Injection",
	"CWE-79":   "Cross-site Scripting",
	"CWE-89":   "SQL Injection",
	"CWE-200":  "Exposure of Sensitive Information",
	"CWE-209":  "Information Exposure Through an Error Message",
	"CWE-250":  "Execution with Unnecessary Privileges",
	"CWE-269":  "Improper Privilege Management",
	"CWE-276":  "Incorrect Default Permissions",
	"CWE-295":  "Improper Certificate Validation",
	"CWE-306":  "Missing Authentication for Critical Function",
	"CWE-307":  "Improper Restriction of Excessive Authentication Attempts",
	"CWE-311":  "Missing Encryption of Sensitive Data",
	"CWE-312":  "Cleartext Storage of Sensitive Information",
	"CWE-319":  "Cleartext Transmission of Sensitive Information",
	"CWE-326":  "Inadequate Encryption Strength",
	"CWE-327":  "Use of a Broken or Risky Cryptographic Algorithm",
	"CWE-328":  "Use of Weak Hash",
	"CWE-330":  "Use of Insufficiently Random Values",
	"CWE-338":  "Use of Cryptographically Weak PRNG",
	"CWE-521":  "Weak Password Requirements",
	"CWE-522":  "Insufficiently Protected Credentials",
	"CWE-532":  "Insertion of Sensitive Information into Log File",
	"CWE-601":  "Open Redirect",
	"CWE-732":  "Incorrect Permission Assignment for Critical Resource",
	"CWE-798":  "Use of Hard-coded Credentials",
	"CWE-918":  "Server-Side Request Forgery",
	"CWE-1104": "Use of Unmaintained Third Party Components",
}

func attckName(id string) string {
	if n, ok := attckNames[id]; ok {
		return n
	}
	return id
}

func cweName(id string) string {
	if !strings.HasPrefix(id, "CWE-") {
		id = "CWE-" + id
	}
	if n, ok := cweNames[id]; ok {
		return id + " (" + n + ")"
	}
	return id
}

func annotateATTCK(ids []string) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if n := attckName(id); n != id {
			parts = append(parts, id+" "+n)
		} else {
			parts = append(parts, id)
		}
	}
	return strings.Join(parts, ", ")
}

// printTechniqueCatalog lists all known ATT&CK techniques referenced by the suite.
func printTechniqueCatalog() {
	var ids []string
	for id := range attckNames {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows := [][]string{}
	for _, id := range ids {
		rows = append(rows, []string{id, attckNames[id]})
	}
	table([]string{"TECHNIQUE", "NAME"}, rows)
}

// ============================================================================
//  OTreeMap domain engine — recursive disk-usage analyzer with an ASCII
//  treemap, largest-item ranking, extension statistics, depth profiling,
//  prune suggestions, and snapshot-based growth tracking. Read-only.
// ============================================================================

type node struct {
	name     string
	path     string
	isDir    bool
	size     int64 // own size (files) or aggregate (dirs)
	self     int64 // bytes directly in this dir (non-recursive files)
	count    int64 // number of files in subtree
	dirs     int64 // number of directories in subtree
	depth    int
	mode     os.FileMode
	modTime  time.Time
	children []*node
}

type duConfig struct {
	root       string
	maxDepth   int
	minSize    int64
	followLink bool
	includeHid bool
	oneFS      bool
	apparent   bool
}

func defaultDU(root string) duConfig { return duConfig{root: root, maxDepth: 64} }

// buildTree walks the filesystem and constructs an aggregated size tree.
func buildTree(cfg duConfig) (*node, []string, error) {
	var warns []string
	root := &node{name: filepath.Base(cfg.root), path: cfg.root, isDir: true, depth: 0}
	nodes := map[string]*node{cfg.root: root}
	walkFn := func(p string, d os.DirEntry, err error) error {
		if err != nil {
			warns = append(warns, "access: "+p+": "+err.Error())
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if p == cfg.root {
			info, _ := d.Info()
			if info != nil {
				root.modTime = info.ModTime()
				root.mode = info.Mode()
			}
			return nil
		}
		name := d.Name()
		if !cfg.includeHid && strings.HasPrefix(name, ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(cfg.root, p)
		depth := strings.Count(rel, string(os.PathSeparator)) + 1
		if cfg.maxDepth > 0 && depth > cfg.maxDepth && d.IsDir() {
			return filepath.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			warns = append(warns, "stat: "+p+": "+err.Error())
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 && !cfg.followLink {
			return nil
		}
		parent := nodes[filepath.Dir(p)]
		if parent == nil {
			parent = root
		}
		n := &node{name: name, path: p, isDir: d.IsDir(), depth: depth, mode: info.Mode(), modTime: info.ModTime()}
		if d.IsDir() {
			nodes[p] = n
		} else {
			n.size = info.Size()
			n.count = 1
		}
		parent.children = append(parent.children, n)
		return nil
	}
	err := filepath.WalkDir(cfg.root, walkFn)
	aggregate(root)
	return root, warns, err
}

// aggregate computes subtree sizes/counts bottom-up.
func aggregate(n *node) {
	if !n.isDir {
		n.count = 1
		return
	}
	var total, selfBytes, count, dirs int64
	for _, c := range n.children {
		aggregate(c)
		total += c.size
		count += c.count
		if c.isDir {
			dirs += c.dirs + 1
		} else {
			selfBytes += c.size
		}
	}
	n.size = total
	n.self = selfBytes
	n.count = count
	n.dirs = dirs
	sort.Slice(n.children, func(i, j int) bool { return n.children[i].size > n.children[j].size })
}

// flatten returns all nodes (optionally only dirs or only files).
func flatten(n *node, dirsOnly, filesOnly bool) []*node {
	var out []*node
	var rec func(*node)
	rec = func(x *node) {
		if x.isDir && !filesOnly {
			out = append(out, x)
		}
		if !x.isDir && !dirsOnly {
			out = append(out, x)
		}
		for _, c := range x.children {
			rec(c)
		}
	}
	rec(n)
	return out
}

func largestNodes(root *node, dirsOnly, filesOnly bool, n int) []*node {
	all := flatten(root, dirsOnly, filesOnly)
	sort.Slice(all, func(i, j int) bool { return all[i].size > all[j].size })
	if len(all) > n {
		all = all[:n]
	}
	return all
}

// findNode locates a node by path.
func findNode(root *node, path string) *node {
	if root.path == path {
		return root
	}
	for _, c := range root.children {
		if n := findNode(c, path); n != nil {
			return n
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Extension statistics
// ---------------------------------------------------------------------------

type extAgg struct {
	ext   string
	count int64
	bytes int64
}

func extensionStats(root *node) []extAgg {
	m := map[string]*extAgg{}
	for _, f := range flatten(root, false, true) {
		e := strings.ToLower(filepath.Ext(f.name))
		if e == "" {
			e = "(none)"
		}
		if m[e] == nil {
			m[e] = &extAgg{ext: e}
		}
		m[e].count++
		m[e].bytes += f.size
	}
	var out []extAgg
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].bytes > out[j].bytes })
	return out
}

// ---------------------------------------------------------------------------
// Depth profile + small-file analysis
// ---------------------------------------------------------------------------

func depthProfile(root *node) map[int]int64 {
	m := map[int]int64{}
	for _, f := range flatten(root, false, true) {
		m[f.depth]++
	}
	return m
}

// maxDepth reports the deepest *directory* nesting level (files don't add a
// level), matching the "nested tree" notion the depth finding describes.
func maxDepth(root *node) int {
	max := 0
	for _, f := range flatten(root, true, false) {
		if f.depth > max {
			max = f.depth
		}
	}
	return max
}

func smallFileCount(root *node, threshold int64) (int64, int64) {
	var n, bytes int64
	for _, f := range flatten(root, false, true) {
		if f.size < threshold {
			n++
			bytes += f.size
		}
	}
	return n, bytes
}

// ---------------------------------------------------------------------------
// ASCII treemap (squarified layout into a character grid)
// ---------------------------------------------------------------------------

type rect struct {
	x, y, w, h int
	n          *node
}

// squarify lays out children into the given rectangle proportionally to size.
func squarify(children []*node, x, y, w, h int, out *[]rect) {
	if w <= 0 || h <= 0 || len(children) == 0 {
		return
	}
	var total int64
	for _, c := range children {
		total += c.size + 1
	}
	if total == 0 {
		return
	}
	// split along the longer axis recursively (slice-and-dice variant)
	if w >= h {
		cx := x
		for i, c := range children {
			cw := int(float64(w) * float64(c.size+1) / float64(total))
			if i == len(children)-1 {
				cw = x + w - cx
			}
			if cw < 1 {
				cw = 1
			}
			*out = append(*out, rect{cx, y, cw, h, c})
			cx += cw
			if cx >= x+w {
				break
			}
		}
	} else {
		cy := y
		for i, c := range children {
			ch := int(float64(h) * float64(c.size+1) / float64(total))
			if i == len(children)-1 {
				ch = y + h - cy
			}
			if ch < 1 {
				ch = 1
			}
			*out = append(*out, rect{x, cy, w, ch, c})
			cy += ch
			if cy >= y+h {
				break
			}
		}
	}
}

func renderTreemap(root *node, width, height int) string {
	if width < 10 {
		width = 60
	}
	if height < 5 {
		height = 16
	}
	grid := make([][]rune, height)
	labels := make([][]rune, height)
	for i := range grid {
		grid[i] = make([]rune, width)
		labels[i] = make([]rune, width)
		for j := range grid[i] {
			grid[i][j] = ' '
			labels[i][j] = ' '
		}
	}
	children := root.children
	if len(children) > 24 {
		children = children[:24]
	}
	var rects []rect
	squarify(children, 0, 0, width, height, &rects)
	shades := []rune{'\u2591', '\u2592', '\u2593', '\u2588'}
	for idx, r := range rects {
		sh := shades[idx%len(shades)]
		for yy := r.y; yy < r.y+r.h && yy < height; yy++ {
			for xx := r.x; xx < r.x+r.w && xx < width; xx++ {
				grid[yy][xx] = sh
			}
		}
		// place a short label
		lbl := []rune(truncStr(r.n.name, maxI(r.w-1, 1)))
		if r.h >= 1 && r.w >= 2 {
			ly := r.y + r.h/2
			for i, ch := range lbl {
				if r.x+i < width && ly < height {
					labels[ly][r.x+i] = ch
				}
			}
		}
	}
	var b strings.Builder
	for i := 0; i < height; i++ {
		for j := 0; j < width; j++ {
			if labels[i][j] != ' ' {
				b.WriteRune(labels[i][j])
			} else {
				b.WriteRune(grid[i][j])
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Prune suggestions
// ---------------------------------------------------------------------------

type pruneSuggestion struct {
	path   string
	size   int64
	reason string
	age    time.Duration
}

var cacheDirNames = []string{"node_modules", ".cache", "cache", "tmp", ".tmp", "__pycache__", ".gradle", ".m2", "target", "build", "dist", ".venv", "venv", ".npm", ".cargo", "Downloads"}

func isCacheLike(name string) bool {
	low := strings.ToLower(name)
	for _, c := range cacheDirNames {
		if low == strings.ToLower(c) {
			return true
		}
	}
	return false
}

func pruneSuggestions(root *node, minSize int64) []pruneSuggestion {
	var out []pruneSuggestion
	for _, d := range flatten(root, true, false) {
		if d.size < minSize {
			continue
		}
		age := time.Since(d.modTime)
		switch {
		case isCacheLike(d.name):
			out = append(out, pruneSuggestion{d.path, d.size, "cache/build directory — usually regenerable", age})
		case age > 365*24*time.Hour && d.size > minSize*4:
			out = append(out, pruneSuggestion{d.path, d.size, "large and untouched for over a year", age})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].size > out[j].size })
	return out
}

// ---------------------------------------------------------------------------
// Snapshot save / load / growth diff
// ---------------------------------------------------------------------------

type snapEntry struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	Dir  bool   `json:"dir"`
}

type snapshot struct {
	Root    string      `json:"root"`
	Created string      `json:"created"`
	Total   int64       `json:"total"`
	Entries []snapEntry `json:"entries"`
}

func makeSnapshot(root *node) *snapshot {
	s := &snapshot{Root: root.path, Created: time.Now().Format(time.RFC3339), Total: root.size}
	for _, d := range flatten(root, true, false) {
		s.Entries = append(s.Entries, snapEntry{Path: d.path, Size: d.size, Dir: true})
	}
	return s
}

func saveSnapshot(s *snapshot, path string) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0644)
}

func loadSnapshot(path string) (*snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

type growthRow struct {
	path  string
	old   int64
	cur   int64
	delta int64
}

func growthDiff(old *snapshot, root *node) []growthRow {
	oldMap := map[string]int64{}
	for _, e := range old.Entries {
		oldMap[e.Path] = e.Size
	}
	var rows []growthRow
	for _, d := range flatten(root, true, false) {
		o := oldMap[d.path]
		if o != d.size {
			rows = append(rows, growthRow{d.path, o, d.size, d.size - o})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return absI64(rows[i].delta) > absI64(rows[j].delta) })
	return rows
}

func absI64(a int64) int64 {
	if a < 0 {
		return -a
	}
	return a
}

// ---------------------------------------------------------------------------
// Report builder
// ---------------------------------------------------------------------------

var bigLogExts = []string{".log", ".log.1", ".out", ".err"}

func buildReport(root *node, cfg duConfig, warns []string) *Report {
	r := newReport(cfg.root)
	md := maxDepth(root)
	smallN, smallB := smallFileCount(root, 4096)
	r.Stats = append(r.Stats,
		KV{"root", cfg.root},
		KV{"total_size", humanBytes(root.size)},
		KV{"files", commaInt(root.count)},
		KV{"directories", commaInt(root.dirs)},
		KV{"max_depth", strconv.Itoa(md)},
		KV{"small_files_<4K", fmt.Sprintf("%s (%s)", commaInt(smallN), humanBytes(smallB))},
	)
	// biggest child share
	if len(root.children) > 0 && root.size > 0 {
		top := root.children[0]
		share := float64(top.size) / float64(root.size)
		r.Stats = append(r.Stats, KV{"largest_child", fmt.Sprintf("%s (%.0f%%)", top.name, share*100)})
		if share > 0.7 {
			r.Findings = append(r.Findings, Finding{ID: "TM-DOMINANT-DIR", Title: "One directory dominates usage",
				Severity: "LOW", Category: "distribution", Score: 2.0,
				Description: fmt.Sprintf("'%s' accounts for %.0f%% of all bytes; most reclaim potential is concentrated there.", top.name, share*100),
				Location:    top.path})
		}
	}
	// many tiny files
	if root.count > 0 && float64(smallN)/float64(root.count) > 0.6 && root.count > 1000 {
		r.Findings = append(r.Findings, Finding{ID: "TM-MANY-SMALL", Title: "Large number of tiny files",
			Severity: "LOW", Category: "inode", Score: 2.5,
			Description: fmt.Sprintf("%s files (%.0f%%) are under 4K; these waste inodes and slow backups even though bytes are modest.", commaInt(smallN), 100*float64(smallN)/float64(root.count))})
	}
	// deep nesting
	if md > 20 {
		r.Findings = append(r.Findings, Finding{ID: "TM-DEEP-NESTING", Title: "Very deep directory nesting",
			Severity: "INFO", Category: "structure", Score: 0.5,
			Description: fmt.Sprintf("Maximum depth is %d; deeply nested trees (often node_modules-style) complicate tooling and backup.", md)})
	}
	// cache/prune candidates
	ps := pruneSuggestions(root, maxI64(root.size/100, 1024*1024))
	var pruneTotal int64
	for _, p := range ps {
		pruneTotal += p.size
	}
	if len(ps) > 0 {
		r.Stats = append(r.Stats, KV{"prunable_candidates", fmt.Sprintf("%d (%s)", len(ps), humanBytes(pruneTotal))})
		r.Findings = append(r.Findings, Finding{ID: "TM-PRUNABLE", Title: "Reclaimable cache/build directories found",
			Severity: "MEDIUM", Category: "storage", Score: 4.0,
			Description: fmt.Sprintf("%d cache/build/old directories totalling %s may be safely removable.", len(ps), humanBytes(pruneTotal)),
			Remediation: "Review prune suggestions; regenerable caches can usually be deleted.",
			Evidence:    ps[0].path})
	}
	// large logs
	for _, f := range flatten(root, false, true) {
		e := strings.ToLower(filepath.Ext(f.name))
		for _, le := range bigLogExts {
			if e == le && f.size > 100*1024*1024 {
				r.Findings = append(r.Findings, Finding{ID: "TM-HUGE-LOG", Title: "Oversized log file",
					Severity: "MEDIUM", Category: "logging", Score: 4.0, ATTCK: []string{"T1070"},
					Description: fmt.Sprintf("Log file is %s; unrotated logs waste space and can hide tampering.", humanBytes(f.size)),
					Location:    f.path, Remediation: "Enable logrotate / size-capped rotation."})
				break
			}
		}
	}
	// world-writable big dirs
	for _, d := range flatten(root, true, false) {
		if d.mode&0002 != 0 && d.size > 10*1024*1024 {
			r.Findings = append(r.Findings, Finding{ID: "TM-WW-DIR", Title: "World-writable large directory",
				Severity: "MEDIUM", Category: "permissions", Score: 5.0, ATTCK: []string{"T1222.002"},
				Description: fmt.Sprintf("World-writable directory holding %s; anyone can add/replace files.", humanBytes(d.size)),
				Location:    d.path, Remediation: "chmod o-w and audit contents."})
			break
		}
	}
	if p := permissionSummary(root); p.worldWritable > 0 || p.setuid > 0 {
		r.Stats = append(r.Stats, KV{"world_writable", commaInt(p.worldWritable)}, KV{"setuid_items", commaInt(p.setuid)})
	}
	r.Stats = append(r.Stats, KV{"age_spread", ageSpreadLabel(root)})
	for _, c := range categorize(root) {
		r.Stats = append(r.Stats, KV{"cat:" + c.K, c.V})
	}
	if orig, est := compressionEstimate(root); orig > 0 && est < orig*8/10 {
		r.Findings = append(r.Findings, Finding{ID: "TM-COMPRESSIBLE", Title: "Significant compression opportunity",
			Severity: "INFO", Category: "storage", Score: 0.5,
			Description: fmt.Sprintf("Text-like files could compress from %s to ~%s (save %s).", humanBytes(orig), humanBytes(est), humanBytes(orig-est))})
	}
	for _, rc := range recommendations(root, cfg) {
		if len(r.Notes) < 20 {
			r.Notes = append(r.Notes, "advice: "+rc)
		}
	}
	for _, w := range warns {
		if len(r.Notes) < 25 {
			r.Notes = append(r.Notes, w)
		}
	}
	return r
}

func maxI64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// top-N rows for TUI
func largestRows(root *node, dirsOnly, filesOnly bool, n int) [][]string {
	rows := [][]string{}
	for _, x := range largestNodes(root, dirsOnly, filesOnly, n) {
		share := 0.0
		if root.size > 0 {
			share = float64(x.size) / float64(root.size)
		}
		rows = append(rows, []string{humanBytes(x.size), asciiBar(share, 14), truncStr(x.path, 50)})
	}
	return rows
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

func usage() {
	banner()
	w := os.Stdout
	fmt.Fprintln(w, col("  USAGE", R+B)+"  "+APPNAME+" [flags]")
	fmt.Fprintln(w, col("  No flags → interactive TUI.  Flags → one-shot CLI. Read-only.", GY))
	fmt.Fprintln(w)
	printHelpSection("SCAN", []string{
		"--path DIR         directory to analyze (required for CLI)",
		"--max-depth N      limit recursion depth (default 64)",
		"--min-size SIZE    ignore items smaller than SIZE for suggestions",
		"--hidden           include dotfiles/dotdirs",
		"--follow-symlinks  follow symbolic links",
	})
	printHelpSection("VIEWS", []string{
		"--top N            show top-N largest items (default 15)",
		"--dirs             rank largest directories",
		"--files            rank largest files",
		"--ext-stats        extension size breakdown",
		"--treemap          render an ASCII treemap",
		"--tm-width N       treemap width (default 70)",
		"--tm-height N      treemap height (default 18)",
		"--prune            list prune/reclaim suggestions",
		"--age              file age histogram",
		"--perms            permission/ownership summary",
		"--categories       storage category breakdown",
		"--hot              directories with most files",
		"--compress         compression-potential estimate",
		"--recommend        storage recommendations",
	})
	printHelpSection("GROWTH", []string{
		"--snapshot FILE    save a directory-size snapshot and exit",
		"--baseline FILE    compare current tree to a saved snapshot",
	})
	printHelpSection("REPORTING", []string{
		"--format FMT       txt|md|json|csv|sarif (default txt)",
		"--output FILE      write report to FILE",
		"--no-color         disable ANSI colour",
	})
	printHelpSection("GENERAL", []string{
		"--demo             synthetic demo tree",
		"--selftest         internal tests",
		"--version          print version",
		"-h, --help         this help",
	})
	printHelpSection("EXAMPLES", []string{
		APPNAME + " --path / --top 20 --treemap",
		APPNAME + " --path ~/projects --prune --format md --output du.md",
		APPNAME + " --path /var --snapshot base.json",
	})
	line(64)
}

func printVersion() {
	fmt.Printf("%s %s  (OWL suite — khaled.s.haddad / owlsec.org)\n", APPNAME, VERSION)
}

var lastRoot *node
var lastCfg duConfig
var lastReport *Report

func main() {
	var (
		path      string
		maxDepthF int
		minSize   string
		top       int
		dirsF     bool
		filesF    bool
		extF      bool
		treemapF  bool
		tmW       int
		tmH       int
		pruneF    bool
		snapF     string
		baseF     string
		hidden    bool
		follow    bool
		format    string
		output    string
		nocolor   bool
		demo      bool
		selftest  bool
		showVer   bool
	)
	fs := flag.NewFlagSet(APPNAME, flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = usage
	fs.StringVar(&path, "path", "", "")
	fs.StringVar(&path, "target", "", "")
	fs.IntVar(&maxDepthF, "max-depth", 64, "")
	fs.StringVar(&minSize, "min-size", "0", "")
	fs.IntVar(&top, "top", 15, "")
	fs.BoolVar(&dirsF, "dirs", false, "")
	fs.BoolVar(&filesF, "files", false, "")
	fs.BoolVar(&extF, "ext-stats", false, "")
	fs.BoolVar(&treemapF, "treemap", false, "")
	fs.IntVar(&tmW, "tm-width", 70, "")
	fs.IntVar(&tmH, "tm-height", 18, "")
	fs.BoolVar(&pruneF, "prune", false, "")
	fs.StringVar(&snapF, "snapshot", "", "")
	fs.StringVar(&baseF, "baseline", "", "")
	fs.BoolVar(&hidden, "hidden", false, "")
	fs.BoolVar(&follow, "follow-symlinks", false, "")
	fs.StringVar(&format, "format", "txt", "")
	fs.StringVar(&output, "output", "", "")
	fs.BoolVar(&nocolor, "no-color", false, "")
	fs.BoolVar(&demo, "demo", false, "")
	fs.BoolVar(&selftest, "selftest", false, "")
	fs.BoolVar(&showVer, "version", false, "")
	ageF := fs.Bool("age", false, "")
	permsF := fs.Bool("perms", false, "")
	catsF := fs.Bool("categories", false, "")
	hotF := fs.Bool("hot", false, "")
	recF := fs.Bool("recommend", false, "")
	compF := fs.Bool("compress", false, "")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return
		}
		errMsg(err.Error())
		os.Exit(2)
	}
	if nocolor {
		noColor = true
	}
	switch {
	case showVer:
		printVersion()
		return
	case selftest:
		runSelfTest()
		return
	case demo:
		runDemo(format, output)
		return
	case path != "":
		cfg := defaultDU(path)
		cfg.maxDepth = maxDepthF
		cfg.minSize = parseSizeTM(minSize)
		cfg.includeHid = hidden
		cfg.followLink = follow
		root, warns, err := buildTree(cfg)
		if err != nil && root.size == 0 {
			errMsg(err.Error())
			os.Exit(1)
		}
		if snapF != "" {
			if err := saveSnapshot(makeSnapshot(root), snapF); err != nil {
				errMsg(err.Error())
				os.Exit(1)
			}
			okMsg("saved snapshot to " + snapF)
			return
		}
		rep := buildReport(root, cfg, warns)
		if baseF != "" {
			old, err := loadSnapshot(baseF)
			if err != nil {
				errMsg(err.Error())
				os.Exit(1)
			}
			rows := growthDiff(old, root)
			rep.Stats = append(rep.Stats, KV{"growth_since", old.Created}, KV{"total_delta", humanBytes(root.size - old.Total)})
			for i, g := range rows {
				if i >= 20 {
					break
				}
				sign := "+"
				if g.delta < 0 {
					sign = "-"
				}
				rep.Stats = append(rep.Stats, KV{"Δ " + truncStr(g.path, 40), sign + humanBytes(absI64(g.delta))})
			}
		}
		if extF {
			for i, e := range extensionStats(root) {
				if i >= 10 {
					break
				}
				rep.Stats = append(rep.Stats, KV{"ext:" + e.ext, fmt.Sprintf("%s (%s files)", humanBytes(e.bytes), commaInt(e.count))})
			}
		}
		if dirsF {
			for _, x := range largestNodes(root, true, false, top) {
				rep.Stats = append(rep.Stats, KV{"dir:" + truncStr(x.path, 40), humanBytes(x.size)})
			}
		}
		if filesF {
			for _, x := range largestNodes(root, false, true, top) {
				rep.Stats = append(rep.Stats, KV{"file:" + truncStr(x.path, 40), humanBytes(x.size)})
			}
		}
		if pruneF {
			for i, p := range pruneSuggestions(root, maxI64(cfg.minSize, 1024*1024)) {
				if i >= 20 {
					break
				}
				rep.Notes = append(rep.Notes, fmt.Sprintf("prune %s (%s): %s", p.path, humanBytes(p.size), p.reason))
			}
		}
		if *ageF {
			rep.Stats = append(rep.Stats, ageHistogram(root)...)
		}
		if *permsF {
			p := permissionSummary(root)
			rep.Stats = append(rep.Stats, KV{"world_writable", commaInt(p.worldWritable)}, KV{"setuid", commaInt(p.setuid)}, KV{"setgid", commaInt(p.setgid)}, KV{"executables", commaInt(p.executable)})
		}
		if *catsF {
			for _, c := range categorize(root) {
				rep.Stats = append(rep.Stats, KV{"cat:" + c.K, c.V})
			}
		}
		if *hotF {
			for _, hd := range hotDirectories(root, 15) {
				rep.Stats = append(rep.Stats, KV{"hot:" + truncStr(hd.path, 40), strconv.Itoa(directFileCount(hd)) + " files"})
			}
		}
		if *compF {
			orig, est := compressionEstimate(root)
			rep.Stats = append(rep.Stats, KV{"compress_estimate", fmt.Sprintf("%s -> %s", humanBytes(orig), humanBytes(est))})
		}
		if *recF {
			for _, rc := range recommendations(root, cfg) {
				rep.Notes = append(rep.Notes, "advice: "+rc)
			}
		}
		if treemapF && (format == "txt" || format == "") && output == "" {
			banner()
			fmt.Print(renderTreemap(root, tmW, tmH))
			fmt.Println()
		}
		_ = emit(rep, format, output)
		return
	default:
		interactive()
	}
}

func parseSizeTM(s string) int64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" || s == "0" {
		return 0
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "G"), strings.HasSuffix(s, "GB"):
		mult = 1 << 30
		s = strings.TrimRight(s, "GB")
	case strings.HasSuffix(s, "M"), strings.HasSuffix(s, "MB"):
		mult = 1 << 20
		s = strings.TrimRight(s, "MB")
	case strings.HasSuffix(s, "K"), strings.HasSuffix(s, "KB"):
		mult = 1 << 10
		s = strings.TrimRight(s, "KB")
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0
	}
	return int64(v * float64(mult))
}

// ---------------------------------------------------------------------------
// Demo + self-test
// ---------------------------------------------------------------------------

func runDemo(format, output string) {
	banner()
	info("creating a synthetic directory tree in a temp dir")
	dir, err := os.MkdirTemp("", "otreemap-demo-")
	if err != nil {
		errMsg(err.Error())
		return
	}
	defer os.RemoveAll(dir)
	layout := map[string]int{
		"media/video/clip1.mp4":                  9_000_000,
		"media/video/clip2.mp4":                  7_500_000,
		"media/photos/img1.jpg":                  1_200_000,
		"media/photos/img2.jpg":                  1_100_000,
		"projects/app/node_modules/dep/index.js": 3_000_000,
		"projects/app/src/main.go":               40_000,
		"logs/app.log":                           180_000_000,
		"cache/.cache/blob":                      5_000_000,
		"docs/report.pdf":                        800_000,
	}
	for rel, sz := range layout {
		full := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(full), 0755)
		os.WriteFile(full, make([]byte, sz), 0644)
	}
	// many tiny files
	tinyDir := filepath.Join(dir, "projects/app/node_modules/dep/.cache")
	os.MkdirAll(tinyDir, 0755)
	for i := 0; i < 1200; i++ {
		os.WriteFile(filepath.Join(tinyDir, "t"+strconv.Itoa(i)), []byte("x"), 0644)
	}
	cfg := defaultDU(dir)
	root, warns, _ := buildTree(cfg)
	fmt.Println()
	okMsg("total: " + humanBytes(root.size) + "  files: " + commaInt(root.count))
	fmt.Println()
	fmt.Println("  " + col("ASCII treemap", R+B))
	fmt.Print(renderTreemap(root, 66, 14))
	fmt.Println()
	fmt.Println("  " + col("largest directories", R+B))
	table([]string{"SIZE", "SHARE", "PATH"}, largestRows(root, true, false, 6))
	fmt.Println()
	rep := buildReport(root, cfg, warns)
	rep.Notes = append(rep.Notes, "Demo tree is synthetic and removed on exit.")
	showFindingsTUI(rep)
	fmt.Println()
	if output != "" || format != "txt" {
		_ = emit(rep, format, output)
	}
	okMsg("demo complete")
}

func runSelfTest() {
	banner()
	info("running internal self-tests")
	fmt.Println()
	pass, fail := 0, 0
	check := func(n string, c bool) {
		if c {
			pass++
			okMsg(n)
		} else {
			fail++
			errMsg(n)
		}
	}
	dir, _ := os.MkdirTemp("", "otm-st-")
	defer os.RemoveAll(dir)
	os.MkdirAll(filepath.Join(dir, "a/b"), 0755)
	os.WriteFile(filepath.Join(dir, "a/f1"), make([]byte, 1000), 0644)
	os.WriteFile(filepath.Join(dir, "a/b/f2"), make([]byte, 2000), 0644)
	os.WriteFile(filepath.Join(dir, "top"), make([]byte, 5000), 0644)
	root, _, _ := buildTree(defaultDU(dir))
	check("aggregate total 8000", root.size == 8000)
	check("file count 3", root.count == 3)
	check("dir count >=2", root.dirs >= 2)
	check("max depth 2", maxDepth(root) == 2)
	a := findNode(root, filepath.Join(dir, "a"))
	check("subdir aggregate 3000", a != nil && a.size == 3000)
	check("largest file is top", largestNodes(root, false, true, 1)[0].name == "top")
	es := extensionStats(root)
	check("ext stats non-empty", len(es) >= 1)
	check("parseSizeTM 1M", parseSizeTM("1M") == 1<<20)
	check("isCacheLike node_modules", isCacheLike("node_modules"))
	tm := renderTreemap(root, 40, 8)
	check("treemap renders", len(tm) > 40)
	snap := makeSnapshot(root)
	check("snapshot has entries", len(snap.Entries) >= 2)
	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
	} else {
		errMsg(fmt.Sprintf("%d passed, %d failed", pass, fail))
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Interactive TUI
// ---------------------------------------------------------------------------

func interactive() {
	for {
		choice := menu("Disk Usage Treemap Analyzer", []string{
			"Analyze a directory",
			"ASCII treemap",
			"Largest directories",
			"Largest files",
			"Extension statistics",
			"Depth profile",
			"Prune suggestions",
			"Save snapshot",
			"Growth vs snapshot",
			"Export last report",
			"Drill-down navigator",
			"Age histogram",
			"Permissions & owners",
			"Storage categories",
			"Hot directories",
			"Recommendations",
			"Self-test",
		})
		switch strings.ToLower(choice) {
		case "h", "help", "?":
			tuiHelp()
		case "1":
			tuiAnalyze()
		case "2":
			tuiTreemap()
		case "3":
			tuiLargest(true, false)
		case "4":
			tuiLargest(false, true)
		case "5":
			tuiExt()
		case "6":
			tuiDepth()
		case "7":
			tuiPrune()
		case "8":
			tuiSnapshot()
		case "9":
			tuiGrowth()
		case "10":
			tuiExport()
		case "11":
			tuiDrill()
		case "12":
			tuiAge()
		case "13":
			tuiPerms()
		case "14":
			tuiCategories()
		case "15":
			tuiHot()
		case "16":
			tuiRecommend()
		case "17":
			clear()
			runSelfTest()
			pause()
		case "0", "00", "q", "exit", "":
			clear()
			okMsg("Goodbye — owlsec.org")
			return
		default:
			warnMsg("unknown selection")
			pause()
		}
	}
}

func requireRoot() bool {
	if lastRoot == nil {
		warnMsg("analyze a directory first")
		pause()
		return false
	}
	return true
}

func tuiAnalyze() {
	clear()
	banner()
	p := prompt("directory to analyze")
	if p == "" {
		return
	}
	cfg := defaultDU(p)
	if v, err := strconv.Atoi(prompt("max depth (blank=64)")); err == nil && v > 0 {
		cfg.maxDepth = v
	}
	info("walking...")
	root, warns, err := buildTree(cfg)
	if err != nil && root.size == 0 {
		errMsg(err.Error())
		pause()
		return
	}
	lastRoot = root
	lastCfg = cfg
	lastReport = buildReport(root, cfg, warns)
	fmt.Println()
	for _, kv := range lastReport.Stats {
		info(kv.K + " = " + kv.V)
	}
	fmt.Println()
	showFindingsTUI(lastReport)
	pause()
}

func tuiTreemap() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	fmt.Print(renderTreemap(lastRoot, 72, 20))
	pause()
}

func tuiLargest(dirs, files bool) {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	table([]string{"SIZE", "SHARE", "PATH"}, largestRows(lastRoot, dirs, files, 20))
	pause()
}

func tuiExt() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	rows := [][]string{}
	for i, e := range extensionStats(lastRoot) {
		if i >= 20 {
			break
		}
		rows = append(rows, []string{e.ext, commaInt(e.count), humanBytes(e.bytes)})
	}
	table([]string{"EXT", "FILES", "BYTES"}, rows)
	pause()
}

func tuiDepth() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	dp := depthProfile(lastRoot)
	var depths []int
	for d := range dp {
		depths = append(depths, d)
	}
	sort.Ints(depths)
	var maxC int64
	for _, c := range dp {
		if c > maxC {
			maxC = c
		}
	}
	rows := [][]string{}
	for _, d := range depths {
		rows = append(rows, []string{strconv.Itoa(d), commaInt(dp[d]), asciiBar(float64(dp[d])/float64(maxI64(maxC, 1)), 20)})
	}
	table([]string{"DEPTH", "FILES", ""}, rows)
	pause()
}

func tuiPrune() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	ps := pruneSuggestions(lastRoot, 1024*1024)
	if len(ps) == 0 {
		okMsg("no obvious prune candidates")
	} else {
		rows := [][]string{}
		for i, p := range ps {
			if i >= 20 {
				break
			}
			rows = append(rows, []string{humanBytes(p.size), truncStr(p.path, 40), truncStr(p.reason, 30)})
		}
		table([]string{"SIZE", "PATH", "REASON"}, rows)
	}
	pause()
}

func tuiSnapshot() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	p := prompt("snapshot output path")
	if p == "" {
		return
	}
	if err := saveSnapshot(makeSnapshot(lastRoot), p); err != nil {
		errMsg(err.Error())
	} else {
		okMsg("saved snapshot to " + p)
	}
	pause()
}

func tuiGrowth() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	p := prompt("baseline snapshot path")
	old, err := loadSnapshot(p)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	rows := growthDiff(old, lastRoot)
	okMsg("total delta: " + humanBytes(lastRoot.size-old.Total))
	disp := [][]string{}
	for i, g := range rows {
		if i >= 20 {
			break
		}
		sign := "+"
		if g.delta < 0 {
			sign = "-"
		}
		disp = append(disp, []string{sign + humanBytes(absI64(g.delta)), truncStr(g.path, 48)})
	}
	table([]string{"DELTA", "PATH"}, disp)
	pause()
}

func tuiExport() {
	clear()
	banner()
	if lastReport == nil {
		warnMsg("analyze a directory first")
		pause()
		return
	}
	f := prompt("format txt/md/json/csv/sarif")
	o := prompt("output file (blank=stdout)")
	if err := emit(lastReport, f, o); err != nil {
		errMsg(err.Error())
	}
	pause()
}

// ---------------------------------------------------------------------------
// Part 5 — age/permission/owner summaries, hot directories, empty dirs,
// compression estimates, storage categories, drill-down, recommendations.
// ---------------------------------------------------------------------------

func ageHistogram(root *node) []KV {
	buckets := []struct {
		label string
		max   time.Duration
	}{
		{"< 1 day", 24 * time.Hour},
		{"1-7 days", 7 * 24 * time.Hour},
		{"1-4 weeks", 30 * 24 * time.Hour},
		{"1-6 months", 182 * 24 * time.Hour},
		{"6-12 months", 365 * 24 * time.Hour},
		{"1-2 years", 2 * 365 * 24 * time.Hour},
		{"> 2 years", 1 << 62},
	}
	counts := make([]int64, len(buckets))
	bytesB := make([]int64, len(buckets))
	for _, f := range flatten(root, false, true) {
		age := time.Since(f.modTime)
		for i, b := range buckets {
			if age < b.max {
				counts[i]++
				bytesB[i] += f.size
				break
			}
		}
	}
	var maxC int64 = 1
	for _, c := range counts {
		if c > maxC {
			maxC = c
		}
	}
	var out []KV
	for i, b := range buckets {
		out = append(out, KV{b.label, fmt.Sprintf("%6s files %-10s %s", commaInt(counts[i]), humanBytes(bytesB[i]), asciiBar(float64(counts[i])/float64(maxC), 18))})
	}
	return out
}

// ---------------------------------------------------------------------------
// Permission + ownership summary
// ---------------------------------------------------------------------------

type permSummary struct {
	worldWritable int64
	setuid        int64
	setgid        int64
	executable    int64
	symlinks      int64
}

func permissionSummary(root *node) permSummary {
	var p permSummary
	for _, n := range flatten(root, false, false) {
		m := n.mode
		if m&0002 != 0 {
			p.worldWritable++
		}
		if m&os.ModeSetuid != 0 {
			p.setuid++
		}
		if m&os.ModeSetgid != 0 {
			p.setgid++
		}
		if !n.isDir && m&0111 != 0 {
			p.executable++
		}
		if m&os.ModeSymlink != 0 {
			p.symlinks++
		}
	}
	return p
}

func ownerSummary(root *node) ([]KV, bool) {
	uidCount := map[uint32]int64{}
	uidBytes := map[uint32]int64{}
	ok := false
	for _, n := range flatten(root, false, true) {
		fi, err := os.Lstat(n.path)
		if err != nil {
			continue
		}
		st, good := fi.Sys().(*syscall.Stat_t)
		if !good {
			continue
		}
		ok = true
		uidCount[st.Uid]++
		uidBytes[st.Uid] += n.size
	}
	if !ok {
		return nil, false
	}
	type ub struct {
		uid   uint32
		count int64
		bytes int64
	}
	var list []ub
	for u, c := range uidCount {
		list = append(list, ub{u, c, uidBytes[u]})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].bytes > list[j].bytes })
	var out []KV
	for i, x := range list {
		if i >= 10 {
			break
		}
		out = append(out, KV{"uid " + strconv.FormatUint(uint64(x.uid), 10), fmt.Sprintf("%s files, %s", commaInt(x.count), humanBytes(x.bytes))})
	}
	return out, true
}

// ---------------------------------------------------------------------------
// Hot directories (by immediate file count) + empty dirs
// ---------------------------------------------------------------------------

func hotDirectories(root *node, n int) []*node {
	dirs := flatten(root, true, false)
	sort.Slice(dirs, func(i, j int) bool {
		return directFileCount(dirs[i]) > directFileCount(dirs[j])
	})
	if len(dirs) > n {
		dirs = dirs[:n]
	}
	return dirs
}

func directFileCount(n *node) int {
	c := 0
	for _, ch := range n.children {
		if !ch.isDir {
			c++
		}
	}
	return c
}

func emptyDirectories(root *node) []string {
	var out []string
	for _, d := range flatten(root, true, false) {
		if len(d.children) == 0 {
			out = append(out, d.path)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Compression potential estimate (heuristic by extension)
// ---------------------------------------------------------------------------

type compHint struct {
	ext   string
	ratio float64 // estimated compressed/original
	note  string
}

var compressTable = []compHint{
	{".log", 0.12, "text logs compress ~8x"},
	{".txt", 0.30, "plain text"},
	{".csv", 0.20, "tabular text compresses well"},
	{".json", 0.15, "structured text compresses well"},
	{".xml", 0.15, "verbose markup compresses well"},
	{".sql", 0.18, "dumps compress well"},
	{".html", 0.22, "markup"},
	{".bmp", 0.25, "uncompressed raster"},
	{".wav", 0.60, "PCM audio -> FLAC"},
	{".tar", 0.45, "uncompressed archive"},
	{".jpg", 0.98, "already compressed"},
	{".png", 0.95, "already compressed"},
	{".mp4", 0.99, "already compressed"},
	{".zip", 1.00, "already compressed"},
	{".gz", 1.00, "already compressed"},
}

func compRatio(ext string) (float64, string, bool) {
	ext = strings.ToLower(ext)
	for _, c := range compressTable {
		if c.ext == ext {
			return c.ratio, c.note, true
		}
	}
	return 0, "", false
}

func compressionEstimate(root *node) (int64, int64) {
	var original, estimated int64
	for _, f := range flatten(root, false, true) {
		r, _, ok := compRatio(filepath.Ext(f.name))
		if !ok {
			r = 0.7 // generic unknown
		}
		original += f.size
		estimated += int64(float64(f.size) * r)
	}
	return original, estimated
}

// ---------------------------------------------------------------------------
// Storage category classification
// ---------------------------------------------------------------------------

var storageCategories = map[string]string{
	".mp4": "media", ".mov": "media", ".mkv": "media", ".avi": "media", ".mp3": "media", ".flac": "media", ".wav": "media",
	".jpg": "images", ".jpeg": "images", ".png": "images", ".gif": "images", ".heic": "images", ".raw": "images", ".webp": "images",
	".pdf": "documents", ".docx": "documents", ".xlsx": "documents", ".pptx": "documents", ".txt": "documents", ".md": "documents",
	".zip": "archives", ".tar": "archives", ".gz": "archives", ".7z": "archives", ".rar": "archives", ".iso": "archives",
	".go": "code", ".py": "code", ".js": "code", ".ts": "code", ".c": "code", ".cpp": "code", ".java": "code", ".rs": "code",
	".log": "logs", ".out": "logs", ".err": "logs",
	".db": "data", ".sqlite": "data", ".sql": "data", ".csv": "data", ".json": "data", ".parquet": "data",
}

func categorize(root *node) []KV {
	agg := map[string]int64{}
	for _, f := range flatten(root, false, true) {
		cat := storageCategories[strings.ToLower(filepath.Ext(f.name))]
		if cat == "" {
			cat = "other"
		}
		agg[cat] += f.size
	}
	type cw struct {
		c string
		v int64
	}
	var list []cw
	for c, v := range agg {
		list = append(list, cw{c, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	var out []KV
	for _, x := range list {
		frac := 0.0
		if root.size > 0 {
			frac = float64(x.v) / float64(root.size)
		}
		out = append(out, KV{x.c, fmt.Sprintf("%-10s %s", humanBytes(x.v), asciiBar(frac, 16))})
	}
	return out
}

// ---------------------------------------------------------------------------
// Recommendations
// ---------------------------------------------------------------------------

func recommendations(root *node, cfg duConfig) []string {
	var recs []string
	ps := pruneSuggestions(root, maxI64(root.size/100, 1024*1024))
	if len(ps) > 0 {
		var t int64
		for _, p := range ps {
			t += p.size
		}
		recs = append(recs, fmt.Sprintf("Prune %d cache/build/old directories to reclaim up to %s.", len(ps), humanBytes(t)))
	}
	orig, est := compressionEstimate(root)
	if orig > 0 && est < orig*8/10 {
		recs = append(recs, fmt.Sprintf("Compressing text-like files could save ~%s (est %s -> %s).", humanBytes(orig-est), humanBytes(orig), humanBytes(est)))
	}
	smallN, _ := smallFileCount(root, 4096)
	if smallN > 5000 {
		recs = append(recs, fmt.Sprintf("Archive the %s tiny files into a tarball to cut inode pressure and speed backups.", commaInt(smallN)))
	}
	p := permissionSummary(root)
	if p.worldWritable > 0 {
		recs = append(recs, fmt.Sprintf("Review %d world-writable items for tampering risk.", p.worldWritable))
	}
	if len(recs) == 0 {
		recs = append(recs, "Storage looks healthy — no major reclaim opportunities detected.")
	}
	return recs
}

// ---------------------------------------------------------------------------
// Interactive drill-down navigation
// ---------------------------------------------------------------------------

func tuiDrill() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	cur := lastRoot
	for {
		clear()
		banner()
		fmt.Println("  " + col("Drill-down: ", R+B) + col(cur.path, W))
		info(fmt.Sprintf("size %s  files %s  dirs %s", humanBytes(cur.size), commaInt(cur.count), commaInt(cur.dirs)))
		fmt.Println()
		var subdirs []*node
		for _, c := range cur.children {
			if c.isDir {
				subdirs = append(subdirs, c)
			}
		}
		if len(subdirs) > 20 {
			subdirs = subdirs[:20]
		}
		rows := [][]string{}
		for i, d := range subdirs {
			rows = append(rows, []string{strconv.Itoa(i + 1), humanBytes(d.size), truncStr(d.name, 40)})
		}
		if len(rows) > 0 {
			table([]string{"#", "SIZE", "SUBDIR"}, rows)
		} else {
			info("(no subdirectories)")
		}
		fmt.Println()
		sel := prompt("number to enter, 'u' up, 'q' quit")
		if sel == "q" {
			return
		}
		if sel == "u" {
			parent := findParent(lastRoot, cur)
			if parent != nil {
				cur = parent
			}
			continue
		}
		if n, err := strconv.Atoi(sel); err == nil && n >= 1 && n <= len(subdirs) {
			cur = subdirs[n-1]
		}
	}
}

func findParent(root, target *node) *node {
	for _, c := range root.children {
		if c == target {
			return root
		}
		if c.isDir {
			if p := findParent(c, target); p != nil {
				return p
			}
		}
	}
	return nil
}

func tuiAge() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	kvTable(ageHistogram(lastRoot))
	pause()
}

func tuiPerms() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	p := permissionSummary(lastRoot)
	kvTable([]KV{
		{"world_writable", commaInt(p.worldWritable)},
		{"setuid", commaInt(p.setuid)},
		{"setgid", commaInt(p.setgid)},
		{"executable_files", commaInt(p.executable)},
		{"symlinks", commaInt(p.symlinks)},
	})
	if ow, ok := ownerSummary(lastRoot); ok {
		fmt.Println()
		fmt.Println("  " + col("top owners", R+B))
		kvTable(ow)
	}
	pause()
}

func tuiCategories() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	kvTable(categorize(lastRoot))
	fmt.Println()
	orig, est := compressionEstimate(lastRoot)
	info(fmt.Sprintf("compression estimate: %s -> %s (save %s)", humanBytes(orig), humanBytes(est), humanBytes(orig-est)))
	pause()
}

func tuiHot() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	rows := [][]string{}
	for _, d := range hotDirectories(lastRoot, 20) {
		rows = append(rows, []string{strconv.Itoa(directFileCount(d)), truncStr(d.path, 50)})
	}
	table([]string{"FILES", "DIRECTORY"}, rows)
	fmt.Println()
	ed := emptyDirectories(lastRoot)
	info(fmt.Sprintf("empty directories: %d", len(ed)))
	pause()
}

func tuiRecommend() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	for _, r := range recommendations(lastRoot, lastCfg) {
		info(r)
	}
	pause()
}

// ---------------------------------------------------------------------------
// Part 6 — size percentiles, same-name detection, best-practice reference.
// ---------------------------------------------------------------------------

func sizePercentiles(root *node) []KV {
	files := flatten(root, false, true)
	if len(files) == 0 {
		return nil
	}
	sizes := make([]int64, len(files))
	for i, f := range files {
		sizes[i] = f.size
	}
	sort.Slice(sizes, func(i, j int) bool { return sizes[i] < sizes[j] })
	pct := func(p float64) int64 {
		idx := int(p / 100 * float64(len(sizes)-1))
		return sizes[idx]
	}
	var total int64
	for _, s := range sizes {
		total += s
	}
	mean := total / int64(len(sizes))
	return []KV{
		{"count", commaInt(int64(len(sizes)))},
		{"min", humanBytes(sizes[0])},
		{"p25", humanBytes(pct(25))},
		{"median", humanBytes(pct(50))},
		{"p75", humanBytes(pct(75))},
		{"p90", humanBytes(pct(90))},
		{"p99", humanBytes(pct(99))},
		{"max", humanBytes(sizes[len(sizes)-1])},
		{"mean", humanBytes(mean)},
	}
}

// sameNameGroups finds identically-named files scattered across directories
// (distinct from content de-duplication; this is a naming/organisation view).
func sameNameGroups(root *node) map[string][]string {
	byName := map[string][]string{}
	for _, f := range flatten(root, false, true) {
		byName[f.name] = append(byName[f.name], f.path)
	}
	out := map[string][]string{}
	for n, paths := range byName {
		if len(paths) > 1 {
			out[n] = paths
		}
	}
	return out
}

func topExtensionsByCount(root *node, n int) []extAgg {
	es := extensionStats(root)
	sort.Slice(es, func(i, j int) bool { return es[i].count > es[j].count })
	if len(es) > n {
		es = es[:n]
	}
	return es
}

type bestPractice struct {
	topic string
	note  string
}

var bestPractices = []bestPractice{
	{"caches", "node_modules, __pycache__, target, build and .cache are regenerable — safe to delete."},
	{"logs", "Cap and rotate logs with logrotate; unrotated logs grow unbounded."},
	{"media", "Media (video/photos) usually dominates usage; move cold media to archive storage."},
	{"tiny files", "Thousands of <4K files waste inodes and slow backups; archive them into tarballs."},
	{"old data", "Files untouched for >1 year are archive candidates; snapshot before deleting."},
	{"permissions", "World-writable large directories are tampering risks; chmod o-w."},
	{"compression", "Text/log/CSV/JSON compress 5-8x; compress cold text data."},
	{"snapshots", "Take periodic snapshots (--snapshot) to track growth and spot runaway dirs."},
	{"VM/disk images", "iso/vmdk/img files are huge; consider thin provisioning or external storage."},
	{"duplicates", "Pair OTreeMap with ODedupe to reclaim byte-identical copies."},
}

func printBestPractices() {
	fmt.Println("  " + col("Disk-usage best practices", R+B))
	rows := [][]string{}
	for _, b := range bestPractices {
		rows = append(rows, []string{b.topic, truncStr(b.note, 60)})
	}
	table([]string{"TOPIC", "GUIDANCE"}, rows)
}

func tuiPercentiles() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	kv := sizePercentiles(lastRoot)
	if kv == nil {
		okMsg("no files")
	} else {
		kvTable(kv)
	}
	pause()
}

func tuiSameName() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	g := sameNameGroups(lastRoot)
	if len(g) == 0 {
		okMsg("no repeated file names")
		pause()
		return
	}
	// show the ones with most copies
	type nc struct {
		name  string
		count int
	}
	var list []nc
	for n, p := range g {
		list = append(list, nc{n, len(p)})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].count > list[j].count })
	rows := [][]string{}
	for i, x := range list {
		if i >= 20 {
			break
		}
		rows = append(rows, []string{strconv.Itoa(x.count), truncStr(x.name, 40)})
	}
	table([]string{"COPIES", "FILENAME"}, rows)
	pause()
}

func tuiBestPractices() {
	clear()
	banner()
	printBestPractices()
	pause()
}

// ---------------------------------------------------------------------------
// Part 7 — directory depth stats, same-name reporting helper, legend.
// ---------------------------------------------------------------------------

func dirDepthStats(root *node) (avg float64, max int, deepest string) {
	dirs := flatten(root, true, false)
	if len(dirs) == 0 {
		return 0, 0, ""
	}
	var sum int
	for _, d := range dirs {
		sum += d.depth
		if d.depth > max {
			max = d.depth
			deepest = d.path
		}
	}
	avg = float64(sum) / float64(len(dirs))
	return
}

func sameNameReport(root *node) []KV {
	g := sameNameGroups(root)
	type nc struct {
		name  string
		count int
	}
	var list []nc
	for n, p := range g {
		list = append(list, nc{n, len(p)})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].count > list[j].count })
	var out []KV
	for i, x := range list {
		if i >= 10 {
			break
		}
		out = append(out, KV{x.name, strconv.Itoa(x.count) + " copies"})
	}
	return out
}

func treemapLegend() string {
	return "  legend: \u2591 \u2592 \u2593 \u2588  (lighter → smaller share; labels name the largest children)"
}

// densityScore rates how "cluttered" a tree is (files per directory).
func densityScore(root *node) float64 {
	if root.dirs == 0 {
		return float64(root.count)
	}
	return float64(root.count) / float64(root.dirs)
}

func tuiDepthStats() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	avg, max, deepest := dirDepthStats(lastRoot)
	kvTable([]KV{
		{"avg_dir_depth", fmt.Sprintf("%.1f", avg)},
		{"max_dir_depth", strconv.Itoa(max)},
		{"deepest_dir", truncStr(deepest, 50)},
		{"files_per_dir", fmt.Sprintf("%.1f", densityScore(lastRoot))},
	})
	pause()
}

// ---------------------------------------------------------------------------
// Part 8 — indented outline view and two-directory comparison.
// ---------------------------------------------------------------------------

func outlineView(n *node, maxDepth int, maxChildren int) string {
	var b strings.Builder
	var rec func(x *node, depth int)
	rec = func(x *node, depth int) {
		if depth > maxDepth {
			return
		}
		indent := strings.Repeat("  ", depth)
		marker := "\u2500"
		if x.isDir {
			marker = "\u25b8"
		}
		b.WriteString(fmt.Sprintf("%s%s %-30s %10s\n", indent, marker, truncStr(x.name, 30), humanBytes(x.size)))
		if !x.isDir {
			return
		}
		shown := 0
		for _, c := range x.children {
			if shown >= maxChildren {
				b.WriteString(indent + "  \u2026 (more)\n")
				break
			}
			rec(c, depth+1)
			shown++
		}
	}
	rec(n, 0)
	return b.String()
}

func tuiOutline() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	fmt.Print(treemapLegend())
	fmt.Println()
	fmt.Print(outlineView(lastRoot, 3, 8))
	pause()
}

type dirCompare struct {
	path  string
	aSize int64
	bSize int64
}

func compareTrees(a, b *node) []dirCompare {
	aMap := map[string]int64{}
	for _, d := range flatten(a, true, false) {
		rel, _ := filepath.Rel(a.path, d.path)
		aMap[rel] = d.size
	}
	var out []dirCompare
	for _, d := range flatten(b, true, false) {
		rel, _ := filepath.Rel(b.path, d.path)
		if as, ok := aMap[rel]; ok && as != d.size {
			out = append(out, dirCompare{rel, as, d.size})
		}
	}
	sort.Slice(out, func(i, j int) bool { return absI64(out[i].bSize-out[i].aSize) > absI64(out[j].bSize-out[j].aSize) })
	return out
}

func tuiCompareTrees() {
	clear()
	banner()
	a := prompt("first directory")
	bp := prompt("second directory")
	ra, _, _ := buildTree(defaultDU(a))
	rb, _, _ := buildTree(defaultDU(bp))
	cmp := compareTrees(ra, rb)
	if len(cmp) == 0 {
		okMsg("directories have identical structure sizes")
		pause()
		return
	}
	rows := [][]string{}
	for i, c := range cmp {
		if i >= 20 {
			break
		}
		rows = append(rows, []string{humanBytes(c.aSize), humanBytes(c.bSize), truncStr(c.path, 40)})
	}
	table([]string{"A", "B", "SUBDIR"}, rows)
	pause()
}

// freeSpaceContext reports the share of the scan relative to common thresholds.
func freeSpaceContext(root *node) []KV {
	gb := func(n int64) float64 { return float64(n) / (1 << 30) }
	total := gb(root.size)
	return []KV{
		{"total_gb", fmt.Sprintf("%.2f", total)},
		{"fills_1gb_quota", fmt.Sprintf("%.0f%%", clampF(total/1.0*100, 0, 999))},
		{"fills_10gb_quota", fmt.Sprintf("%.0f%%", clampF(total/10.0*100, 0, 999))},
		{"fills_100gb_quota", fmt.Sprintf("%.1f%%", clampF(total/100.0*100, 0, 999))},
	}
}

func tuiQuota() {
	clear()
	banner()
	if !requireRoot() {
		return
	}
	kvTable(freeSpaceContext(lastRoot))
	pause()
}

// biggestExtensionSummary returns a one-line headline of the dominant file type.
func biggestExtensionSummary(root *node) string {
	es := extensionStats(root)
	if len(es) == 0 {
		return "no files"
	}
	top := es[0]
	share := 0.0
	if root.size > 0 {
		share = float64(top.bytes) / float64(root.size)
	}
	return fmt.Sprintf("%s dominates with %s across %s files (%.0f%% of bytes)",
		top.ext, humanBytes(top.bytes), commaInt(top.count), share*100)
}

// headline prints the dominant file-type summary for the last scan.
func headline(root *node) string {
	return "Summary: " + biggestExtensionSummary(root)
}

func ageSpreadLabel(root *node) string {
	files := flatten(root, false, true)
	if len(files) == 0 {
		return "n/a"
	}
	oldest := files[0].modTime
	newest := files[0].modTime
	for _, f := range files {
		if f.modTime.Before(oldest) {
			oldest = f.modTime
		}
		if f.modTime.After(newest) {
			newest = f.modTime
		}
	}
	return fmt.Sprintf("%s .. %s", oldest.Format("2006-01-02"), newest.Format("2006-01-02"))
}

// ---- OWL house help content ----
var owlHelpAbout = []string{
	"OTreeMap analyses disk usage under a directory and renders it as an ASCII treemap. It walks the tree, aggregates sizes, and surfaces the largest directories and files, extension and age breakdowns, permission/owner summaries, storage categories and prune suggestions.",
	"It can snapshot usage to JSON and later show growth versus that snapshot, and export any report as txt / md / json / csv / sarif. Everything is read-only; it never deletes or modifies files.",
}
var owlHelpFlow = []string{
	"Type the number of an option and press Enter. Most options ask for a path (default: current directory) and a count. Start with [1] Analyze to build the tree, then explore with the treemap, largest-dirs/files and the drill-down navigator. [H] opens this help, [0] or q quits.",
	"Everything is also available from the command line (see page 2) for scripting and scheduled snapshots.",
}
var owlHelpMenu = []owlHelpItem{
	{"1", "Analyze a directory: walk a path and show totals, file/dir counts and depth."},
	{"2", "ASCII treemap: proportional box view of where the space goes."},
	{"3/4", "Largest directories / files: the top space consumers, ranked."},
	{"5", "Extension statistics: bytes and counts grouped by file extension."},
	{"6", "Depth profile: how size is distributed across directory depth."},
	{"7", "Prune suggestions: caches, build dirs and large stale files worth clearing."},
	{"8/9", "Save snapshot / Growth vs snapshot: record usage to JSON, then diff later to see what grew."},
	{"10", "Export last report: write the latest result as txt/md/json/csv/sarif."},
	{"11", "Drill-down navigator: walk into subdirectories interactively."},
	{"12", "Age histogram: file counts/size by last-modified age."},
	{"13", "Permissions & owners: summarise modes and owners under the tree."},
	{"14", "Storage categories: group by kind (media, code, archives, …)."},
	{"15", "Hot directories: the directories changed most recently."},
	{"16", "Recommendations: graded findings summarising cleanup opportunities."},
	{"17", "Self-test: build a temp tree and verify the aggregation engine."},
}
var owlHelpTips = []owlHelpItem{
	{"*", "All analysis is read-only. Prune suggestions only list candidates — OTreeMap never deletes anything."},
	{"*", "Use [8] to snapshot a path, then [9] weeks later to see exactly which directories grew."},
	{"*", "Symlinks are not followed, so the totals match real on-disk usage without double-counting."},
	{"*", "Run --selftest (or option [17]) to confirm the tree-aggregation engine on a known layout."},
}
