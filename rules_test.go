package main

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const dirty = `package demo

import "database/sql"

// TICKET-17 moved this
func load(db *sql.DB) []string {
	var out []string
	rows, _ := db.Query("SELECT a")
	defer rows.Close()
	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil {
			out = append(out, s)
		}
	}
	_ = db.Ping()
	return out
}
`

const clean = `// Package demo loads names.
package demo

import "database/sql"

func load(db *sql.DB) ([]string, error) {
	var out []string
	rows, err := db.Query("SELECT a")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
`

func count(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.Rule]++
	}
	return m
}

func TestDirtyGo(t *testing.T) {
	pats := []*regexp.Regexp{regexp.MustCompile(`TICKET-\d+`)}
	got := count(checkGo("a.go", []byte(dirty), pats))
	for _, id := range []string{"L001", "L002", "L003", "L004", "L006"} {
		if got[id] != 1 {
			t.Errorf("%s: got %d, want 1", id, got[id])
		}
	}
}

func TestCleanGo(t *testing.T) {
	pats := []*regexp.Regexp{regexp.MustCompile(`TICKET-\d+`)}
	if got := checkGo("a.go", []byte(clean), pats); len(got) != 0 {
		t.Errorf("clean file has findings: %v", got)
	}
}

func TestParseError(t *testing.T) {
	if got := count(checkGo("a.go", []byte("package"), nil)); got["L000"] != 1 {
		t.Errorf("L000: got %d, want 1", got["L000"])
	}
}

func TestText(t *testing.T) {
	cfg := Config{MaxFileLines: 3, MaxLineLength: 10}
	src := "ok\nzero" + string(rune(0x200B)) + "width\n" + strings.Repeat("x", 11) + "\nlast\n"
	got := count(checkText("a.ts", []byte(src), cfg))
	for _, id := range []string{"L005", "L007", "L008"} {
		if got[id] != 1 {
			t.Errorf("%s: got %d, want 1", id, got[id])
		}
	}
}

func TestScanIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(dirty), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vendor", "b.go"), []byte(dirty), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(filepath.Join(dir, "limator.json"), false)
	if err != nil {
		t.Fatal(err)
	}
	a, err := scan(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := scan(dir, cfg)
	if a.Files != 1 {
		t.Errorf("files: got %d, want 1 (vendor must be skipped)", a.Files)
	}
	if a.Hash != b.Hash || a.Hash == "" {
		t.Errorf("hash not stable: %q vs %q", a.Hash, b.Hash)
	}
}

func TestGateRatchet(t *testing.T) {
	base := filepath.Join(t.TempDir(), "base.json")
	rep := &Report{Rules: rules, Counts: map[string]int{"L004": 5}}
	if code, err := gate(rep, base); code != 0 || err != nil {
		t.Fatalf("first run: %d %v", code, err)
	}
	rep.Counts["L004"] = 6
	if code, _ := gate(rep, base); code != 1 {
		t.Errorf("worse: got %d, want 1", code)
	}
	rep.Counts["L004"] = 3
	if code, _ := gate(rep, base); code != 0 {
		t.Errorf("better: got %d, want 0", code)
	}
	rep.Counts["L004"] = 4
	if code, _ := gate(rep, base); code != 1 {
		t.Errorf("ratchet did not tighten: got %d, want 1", code)
	}
}

func TestNoNetworkImports(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == "net" || strings.HasPrefix(p, "net/") || p == "os/exec" || p == "syscall" {
				t.Errorf("%s imports %s", name, p)
			}
		}
	}
}

func TestSkipGlob(t *testing.T) {
	if !matchAny([]string{"wt-*"}, "wt-k9") || matchAny([]string{"wt-*"}, "gateway") {
		t.Error("glob skip is wrong")
	}
	if checkSkip([]string{"[bad"}) == nil {
		t.Error("bad pattern accepted")
	}
}

func writeCfg(t *testing.T, dir, body string) (Config, error) {
	t.Helper()
	p := filepath.Join(dir, "limator.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return loadConfig(p, true)
}

func TestDataRuleAndException(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"a.tsx": "<div style={{color: 1}} />\n<p>ok</p>\n", "b.tsx": "<div style={{color: 2}} />\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := writeCfg(t, dir, `{"rules":[{"id":"X001","name":"inline-style","pattern":"style=\\{\\{","files":"*.tsx"}],
		"exceptions":[{"rule":"X001","path":"b.tsx","reason":"legacy screen"},{"rule":"L004","path":"nothing/","reason":"stale"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := scan(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts["X001"] != 1 || rep.Suppressed["X001"] != 1 || rep.Counts["H002"] != 1 {
		t.Errorf("counts %v suppressed %v", rep.Counts, rep.Suppressed)
	}
}

func TestConfigRejectsBadInput(t *testing.T) {
	for _, body := range []string{
		`{"exceptions":[{"rule":"L004","path":"a.go","reason":" "}]}`,
		`{"rules":[{"id":"L001","pattern":"x"}]}`,
		`{"rules":[{"id":"X1","pattern":"("}]}`,
		`{"imports":[{"id":"E1"}]}`,
		`{"skip_dirs":["[bad"]}`,
	} {
		if _, err := writeCfg(t, t.TempDir(), body); err == nil {
			t.Errorf("accepted: %s", body)
		}
	}
}

func TestImportTool(t *testing.T) {
	dir := t.TempDir()
	im := Import{ID: "E001", Name: "errcheck", File: "tool.txt"}
	if got := count(importTool(dir, im)); got["H001"] != 1 {
		t.Errorf("missing file: %v", got)
	}
	file := filepath.Join(dir, "tool.txt")
	if err := os.WriteFile(file, []byte("a.go:3:5:\tdefer rows.Close()\nsub\\b.go:10: something\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := importTool(dir, im)
	if got := count(fs); got["E001"] != 2 || got["H001"] != 0 {
		t.Errorf("healthy output: %v", got)
	}
	if fs[1].File != "sub/b.go" || fs[1].Line != 10 {
		t.Errorf("second finding: %+v", fs[1])
	}
	if err := os.WriteFile(file, []byte("panic: cannot decode\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := count(importTool(dir, im)); got["H001"] != 1 || got["E001"] != 0 {
		t.Errorf("crashed tool: %v", got)
	}
}

func TestSarif(t *testing.T) {
	rep := &Report{Version: version, Rules: rules, Findings: []Finding{{"L004", "a.go", 3, "call result discarded"}}}
	raw, err := sarif(rep)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			}
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 || doc.Runs[0].Results[0].RuleID != "L004" {
		t.Errorf("unexpected sarif: %s", raw)
	}
}

func fixCfg(scope string) Config {
	return Config{FixScope: scope, comments: []*regexp.Regexp{regexp.MustCompile(`TICKET-\d+`)}}
}

func TestFixRemovesMatchingComments(t *testing.T) {
	src := "package demo\n\n//go:generate echo TICKET-1\n\n// keeps this line\n// TICKET-17 moved this\n" +
		"func a() int {\n\tx := 1 // TICKET-18 temp\n\treturn x\n}\n"
	out, removed, _, err := fixGo([]byte(src), fixCfg("line"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if removed != 2 || strings.Contains(got, "TICKET-17") || strings.Contains(got, "TICKET-18") {
		t.Errorf("removed %d:\n%s", removed, got)
	}
	if !strings.Contains(got, "keeps this line") || !strings.Contains(got, "//go:generate echo TICKET-1") || !strings.Contains(got, "x := 1\n") {
		t.Errorf("lost something:\n%s", got)
	}
	out, _, _, err = fixGo([]byte(src), fixCfg("group"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "keeps this line") {
		t.Errorf("group scope kept the group:\n%s", out)
	}
}

func TestFixCleansInvisibleOnlyInComments(t *testing.T) {
	zw := string(rune(0x200B))
	src := "package demo\n\n// hid" + zw + "den\nvar s = \"a" + zw + "b\"\n"
	out, _, cleaned, err := fixGo([]byte(src), fixCfg("line"))
	if err != nil {
		t.Fatal(err)
	}
	if cleaned != 1 || !strings.Contains(string(out), "// hidden") || !strings.Contains(string(out), "a"+zw+"b") {
		t.Errorf("cleaned %d: %q", cleaned, out)
	}
}

func TestSameCode(t *testing.T) {
	if !sameCode([]byte("package a\n// c\nvar x = 1\n"), []byte("package a\nvar x = 1\n")) {
		t.Error("comment-only change rejected")
	}
	if sameCode([]byte("package a\nvar x = 1\n"), []byte("package a\nvar x = 2\n")) {
		t.Error("code change accepted")
	}
}

func TestHTMLReportIsSelfContained(t *testing.T) {
	rep := &Report{Version: version, Hash: "abc", Rules: rules, Counts: map[string]int{"L004": 1}}
	rep.Findings = []Finding{{"L004", "a.go", 3, "</script><b>x"}}
	raw, err := htmlReport(rep)
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	if strings.Contains(page, "http://") || strings.Contains(page, "https://") || strings.Contains(page, " src=") {
		t.Error("report loads something from outside the file")
	}
	if strings.Count(page, "</script>") != 2 {
		t.Error("finding text can break out of the data block")
	}
	if !strings.Contains(page, `"a.go"`) {
		t.Error("findings are missing from the page")
	}
}

func TestParseGoMod(t *testing.T) {
	src := "module demo\n\ngo 1.22\n\nrequire example.com/one v1.0.0\n\nrequire (\n\texample.com/two v2.1.0\n" +
		"\texample.com/three v0.3.0 // indirect\n)\n\nreplace (\n\texample.com/two => ../two\n)\n"
	got := parseGoMod([]byte(src))
	if len(got) != 3 || got[0].Name != "example.com/one" || got[1].Version != "v2.1.0" || !got[2].Indirect || got[1].Indirect {
		t.Errorf("unexpected: %+v", got)
	}
}

func TestClassify(t *testing.T) {
	for text, want := range map[string]string{
		"Permission is hereby granted, free of charge, to any person":            "MIT",
		"Apache License\nVersion 2.0, January 2004":                              "Apache-2.0",
		"Redistribution and use in source and binary forms. Neither the name of": "BSD-3-Clause",
		"GNU GENERAL PUBLIC LICENSE Version 3":                                   "GPL-3.0",
		"all rights reserved":                                                    "unknown",
	} {
		if got := classify(text); got != want {
			t.Errorf("%q: got %s, want %s", text, got, want)
		}
	}
}

func write(t *testing.T, file, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInventoryAndAudit(t *testing.T) {
	dir, cache := t.TempDir(), t.TempDir()
	write(t, filepath.Join(dir, "a.go"), clean)
	write(t, filepath.Join(dir, "b.go"), dirty)
	write(t, filepath.Join(dir, "go.mod"), "module demo\n\nrequire example.com/Lib v1.0.0\n")
	write(t, filepath.Join(cache, "example.com", "!lib@v1.0.0", "LICENSE"), "Permission is hereby granted, free of charge")
	write(t, filepath.Join(dir, "web", "package.json"), `{"dependencies":{"left":"^1.0.0"}}`)
	write(t, filepath.Join(dir, "web", "node_modules", "left", "package.json"), `{"version":"1.2.3","license":"ISC"}`)
	cfg, err := writeCfg(t, dir, `{"module_cache":"`+filepath.ToSlash(cache)+`"}`)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := inventory(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Files) != 2 || inv.Files[0].Doc != "Package demo loads names." || inv.Files[1].Doc != "" {
		t.Errorf("files: %+v", inv.Files)
	}
	if len(inv.Dependencies) != 2 || inv.Dependencies[0].License != "MIT" {
		t.Fatalf("dependencies: %+v", inv.Dependencies)
	}
	if d := inv.Dependencies[1]; d.Name != "left" || d.Version != "1.2.3" || d.License != "ISC" || d.Manifest != "web/package.json" {
		t.Errorf("npm dependency: %+v", d)
	}
	again, err := inventory(dir, cfg)
	if err != nil || again.Hash != inv.Hash || inv.Hash == "" {
		t.Errorf("inventory hash not stable")
	}
	bom, err := cyclonedx(inv)
	if err != nil || !strings.Contains(string(bom), `"pkg:golang/example.com/Lib@v1.0.0"`) || !strings.Contains(string(bom), `"pkg:npm/left@1.2.3"`) {
		t.Errorf("cyclonedx: %s", bom)
	}
	rep, err := scan(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	a, err := audit(rep, inv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := audit(rep, inv, cfg)
	if a.Hash == "" || a.Hash != b.Hash || a.ConfigSHA256 == "" || a.GoFilesNoDoc != 1 || a.Licenses["MIT"] != 1 || len(a.Controls) != 4 {
		t.Errorf("audit: %+v", a)
	}
}
