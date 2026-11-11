package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Report struct {
	Tool       string         `json:"tool"`
	Version    string         `json:"version"`
	Files      int            `json:"files"`
	Rules      []Rule         `json:"rules"`
	Counts     map[string]int `json:"counts"`
	Suppressed map[string]int `json:"suppressed"`
	Exceptions []Exception    `json:"exceptions"`
	Hash       string         `json:"hash"`
	Findings   []Finding      `json:"findings"`
}

func scan(root string, cfg Config) (*Report, error) {
	rep := &Report{Tool: "limator", Version: version, Findings: []Finding{}, Exceptions: []Exception{}}
	rep.Counts, rep.Suppressed = map[string]int{}, map[string]int{}
	rep.Rules = append(rep.Rules, rules...)
	for _, r := range cfg.Rules {
		rep.Rules = append(rep.Rules, Rule{r.ID, r.Name, r.Msg})
	}
	for _, im := range cfg.Imports {
		rep.Rules = append(rep.Rules, Rule{im.ID, im.Name, "imported from " + im.File})
	}
	var all []Finding
	err := walkFiles(root, cfg, func(rel, abs string, src []byte) error {
		rep.Files++
		all = append(all, checkText(rel, src, cfg)...)
		all = append(all, checkSecrets(rel, src)...)
		if filepath.Ext(abs) == ".go" {
			all = append(all, checkGo(rel, src, cfg.comments)...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, im := range cfg.Imports {
		all = append(all, importTool(cfg.dir, im)...)
	}
	err = walkTree(root, cfg, func(name string) bool { return secretFile(name, cfg) }, func(rel, abs string, src []byte) error {
		all = append(all, checkSecrets(rel, src)...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if cfg.VulnDB != "" {
		all = append(all, checkVulns(root, cfg)...)
	}
	for _, e := range cfg.Exceptions {
		e.Used = 0
		rep.Exceptions = append(rep.Exceptions, e)
	}
	for _, f := range all {
		hit := false
		for i := range rep.Exceptions {
			if rep.Exceptions[i].matches(f) {
				rep.Exceptions[i].Used++
				hit = true
				break
			}
		}
		if hit {
			rep.Suppressed[f.Rule]++
		} else {
			rep.Findings = append(rep.Findings, f)
		}
	}
	for _, e := range rep.Exceptions {
		if e.Used == 0 {
			rep.Findings = append(rep.Findings, Finding{"H002", "limator.json", 1, "exception matches nothing: " + e.Rule + " " + e.Path})
		}
	}
	sort.Slice(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Msg < b.Msg
	})
	for _, r := range rep.Rules {
		rep.Counts[r.ID] = 0
	}
	h := sha256.New()
	fmt.Fprintln(h, version)
	for _, f := range rep.Findings {
		rep.Counts[f.Rule]++
		fmt.Fprintf(h, "%s|%s|%d|%s\n", f.Rule, f.File, f.Line, f.Msg)
	}
	for _, e := range rep.Exceptions {
		fmt.Fprintf(h, "x|%s|%s|%s|%d\n", e.Rule, e.Path, e.Reason, e.Used)
	}
	rep.Hash = hex.EncodeToString(h.Sum(nil))
	return rep, nil
}

var toolLine = regexp.MustCompile(`^((?:[A-Za-z]:)?[^:]+):(\d+)(?::\d+)?:\s*(.*)$`)

func importTool(dir string, im Import) []Finding {
	p := im.File
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, p)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return []Finding{{"H001", im.File, 1, im.Name + ": output file missing"}}
	}
	var out []Finding
	bad := ""
	for _, l := range strings.Split(strings.TrimPrefix(string(raw), string(rune(0xFEFF))), "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" {
			continue
		}
		m := toolLine.FindStringSubmatch(l)
		n := 0
		if m != nil && !strings.Contains(l, "panic:") {
			n, err = strconv.Atoi(m[2])
		}
		if m == nil || err != nil || n == 0 {
			if bad == "" {
				bad = l
			}
			err = nil
			continue
		}
		out = append(out, Finding{im.ID, strings.ReplaceAll(m[1], "\\", "/"), n, strings.TrimSpace(m[3])})
	}
	if bad != "" {
		if len(bad) > 120 {
			bad = bad[:120]
		}
		out = append(out, Finding{"H001", im.File, 1, im.Name + ": unreadable output: " + bad})
	}
	return out
}

func sarif(rep *Report) ([]byte, error) {
	rs := []map[string]any{}
	for _, r := range rep.Rules {
		rs = append(rs, map[string]any{"id": r.ID, "name": r.Name, "shortDescription": map[string]any{"text": r.Doc}})
	}
	results := []map[string]any{}
	for _, f := range rep.Findings {
		results = append(results, map[string]any{
			"ruleId":  f.Rule,
			"message": map[string]any{"text": f.Msg},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": f.File},
				"region":           map[string]any{"startLine": f.Line},
			}}},
		})
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": "limator", "version": rep.Version, "rules": rs}},
			"results": results,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}
