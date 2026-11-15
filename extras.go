// extras.go holds the commit hook, file headers, the fix for TypeScript comments, line exceptions and churn.

package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const hookMark = "# limator gate"

type Header struct {
	File       string `json:"file"`
	Suggestion string `json:"suggestion"`
}

func installHook(root, base, cfgPath string) error {
	dir := filepath.Join(root, ".git", "hooks")
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return fmt.Errorf("%s is not a git repository with a hooks folder", root)
	}
	file := filepath.Join(dir, "pre-commit")
	if old, err := os.ReadFile(file); err == nil && !strings.Contains(string(old), hookMark) {
		return fmt.Errorf("%s exists and was not written by limator; add the gate to it by hand", file)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	if base == "" {
		base = filepath.Join(abs, "limator-baseline.json")
	}
	if base, err = filepath.Abs(base); err != nil {
		return err
	}
	line := fmt.Sprintf("exec %q gate %q -b %q", filepath.ToSlash(self), filepath.ToSlash(abs), filepath.ToSlash(base))
	if cfgPath != "" {
		full, err := filepath.Abs(cfgPath)
		if err != nil {
			return err
		}
		line += fmt.Sprintf(" -c %q", filepath.ToSlash(full))
	}
	if err := os.WriteFile(file, []byte("#!/bin/sh\n"+hookMark+"\n"+line+"\n"), 0o755); err != nil {
		return err
	}
	fmt.Println("hook: every commit now runs the gate against", base)
	return nil
}

func suggestHeader(rel string, src []byte) string {
	f, err := parser.ParseFile(token.NewFileSet(), "", src, 0)
	if err != nil {
		return ""
	}
	var exported, other []string
	add := func(name string) {
		if name == "_" || name == "init" || name == "main" {
			return
		}
		if ast.IsExported(name) {
			exported = append(exported, name)
		} else {
			other = append(other, name)
		}
	}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				add(d.Name.Name)
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				if ts, ok := s.(*ast.TypeSpec); ok {
					add(ts.Name.Name)
				}
			}
		}
	}
	names := append(exported, other...)
	if len(names) > 3 {
		names = names[:3]
	}
	base := filepath.Base(rel)
	if len(names) == 0 {
		return base + " belongs to package " + f.Name.Name + "."
	}
	return base + " holds " + strings.Join(names, ", ") + "."
}

func writeHeaders(root string, cfg Config, out string) error {
	list := []Header{}
	err := walkFiles(root, cfg, func(rel, abs string, src []byte) error {
		if filepath.Ext(abs) != ".go" {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), "", src, parser.ParseComments)
		if err != nil || hasFileDoc(f) {
			return nil
		}
		list = append(list, Header{rel, suggestHeader(rel, src)})
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("headers: %d Go files have no leading comment\n", len(list))
	if out == "" {
		return nil
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, data, 0o600)
}

func addHeader(root, rel, text string) error {
	text = strings.TrimSpace(text)
	if text == "" || strings.ContainsAny(text, "\r\n") || !filepath.IsLocal(filepath.FromSlash(rel)) || filepath.Ext(rel) != ".go" {
		return fmt.Errorf("a Go file inside the folder and one line of text are required")
	}
	abs := filepath.Join(root, filepath.FromSlash(rel))
	src, err := os.ReadFile(abs)
	if err != nil {
		return err
	}
	f, err := parser.ParseFile(token.NewFileSet(), "", src, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("%s does not parse", rel)
	}
	if hasFileDoc(f) {
		return fmt.Errorf("%s already has a leading comment", rel)
	}
	end := "\n"
	if strings.Contains(string(src), "\r\n") {
		end = "\r\n"
	}
	next := []byte("// " + text + end + end + string(src))
	check, err := parser.ParseFile(token.NewFileSet(), "", next, parser.ParseComments)
	if err != nil || !hasFileDoc(check) || !sameCode(src, next) {
		return fmt.Errorf("proof failed: the header would change the code of %s", rel)
	}
	set, err := newUndo(root)
	if err != nil {
		return err
	}
	if err := set.replace(rel, abs, src, next); err != nil {
		return err
	}
	if err := set.save(); err != nil {
		return err
	}
	fmt.Println("header: added to", rel)
	return nil
}

func sameTS(a, b []byte) bool {
	ca, _ := tsViews(a)
	cb, _ := tsViews(b)
	return strings.Join(strings.Fields(string(ca)), " ") == strings.Join(strings.Fields(string(cb)), " ")
}

func fixTS(src []byte, cfg Config) (fixResult, error) {
	res := fixResult{out: src}
	if cfg.FixScope != "smart" {
		return res, nil
	}
	code, comments := tsViews(src)
	lines := strings.Split(string(src), "\n")
	codeLines, commentLines := strings.Split(string(code), "\n"), strings.Split(string(comments), "\n")
	drop := map[int]bool{}
	prev := ""
	for i, raw := range lines {
		mark := strings.TrimRight(commentLines[i], " \t\r")
		alone := strings.TrimSpace(codeLines[i]) == ""
		start := len(mark) - len(strings.TrimLeft(mark, " \t"))
		text := mark[start:]
		before := prev
		prev = ""
		if alone && strings.HasPrefix(text, "//") {
			prev = text
		}
		if text == "" || !matchesComment(text, cfg) {
			continue
		}
		if !alone || !strings.HasPrefix(text, "//") || start > len(raw) {
			res.review++
			res.note("review", i, raw, "")
			continue
		}
		next, act := smart(text, before == "" || endsSentence(before), cfg)
		switch act {
		case leave:
			res.review++
			res.note("review", i, raw, "")
		case rewrite:
			lines[i] = raw[:start] + next + lineEnd(raw)
			res.cleaned++
			res.note("rewrite", i, raw, lines[i])
		case remove:
			drop[i] = true
			res.removed++
			res.note("remove", i, raw, "")
		}
	}
	if res.removed == 0 && res.cleaned == 0 {
		return res, nil
	}
	var keep []string
	for i, l := range lines {
		if !drop[i] {
			keep = append(keep, l)
		}
	}
	out := []byte(strings.Join(keep, "\n"))
	if !sameTS(src, out) {
		return fixResult{}, fmt.Errorf("proof failed: code outside comments would change")
	}
	res.out = out
	return res, nil
}

func markLineExceptions(found []Finding, src []byte, cfg Config) {
	var lines []string
	for i, f := range found {
		for n, e := range cfg.Exceptions {
			if e.Line == "" || e.Rule != f.Rule || !e.covers(f.File) {
				continue
			}
			if lines == nil {
				lines = strings.Split(string(src), "\n")
			}
			if f.Line >= 1 && f.Line <= len(lines) && strings.Contains(lines[f.Line-1], e.Line) {
				found[i].Rule = "~" + f.Rule + "~" + strconv.Itoa(n)
				break
			}
		}
	}
}

func lineException(rule string) (string, int, bool) {
	parts := strings.Split(rule, "~")
	if len(parts) != 3 || parts[0] != "" {
		return "", 0, false
	}
	n, err := strconv.Atoi(parts[2])
	return parts[1], n, err == nil
}

func loadChurn(cfg Config) (map[string]int, error) {
	out := map[string]int{}
	if cfg.ChurnFile == "" {
		return out, nil
	}
	file := cfg.ChurnFile
	if !filepath.IsAbs(file) {
		file = filepath.Join(cfg.dir, file)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("churn_file: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if name := strings.TrimSpace(line); name != "" {
			out[filepath.ToSlash(name)]++
		}
	}
	return out, nil
}
