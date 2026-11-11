package main

import (
	"bytes"
	"fmt"
	"go/format"
	"go/parser"
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func walkFiles(root string, cfg Config, fn func(rel, abs string, src []byte) error) error {
	wanted := map[string]bool{}
	for _, e := range cfg.Extensions {
		wanted[e] = true
	}
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && matchAny(cfg.SkipDirs, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !wanted[filepath.Ext(p)] {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		return fn(filepath.ToSlash(rel), p, src)
	})
}

func tokens(src []byte) ([]string, error) {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	bad := 0
	s.Init(file, src, func(token.Position, string) { bad++ }, 0)
	var out []string
	for {
		_, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		out = append(out, tok.String()+" "+lit)
	}
	if bad > 0 {
		return nil, fmt.Errorf("%d scan errors", bad)
	}
	return out, nil
}

func sameCode(a, b []byte) bool {
	ta, err := tokens(a)
	if err != nil {
		return false
	}
	tb, err := tokens(b)
	if err != nil || len(ta) != len(tb) {
		return false
	}
	for i := range ta {
		if ta[i] != tb[i] {
			return false
		}
	}
	return true
}

func matchesComment(text string, cfg Config) bool {
	for _, re := range cfg.comments {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

func directive(text string) bool {
	for _, p := range []string{"//go:", "// +build", "//line ", "//export ", "//nolint", "//lint:"} {
		if strings.HasPrefix(text, p) {
			return true
		}
	}
	return false
}

func fixGo(src []byte, cfg Config) ([]byte, int, int, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.ParseComments)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("does not parse")
	}
	for _, im := range f.Imports {
		if im.Path.Value == `"C"` {
			return src, 0, 0, nil
		}
	}
	lines := strings.Split(string(src), "\n")
	drop := map[int]bool{}
	touched := map[int]bool{}
	removed, cleaned := 0, 0
	for _, cg := range f.Comments {
		group := false
		if cfg.FixScope == "group" {
			for _, c := range cg.List {
				if matchesComment(c.Text, cfg) {
					group = true
				}
			}
		}
		for _, c := range cg.List {
			start, end := fset.Position(c.Pos()), fset.Position(c.End())
			i := start.Line - 1
			if directive(c.Text) || touched[i] {
				continue
			}
			before := lines[i][:start.Column-1]
			if group || matchesComment(c.Text, cfg) {
				after := lines[end.Line-1][end.Column-1:]
				switch {
				case strings.TrimSpace(before) == "" && strings.TrimSpace(after) == "":
					for l := i; l < end.Line; l++ {
						drop[l] = true
						touched[l] = true
					}
					removed++
				case start.Line == end.Line && strings.TrimSpace(after) == "":
					cr := ""
					if strings.HasSuffix(lines[i], "\r") {
						cr = "\r"
					}
					lines[i] = strings.TrimRight(before, " \t") + cr
					touched[i] = true
					removed++
				}
				continue
			}
			if strings.HasPrefix(c.Text, "//") {
				tail := lines[i][start.Column-1:]
				clean := strings.Map(func(r rune) rune {
					if invisible[r] {
						return -1
					}
					return r
				}, tail)
				if clean != tail {
					lines[i] = before + clean
					touched[i] = true
					cleaned++
				}
			}
		}
	}
	if removed == 0 && cleaned == 0 {
		return src, 0, 0, nil
	}
	var keep []string
	for i, l := range lines {
		if !drop[i] {
			keep = append(keep, l)
		}
	}
	out := []byte(strings.Join(keep, "\n"))
	if !sameCode(src, out) {
		return nil, 0, 0, fmt.Errorf("proof failed: code tokens would change")
	}
	if formatted, err := format.Source(src); err == nil && bytes.Equal(formatted, src) {
		if again, err := format.Source(out); err == nil && sameCode(src, again) {
			out = again
		}
	}
	return out, removed, cleaned, nil
}

func fixAll(root string, cfg Config, dry bool) error {
	files, removed, cleaned, skipped := 0, 0, 0, 0
	err := walkFiles(root, cfg, func(rel, abs string, src []byte) error {
		if filepath.Ext(abs) != ".go" {
			return nil
		}
		out, r, c, err := fixGo(src, cfg)
		if err != nil {
			skipped++
			fmt.Printf("fix: skipped %s: %v\n", rel, err)
			return nil
		}
		if r == 0 && c == 0 {
			return nil
		}
		files++
		removed += r
		cleaned += c
		if dry {
			return nil
		}
		info, err := os.Stat(abs)
		if err != nil {
			return err
		}
		return os.WriteFile(abs, out, info.Mode().Perm())
	})
	if err != nil {
		return err
	}
	mode := "changed"
	if dry {
		mode = "would change"
	}
	fmt.Printf("fix: %s %d files, %d comments removed, %d comments cleaned, %d files skipped\n", mode, files, removed, cleaned, skipped)
	return nil
}
