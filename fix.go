package main

import (
	"bytes"
	"fmt"
	"go/format"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	leave = iota
	rewrite
	remove
)

type fixResult struct {
	out                      []byte
	removed, cleaned, review int
}

var (
	parenRe = regexp.MustCompile(`\s*\([^()]*\)`)
	leadSep = regexp.MustCompile(`^\s*[:\-\x{2013}\x{2014}]\s+`)
)

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

func hasWord(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) >= 0
}

func upperFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 {
		return s
	}
	return string(unicode.ToUpper(r)) + s[n:]
}

func lineEnd(line string) string {
	if strings.HasSuffix(line, "\r") {
		return "\r"
	}
	return ""
}

func endsSentence(text string) bool {
	t := strings.TrimSpace(strings.TrimPrefix(text, "//"))
	return t == "" || strings.ContainsAny(t[len(t)-1:], ".!?")
}

func stripRefs(body string, cfg Config) (string, bool) {
	out := parenRe.ReplaceAllStringFunc(body, func(m string) string {
		if matchesComment(m, cfg) {
			return ""
		}
		return m
	})
	for _, re := range cfg.comments {
		loc := re.FindStringIndex(out)
		if loc == nil || strings.TrimSpace(out[:loc[0]]) != "" {
			continue
		}
		rest := out[loc[1]:]
		if !hasWord(rest) {
			out = ""
			continue
		}
		if sep := leadSep.FindString(rest); sep != "" {
			out = out[:loc[0]] + upperFirst(rest[len(sep):])
		}
	}
	if matchesComment(out, cfg) {
		return body, false
	}
	return out, true
}

func smart(text string, droppable bool, cfg Config) (string, int) {
	if !strings.HasPrefix(text, "//") {
		return text, leave
	}
	body, ok := stripRefs(text[2:], cfg)
	switch {
	case !ok:
		return text, leave
	case hasWord(body):
		return "//" + strings.TrimRight(body, " \t"), rewrite
	case droppable:
		return "", remove
	}
	return text, leave
}

func fixGo(src []byte, cfg Config) ([]byte, int, int, error) {
	res, err := fixFile(src, cfg)
	return res.out, res.removed, res.cleaned, err
}

func fixFile(src []byte, cfg Config) (fixResult, error) {
	res := fixResult{out: src}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.ParseComments)
	if err != nil {
		return fixResult{}, fmt.Errorf("does not parse")
	}
	for _, im := range f.Imports {
		if im.Path.Value == `"C"` {
			return res, nil
		}
	}
	lines := strings.Split(string(src), "\n")
	drop := map[int]bool{}
	touched := map[int]bool{}
	for _, cg := range f.Comments {
		group := false
		if cfg.FixScope == "group" {
			for _, c := range cg.List {
				if matchesComment(c.Text, cfg) {
					group = true
				}
			}
		}
		for k, c := range cg.List {
			start, end := fset.Position(c.Pos()), fset.Position(c.End())
			i := start.Line - 1
			if directive(c.Text) || touched[i] {
				continue
			}
			before := lines[i][:start.Column-1]
			alone := strings.TrimSpace(before) == ""
			hit := group || matchesComment(c.Text, cfg)
			if hit && cfg.FixScope == "smart" {
				first := k == 0 || endsSentence(cg.List[k-1].Text)
				text, act := smart(c.Text, first || !alone, cfg)
				switch act {
				case leave:
					res.review++
				case rewrite:
					lines[i] = before + text + lineEnd(lines[i])
					touched[i] = true
					res.cleaned++
				case remove:
					if alone {
						drop[i] = true
					} else {
						lines[i] = strings.TrimRight(before, " \t") + lineEnd(lines[i])
					}
					touched[i] = true
					res.removed++
				}
				continue
			}
			if hit {
				after := lines[end.Line-1][end.Column-1:]
				switch {
				case alone && strings.TrimSpace(after) == "":
					for l := i; l < end.Line; l++ {
						drop[l] = true
						touched[l] = true
					}
					res.removed++
				case start.Line == end.Line && strings.TrimSpace(after) == "":
					lines[i] = strings.TrimRight(before, " \t") + lineEnd(lines[i])
					touched[i] = true
					res.removed++
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
					res.cleaned++
				}
			}
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
	if !sameCode(src, out) {
		return fixResult{}, fmt.Errorf("proof failed: code tokens would change")
	}
	if formatted, err := format.Source(src); err == nil && bytes.Equal(formatted, src) {
		if again, err := format.Source(out); err == nil && sameCode(src, again) {
			out = again
		}
	}
	res.out = out
	return res, nil
}

func fixAll(root string, cfg Config, dry bool) error {
	files, skipped := 0, 0
	var sum fixResult
	err := walkFiles(root, cfg, func(rel, abs string, src []byte) error {
		if filepath.Ext(abs) != ".go" {
			return nil
		}
		res, err := fixFile(src, cfg)
		if err != nil {
			skipped++
			fmt.Printf("fix: skipped %s: %v\n", rel, err)
			return nil
		}
		sum.review += res.review
		if res.removed == 0 && res.cleaned == 0 {
			return nil
		}
		files++
		sum.removed += res.removed
		sum.cleaned += res.cleaned
		if dry {
			return nil
		}
		info, err := os.Stat(abs)
		if err != nil {
			return err
		}
		return os.WriteFile(abs, res.out, info.Mode().Perm())
	})
	if err != nil {
		return err
	}
	mode := "changed"
	if dry {
		mode = "would change"
	}
	fmt.Printf("fix: %s %d files, %d comments removed, %d comments cleaned, %d left for review, %d files skipped\n", mode, files, sum.removed, sum.cleaned, sum.review, skipped)
	return nil
}
