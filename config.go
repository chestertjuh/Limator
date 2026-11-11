package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

type DataRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Files   string `json:"files"`
	Msg     string `json:"msg"`
	re      *regexp.Regexp
}

type Exception struct {
	Rule   string `json:"rule"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Used   int    `json:"used"`
}

type Import struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	File string `json:"file"`
}

type Config struct {
	CommentPatterns []string    `json:"comment_patterns"`
	MaxFileLines    int         `json:"max_file_lines"`
	MaxLineLength   int         `json:"max_line_length"`
	SkipDirs        []string    `json:"skip_dirs"`
	Extensions      []string    `json:"extensions"`
	Rules           []DataRule  `json:"rules"`
	Exceptions      []Exception `json:"exceptions"`
	Imports         []Import    `json:"imports"`
	comments        []*regexp.Regexp
	dir             string
}

func loadConfig(file string, required bool) (Config, error) {
	cfg := Config{dir: filepath.Dir(file)}
	raw, err := os.ReadFile(file)
	if err != nil && (required || !errors.Is(err, os.ErrNotExist)) {
		return cfg, err
	}
	if err == nil {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("%s: %w", file, err)
		}
	}
	if cfg.MaxFileLines == 0 {
		cfg.MaxFileLines = 1000
	}
	if cfg.MaxLineLength == 0 {
		cfg.MaxLineLength = 160
	}
	if cfg.SkipDirs == nil {
		cfg.SkipDirs = []string{"vendor", "node_modules", ".git", ".next", "dist", "build", "out"}
	}
	if cfg.Extensions == nil {
		cfg.Extensions = []string{".go", ".ts", ".tsx"}
	}
	return cfg, cfg.validate()
}

func (cfg *Config) validate() error {
	for _, p := range cfg.CommentPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("comment_patterns: %w", err)
		}
		cfg.comments = append(cfg.comments, re)
	}
	if err := checkSkip(cfg.SkipDirs); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.ID == "" || builtin(r.ID) || seen[r.ID] {
			return fmt.Errorf("rules: id %q is empty, reserved or used twice", r.ID)
		}
		seen[r.ID] = true
		re, err := regexp.Compile(r.Pattern)
		if err != nil || r.Pattern == "" {
			return fmt.Errorf("rules %s: bad pattern", r.ID)
		}
		r.re = re
		if r.Files == "" {
			r.Files = "*"
		}
		if _, err := path.Match(r.Files, ""); err != nil {
			return fmt.Errorf("rules %s: bad files glob", r.ID)
		}
		if r.Name == "" {
			r.Name = r.ID
		}
		if r.Msg == "" {
			r.Msg = r.Name
		}
	}
	for i := range cfg.Imports {
		im := &cfg.Imports[i]
		if im.ID == "" || im.File == "" || builtin(im.ID) || seen[im.ID] {
			return fmt.Errorf("imports: id %q needs a file and a free id", im.ID)
		}
		seen[im.ID] = true
		if im.Name == "" {
			im.Name = im.ID
		}
	}
	for _, e := range cfg.Exceptions {
		if e.Rule == "" || e.Path == "" || strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("exceptions: rule, path and reason are required (%s %s)", e.Rule, e.Path)
		}
		if _, err := path.Match(e.Path, ""); err != nil && !strings.HasSuffix(e.Path, "/") {
			return fmt.Errorf("exceptions %s: bad path glob %q", e.Rule, e.Path)
		}
	}
	return nil
}

func checkSkip(pats []string) error {
	for _, pat := range pats {
		if _, err := filepath.Match(pat, ""); err != nil {
			return fmt.Errorf("skip_dirs %q: %w", pat, err)
		}
	}
	return nil
}

func matchAny(pats []string, name string) bool {
	for _, pat := range pats {
		if ok, err := filepath.Match(pat, name); err == nil && ok {
			return true
		}
	}
	return false
}

func (e Exception) matches(f Finding) bool {
	if e.Rule != f.Rule {
		return false
	}
	if strings.HasSuffix(e.Path, "/") {
		return strings.HasPrefix(f.File, e.Path)
	}
	if ok, err := path.Match(e.Path, f.File); err == nil && ok {
		return true
	}
	ok, err := path.Match(e.Path, path.Base(f.File))
	return err == nil && ok
}
