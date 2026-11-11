package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type OriginMark struct {
	File   string `json:"file"`
	Func   string `json:"func"`
	Origin string `json:"origin"`
	Note   string `json:"note"`
}

func originFile(root string, cfg Config) string {
	if cfg.OriginFile == "" {
		return filepath.Join(root, ".limator-origin.json")
	}
	if filepath.IsAbs(cfg.OriginFile) {
		return cfg.OriginFile
	}
	return filepath.Join(cfg.dir, cfg.OriginFile)
}

func loadOriginMarks(file string) ([]OriginMark, error) {
	raw, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var marks []OriginMark
	if err := json.Unmarshal(raw, &marks); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return marks, nil
}

func loadOrigins(file string) (map[string]string, error) {
	marks, err := loadOriginMarks(file)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, m := range marks {
		out[m.File+"|"+m.Func] = m.Origin
	}
	return out, nil
}

func setOrigin(root string, cfg Config, opt map[string]string, all []Unit) error {
	kind, file, fn, every := opt["-kind"], filepath.ToSlash(opt["-f"]), opt["-fn"], opt["-all"] != ""
	if (kind != "ai" && kind != "human" && kind != "mixed") || (file == "" && !every) {
		return fmt.Errorf("origin needs -kind ai|human|mixed and either -f <file> [-fn function] or -all yes")
	}
	target := originFile(root, cfg)
	old, err := loadOriginMarks(target)
	if err != nil {
		return err
	}
	marks := map[string]OriginMark{}
	for _, m := range old {
		marks[m.File+"|"+m.Func] = m
	}
	count := 0
	for _, u := range all {
		if every || (u.File == file && (fn == "" || u.Func == fn)) {
			marks[u.File+"|"+u.Func] = OriginMark{File: u.File, Func: u.Func, Origin: kind, Note: opt["-note"]}
			count++
		}
	}
	if count == 0 {
		return fmt.Errorf("no function matched %s %s", file, fn)
	}
	list := make([]OriginMark, 0, len(marks))
	for _, m := range marks {
		list = append(list, m)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].File != list[j].File {
			return list[i].File < list[j].File
		}
		return list[i].Func < list[j].Func
	})
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("origin: recorded %d functions as %s\n", count, kind)
	return os.WriteFile(target, append(raw, '\n'), 0o644)
}
