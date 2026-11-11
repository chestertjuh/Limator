package main

import (
	"io/fs"
	"os"
	"path/filepath"
)

func walkTree(root string, cfg Config, want func(name string) bool, fn func(rel, abs string, src []byte) error) error {
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
		if !want(d.Name()) {
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

func walkFiles(root string, cfg Config, fn func(rel, abs string, src []byte) error) error {
	wanted := map[string]bool{}
	for _, e := range cfg.Extensions {
		wanted[e] = true
	}
	return walkTree(root, cfg, func(name string) bool { return wanted[filepath.Ext(name)] }, fn)
}
