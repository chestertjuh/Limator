// walk.go lists the files to scan and reads them on every processor core.

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

type entry struct{ rel, abs string }

func listTree(root string, cfg Config, want func(name string) bool) ([]entry, error) {
	var out []entry
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
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
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out = append(out, entry{filepath.ToSlash(rel), p})
		return nil
	})
	return out, err
}

func wantedExt(cfg Config) func(name string) bool {
	wanted := map[string]bool{}
	for _, e := range cfg.Extensions {
		wanted[e] = true
	}
	return func(name string) bool { return wanted[filepath.Ext(name)] }
}

func walkTree(root string, cfg Config, want func(name string) bool, fn func(rel, abs string, src []byte) error) error {
	entries, err := listTree(root, cfg, want)
	if err != nil {
		return err
	}
	for _, e := range entries {
		src, err := os.ReadFile(e.abs)
		if err != nil {
			return err
		}
		if err := fn(e.rel, e.abs, src); err != nil {
			return err
		}
	}
	return nil
}

func walkFiles(root string, cfg Config, fn func(rel, abs string, src []byte) error) error {
	return walkTree(root, cfg, wantedExt(cfg), fn)
}

func mapFiles[T any](entries []entry, fn func(i int, e entry, src []byte) T) ([]T, error) {
	out := make([]T, len(entries))
	errs := make([]error, len(entries))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < runtime.NumCPU(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				src, err := os.ReadFile(entries[i].abs)
				if err != nil {
					errs[i] = err
					continue
				}
				out[i] = fn(i, entries[i], src)
			}
		}()
	}
	for i := range entries {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
