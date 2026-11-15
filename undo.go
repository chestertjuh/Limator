package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

type undoFile struct {
	Rel   string `json:"rel"`
	After string `json:"after"`
}

type undoSet struct {
	Root  string     `json:"root"`
	Files []undoFile `json:"files"`
	dir   string
}

func sumOf(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

func writeAtomic(path string, data []byte, perm fs.FileMode) error {
	tmp := path + ".limator-tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func undoHome(root string) (string, error) {
	home, err := cacheHome()
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "limator", "undo", sumOf([]byte(abs))[:16]), nil
}

func newUndo(root string) (*undoSet, error) {
	home, err := undoHome(root)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, time.Now().UTC().Format("20060102T150405.000"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &undoSet{Root: abs, dir: dir}, nil
}

func (u *undoSet) replace(rel, abs string, old, next []byte) error {
	keep := filepath.Join(u.dir, "files", filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(keep), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keep, old, 0o600); err != nil {
		return err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return err
	}
	if err := writeAtomic(abs, next, info.Mode().Perm()); err != nil {
		return err
	}
	u.Files = append(u.Files, undoFile{rel, sumOf(next)})
	return nil
}

func (u *undoSet) save() error {
	data, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(u.dir, "undo.json"), data, 0o600)
}

func lastUndo(root string) (*undoSet, error) {
	home, err := undoHome(root)
	if err != nil {
		return nil, err
	}
	names, err := os.ReadDir(home)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for i := len(names) - 1; i >= 0; i-- {
		dir := filepath.Join(home, names[i].Name())
		data, err := os.ReadFile(filepath.Join(dir, "undo.json"))
		if err != nil {
			continue
		}
		set := &undoSet{dir: dir}
		if err := json.Unmarshal(data, set); err != nil {
			return nil, fmt.Errorf("undo record %s is damaged", names[i].Name())
		}
		return set, nil
	}
	return nil, fmt.Errorf("nothing to undo")
}

func undoLast(root string) error {
	set, err := lastUndo(root)
	if err != nil {
		return err
	}
	restored, skipped := 0, 0
	for _, f := range set.Files {
		if !filepath.IsLocal(filepath.FromSlash(f.Rel)) {
			return fmt.Errorf("undo record holds a path outside the directory")
		}
		abs := filepath.Join(root, filepath.FromSlash(f.Rel))
		cur, err := os.ReadFile(abs)
		if err != nil || sumOf(cur) != f.After {
			skipped++
			fmt.Printf("undo: left %s alone, it changed after the fix\n", f.Rel)
			continue
		}
		old, err := os.ReadFile(filepath.Join(set.dir, "files", filepath.FromSlash(f.Rel)))
		if err != nil {
			return err
		}
		info, err := os.Stat(abs)
		if err != nil {
			return err
		}
		if err := writeAtomic(abs, old, info.Mode().Perm()); err != nil {
			return err
		}
		restored++
	}
	if err := os.Rename(filepath.Join(set.dir, "undo.json"), filepath.Join(set.dir, "undone.json")); err != nil {
		return err
	}
	fmt.Printf("undo: restored %d files, %d left alone\n", restored, skipped)
	return nil
}
