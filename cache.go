// cache.go keeps the findings of unchanged files between scans.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

var cacheHome = os.UserCacheDir

type cache struct {
	path string
	old  map[string][]Finding
}

func openCache(root string, cfg Config) *cache {
	if cfg.NoCache {
		return nil
	}
	dir, err := cacheHome()
	if err != nil {
		return nil
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil
	}
	id := sha256.Sum256([]byte(version + "\x00" + cfg.sum + "\x00" + abs))
	c := &cache{path: filepath.Join(dir, "limator", hex.EncodeToString(id[:8])+".json"), old: map[string][]Finding{}}
	data, err := os.ReadFile(c.path)
	if err != nil {
		return c
	}
	if json.Unmarshal(data, &c.old) != nil {
		c.old = map[string][]Finding{}
	}
	return c
}

func fileKey(rel string, src []byte) string {
	h := sha256.New()
	h.Write([]byte(rel))
	h.Write([]byte{0})
	h.Write(src)
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func (c *cache) save(keys []string, found [][]Finding) error {
	next := make(map[string][]Finding, len(keys))
	for i, k := range keys {
		next[k] = found[i]
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}
