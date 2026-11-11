package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxDownload = 512 << 20
	vulnURL     = "https://vuln.go.dev/vulndb.zip"
	indexURL    = "https://vuln.go.dev/index/db.json"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  limator-update vulndb -dir <folder> [-url address]
  limator-update check  -dir <folder> [-url address]
  limator-update pack   -url <address> -sha256 <hash> -o <file>`)
	os.Exit(2)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "limator-update:", err)
	os.Exit(1)
}

func fetch(url string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if closeErr := resp.Body.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	if len(raw) > maxDownload {
		return nil, fmt.Errorf("%s: larger than %d MB", url, maxDownload>>20)
	}
	return raw, nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func unpack(raw []byte, dir string) (int, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, f := range zr.File {
		name := filepath.FromSlash(f.Name)
		if !filepath.IsLocal(name) {
			return 0, fmt.Errorf("unsafe path in archive: %s", f.Name)
		}
		target := filepath.Join(dir, name)
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return 0, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return 0, err
		}
		rc, err := f.Open()
		if err != nil {
			return 0, err
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxDownload))
		if closeErr := rc.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return 0, err
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

func updateVulnDB(dir, url string) (string, error) {
	raw, err := fetch(url)
	if err != nil {
		return "", err
	}
	fresh, old := dir+".new", dir+".old"
	if err := os.RemoveAll(fresh); err != nil {
		return "", err
	}
	n, err := unpack(raw, fresh)
	if err == nil && n == 0 {
		err = fmt.Errorf("archive is empty")
	}
	if err != nil {
		if rmErr := os.RemoveAll(fresh); rmErr != nil {
			return "", fmt.Errorf("%v; cleanup failed: %v", err, rmErr)
		}
		return "", err
	}
	if err := os.RemoveAll(old); err != nil {
		return "", err
	}
	if _, err := os.Stat(dir); err == nil {
		if err := os.Rename(dir, old); err != nil {
			return "", err
		}
	}
	if err := os.Rename(fresh, dir); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d files, sha256 %s", n, digest(raw)), nil
}

func updatePack(url, want, out string) error {
	if want == "" {
		return fmt.Errorf("-sha256 is required: a pack is only accepted with a pinned hash")
	}
	raw, err := fetch(url)
	if err != nil {
		return err
	}
	if got := digest(raw); !strings.EqualFold(got, want) {
		return fmt.Errorf("%s has sha256 %s, expected %s", url, got, want)
	}
	return os.WriteFile(out, raw, 0o644)
}

func modified(raw []byte) string {
	var v struct {
		Modified string `json:"modified"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	return v.Modified
}

func checkVulnDB(dir, url string) (string, error) {
	remote, err := fetch(url)
	if err != nil {
		return "", err
	}
	want := modified(remote)
	if want == "" {
		return "", fmt.Errorf("%s: no modification time", url)
	}
	local, err := os.ReadFile(filepath.Join(dir, "index", "db.json"))
	if err != nil {
		return "update available: no local copy, remote is " + want, nil
	}
	if have := modified(local); have != want {
		return "update available: local " + have + ", remote " + want, nil
	}
	return "up to date: " + want, nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	dir := fs.String("dir", "", "folder for the vulnerability database")
	url := fs.String("url", "", "download address")
	sum := fs.String("sha256", "", "expected SHA-256 of the pack")
	out := fs.String("o", "", "file to write the pack to")
	if err := fs.Parse(os.Args[2:]); err != nil {
		fail(err)
	}
	switch os.Args[1] {
	case "vulndb":
		if *dir == "" {
			usage()
		}
		if *url == "" {
			*url = vulnURL
		}
		msg, err := updateVulnDB(*dir, *url)
		if err != nil {
			fail(err)
		}
		fmt.Printf("limator-update: %s written to %s; the previous copy is kept in %s.old\n", msg, *dir, *dir)
	case "check":
		if *dir == "" {
			usage()
		}
		if *url == "" {
			*url = indexURL
		}
		msg, err := checkVulnDB(*dir, *url)
		if err != nil {
			fail(err)
		}
		fmt.Println("limator-update:", msg)
	case "pack":
		if *url == "" || *out == "" {
			usage()
		}
		if err := updatePack(*url, *sum, *out); err != nil {
			fail(err)
		}
		fmt.Printf("limator-update: pack written to %s\n", *out)
	default:
		usage()
	}
}
