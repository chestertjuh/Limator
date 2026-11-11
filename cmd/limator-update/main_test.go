package main

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func archive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func serve(t *testing.T, body []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write(body); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestVulnDBIsReplacedAndPreviousCopyKept(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vulndb")
	first := serve(t, archive(t, map[string]string{"ID/GO-1.json": "{}", "index/db.json": "{}"}))
	if _, err := updateVulnDB(dir, first); err != nil {
		t.Fatal(err)
	}
	second := serve(t, archive(t, map[string]string{"ID/GO-2.json": "{}"}))
	if _, err := updateVulnDB(dir, second); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ID", "GO-2.json")); err != nil {
		t.Errorf("new copy missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir+".old", "ID", "GO-1.json")); err != nil {
		t.Errorf("previous copy not kept: %v", err)
	}
}

func TestUnsafeArchiveLeavesTheDatabaseAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vulndb")
	good := serve(t, archive(t, map[string]string{"ID/GO-1.json": "{}"}))
	if _, err := updateVulnDB(dir, good); err != nil {
		t.Fatal(err)
	}
	for _, files := range []map[string]string{{"../evil.json": "{}"}, {}} {
		if _, err := updateVulnDB(dir, serve(t, archive(t, files))); err == nil {
			t.Errorf("accepted archive %v", files)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "ID", "GO-1.json")); err != nil {
		t.Errorf("database was changed by a refused archive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil.json")); err == nil {
		t.Error("archive wrote outside the target folder")
	}
}

func TestPackNeedsTheRightHash(t *testing.T) {
	body := []byte(`{"rules":[]}`)
	url := serve(t, body)
	out := filepath.Join(t.TempDir(), "pack.json")
	if err := updatePack(url, "", out); err == nil {
		t.Error("pack accepted without a hash")
	}
	if err := updatePack(url, "00", out); err == nil {
		t.Error("pack accepted with a wrong hash")
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("refused pack was written")
	}
	if err := updatePack(url, digest(body), out); err != nil {
		t.Errorf("pack with the right hash refused: %v", err)
	}
}

func TestCheckComparesModificationTimes(t *testing.T) {
	dir := t.TempDir()
	url := serve(t, []byte(`{"modified":"2026-01-02T00:00:00Z"}`))
	if msg, err := checkVulnDB(dir, url); err != nil || !strings.HasPrefix(msg, "update available: no local copy") {
		t.Errorf("no local copy: %q %v", msg, err)
	}
	index := filepath.Join(dir, "index", "db.json")
	if err := os.MkdirAll(filepath.Dir(index), 0o755); err != nil {
		t.Fatal(err)
	}
	for body, want := range map[string]string{`{"modified":"2026-01-01T00:00:00Z"}`: "update available: local", `{"modified":"2026-01-02T00:00:00Z"}`: "up to date"} {
		if err := os.WriteFile(index, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if msg, err := checkVulnDB(dir, url); err != nil || !strings.HasPrefix(msg, want) {
			t.Errorf("%s: %q %v", want, msg, err)
		}
	}
}
