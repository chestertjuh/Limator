package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Pack struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

func (cfg *Config) loadPacks() error {
	for _, p := range cfg.Packs {
		file := p.File
		if !filepath.IsAbs(file) {
			file = filepath.Join(cfg.dir, file)
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("packs: %w", err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, p.SHA256) {
			return fmt.Errorf("packs: %s has sha256 %s, the config pins %q", p.File, got, p.SHA256)
		}
		var body struct {
			Rules           []DataRule `json:"rules"`
			CommentPatterns []string   `json:"comment_patterns"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return fmt.Errorf("packs: %s: %w", p.File, err)
		}
		cfg.Rules = append(cfg.Rules, body.Rules...)
		cfg.CommentPatterns = append(cfg.CommentPatterns, body.CommentPatterns...)
	}
	return nil
}

func importSarif(raw []byte, im Import) ([]Finding, bool) {
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.Runs == nil {
		return nil, false
	}
	out := []Finding{}
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			f := Finding{Rule: im.ID, File: im.File, Line: 1, Msg: r.Message.Text}
			if len(r.Locations) > 0 {
				loc := r.Locations[0].PhysicalLocation
				if loc.ArtifactLocation.URI != "" {
					f.File = loc.ArtifactLocation.URI
				}
				if loc.Region.StartLine > 0 {
					f.Line = loc.Region.StartLine
				}
			}
			if r.RuleID != "" {
				f.Msg = r.RuleID + ": " + f.Msg
			}
			out = append(out, f)
		}
	}
	return out, true
}
