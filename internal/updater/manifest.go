package updater

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"time"
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type ReleaseManifest struct {
	Version     string              `json:"version"`
	PublishedAt time.Time           `json:"published_at,omitempty"`
	Prerelease  bool                `json:"prerelease,omitempty"`
	Artifacts   map[string]Artifact `json:"artifacts"`
}

type Artifact struct {
	Archive         string            `json:"archive"`
	ArchiveSHA256   string            `json:"archive_sha256"`
	Installer       string            `json:"installer,omitempty"`
	InstallerSHA256 string            `json:"installer_sha256,omitempty"`
	Deb             string            `json:"deb,omitempty"`
	DebSHA256       string            `json:"deb_sha256,omitempty"`
	Files           map[string]string `json:"files"`
}

func TargetKey(goos, goarch string) string {
	return goos + "-" + goarch
}

func ParseManifest(r io.Reader) (ReleaseManifest, error) {
	var m ReleaseManifest
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	if err := dec.Decode(&m); err != nil {
		return ReleaseManifest{}, fmt.Errorf("decode release manifest: %w", err)
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return ReleaseManifest{}, errors.New("unexpected trailing data in release manifest")
	}
	if err := m.Validate(); err != nil {
		return ReleaseManifest{}, err
	}
	return m, nil
}

func (m ReleaseManifest) Validate() error {
	if _, err := ParseVersion(m.Version); err != nil {
		return fmt.Errorf("invalid manifest version %q: %w", m.Version, err)
	}
	if len(m.Artifacts) == 0 {
		return errors.New("release manifest contains no artifacts")
	}
	for target, art := range m.Artifacts {
		if target == "" || strings.ContainsAny(target, "/\\") {
			return fmt.Errorf("invalid target key %q", target)
		}
		if err := validateAssetName(art.Archive); err != nil {
			return fmt.Errorf("target %s archive: %w", target, err)
		}
		if !isSHA256(art.ArchiveSHA256) {
			return fmt.Errorf("target %s invalid archive_sha256", target)
		}
		if art.Installer != "" {
			if err := validateAssetName(art.Installer); err != nil {
				return fmt.Errorf("target %s installer: %w", target, err)
			}
			if !isSHA256(art.InstallerSHA256) {
				return fmt.Errorf("target %s invalid installer_sha256", target)
			}
		}
		if art.Deb != "" {
			if err := validateAssetName(art.Deb); err != nil {
				return fmt.Errorf("target %s deb: %w", target, err)
			}
			if !isSHA256(art.DebSHA256) {
				return fmt.Errorf("target %s invalid deb_sha256", target)
			}
		}
		if len(art.Files) == 0 {
			return fmt.Errorf("target %s has no inner file checksums", target)
		}
		for rel, sum := range art.Files {
			if err := validateRelativePath(rel); err != nil {
				return fmt.Errorf("target %s file %q: %w", target, rel, err)
			}
			if !isSHA256(sum) {
				return fmt.Errorf("target %s file %q invalid sha256", target, rel)
			}
		}
	}
	return nil
}

func ParseChecksums(r io.Reader) (map[string]string, error) {
	result := make(map[string]string)
	scanner := bufio.NewScanner(io.LimitReader(r, 1<<20))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("checksums line %d: expected '<sha256> <filename>'", lineNo)
		}
		hash := strings.ToLower(fields[0])
		name := strings.TrimPrefix(fields[1], "*")
		if !isSHA256(hash) {
			return nil, fmt.Errorf("checksums line %d: invalid sha256 %q", lineNo, fields[0])
		}
		if err := validateAssetName(name); err != nil {
			return nil, fmt.Errorf("checksums line %d: %w", lineNo, err)
		}
		result[name] = hash
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, errors.New("checksums file is empty")
	}
	return result, nil
}

func isSHA256(s string) bool {
	return sha256Pattern.MatchString(strings.ToLower(strings.TrimSpace(s)))
}

func validateAssetName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\:\x00") {
		return fmt.Errorf("invalid asset name %q", name)
	}
	return nil
}

func validateRelativePath(rel string) error {
	if rel == "" || strings.ContainsAny(rel, "\\:\x00") || strings.HasPrefix(rel, "/") {
		return errors.New("must be a clean relative slash path")
	}
	cleaned := path.Clean(rel)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned != rel {
		return errors.New("must be a normalized relative path without traversal")
	}
	return nil
}
