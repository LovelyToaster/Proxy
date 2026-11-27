package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"proxy.local/m0/internal/updater"
)

func main() {
	var (
		dir        string
		version    string
		prerelease bool
	)
	flag.StringVar(&dir, "dir", "", "directory containing release artifacts")
	flag.StringVar(&version, "version", "", "release semantic version (e.g. v0.2.0)")
	flag.BoolVar(&prerelease, "prerelease", false, "mark release as prerelease")
	flag.Parse()

	if dir == "" || version == "" {
		fmt.Fprintln(os.Stderr, "usage: release-manifest --dir <artifacts-dir> --version <vX.Y.Z> [--prerelease]")
		os.Exit(2)
	}
	if err := run(dir, version, prerelease); err != nil {
		fmt.Fprintf(os.Stderr, "release-manifest: %v\n", err)
		os.Exit(1)
	}
}

func run(dir, version string, prerelease bool) error {
	sv, err := updater.ParseVersion(version)
	if err != nil {
		return err
	}
	if sv.IsPrerelease() {
		prerelease = true
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	artifacts := make(map[string]updater.Artifact)
	checksumLines := make([]string, 0, len(entries))

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "checksums.txt" || name == "release-manifest.json" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		full := filepath.Join(dir, name)
		sum, err := fileSHA256(full)
		if err != nil {
			return err
		}
		checksumLines = append(checksumLines, fmt.Sprintf("%s  %s", sum, name))

		switch {
		case name == "proxy-windows-amd64.zip":
			art := artifacts["windows-amd64"]
			art.Archive = name
			art.ArchiveSHA256 = sum
			files, err := zipFileHashes(full)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			art.Files = files
			artifacts["windows-amd64"] = art
		case strings.HasPrefix(name, "Proxy-Setup-") && strings.HasSuffix(name, "-x64.exe"):
			art := artifacts["windows-amd64"]
			art.Installer = name
			art.InstallerSHA256 = sum
			artifacts["windows-amd64"] = art
		case name == "proxy-linux-amd64.tar.gz":
			art := artifacts["linux-amd64"]
			art.Archive = name
			art.ArchiveSHA256 = sum
			files, err := tarGzFileHashes(full)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			art.Files = files
			artifacts["linux-amd64"] = art
		case name == "proxy-linux-arm64.tar.gz":
			art := artifacts["linux-arm64"]
			art.Archive = name
			art.ArchiveSHA256 = sum
			files, err := tarGzFileHashes(full)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			art.Files = files
			artifacts["linux-arm64"] = art
		case strings.HasPrefix(name, "proxy_") && strings.HasSuffix(name, "_amd64.deb"):
			art := artifacts["linux-amd64"]
			art.Deb = name
			art.DebSHA256 = sum
			artifacts["linux-amd64"] = art
		case strings.HasPrefix(name, "proxy_") && strings.HasSuffix(name, "_arm64.deb"):
			art := artifacts["linux-arm64"]
			art.Deb = name
			art.DebSHA256 = sum
			artifacts["linux-arm64"] = art
		}
	}

	manifest := updater.ReleaseManifest{
		Version:     version,
		PublishedAt: time.Now().UTC().Truncate(time.Second),
		Prerelease:  prerelease,
		Artifacts:   artifacts,
	}
	if err := manifest.Validate(); err != nil {
		return fmt.Errorf("validate manifest: %w", err)
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	manifestBytes = append(manifestBytes, '\n')
	manifestPath := filepath.Join(dir, "release-manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0644); err != nil {
		return err
	}
	manifestSum := sha256.Sum256(manifestBytes)
	checksumLines = append(checksumLines, fmt.Sprintf("%s  release-manifest.json", hex.EncodeToString(manifestSum[:])))
	sort.Slice(checksumLines, func(i, j int) bool {
		_, ni, _ := strings.Cut(checksumLines[i], "  ")
		_, nj, _ := strings.Cut(checksumLines[j], "  ")
		return ni < nj
	})

	checksumPath := filepath.Join(dir, "checksums.txt")
	return os.WriteFile(checksumPath, []byte(strings.Join(checksumLines, "\n")+"\n"), 0644)
}

func fileSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func zipFileHashes(filePath string) (map[string]string, error) {
	zr, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out := make(map[string]string)
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rel := path.Clean(strings.ReplaceAll(f.Name, "\\", "/"))
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		_, copyErr := io.Copy(h, rc)
		closeErr := rc.Close()
		if copyErr != nil {
			return nil, copyErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		out[rel] = hex.EncodeToString(h.Sum(nil))
	}
	return out, nil
}

func tarGzFileHashes(filePath string) (map[string]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := make(map[string]string)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		rel := path.Clean(strings.TrimPrefix(strings.ReplaceAll(hdr.Name, "\\", "/"), "./"))
		h := sha256.New()
		if _, err := io.Copy(h, tr); err != nil {
			return nil, err
		}
		out[rel] = hex.EncodeToString(h.Sum(nil))
	}
	return out, nil
}
