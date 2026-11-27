package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const maxExtractedBytes int64 = 256 << 20 // 256 MiB

func ExtractArchive(archivePath, destDir string) error {
	switch {
	case strings.HasSuffix(strings.ToLower(archivePath), ".zip"):
		return extractZip(archivePath, destDir, maxExtractedBytes)
	case strings.HasSuffix(strings.ToLower(archivePath), ".tar.gz"):
		return extractTarGz(archivePath, destDir, maxExtractedBytes)
	default:
		return fmt.Errorf("unsupported archive format: %s", filepath.Base(archivePath))
	}
}

func safeExtractPath(destDir, rawName string) (string, error) {
	cleaned := strings.ReplaceAll(rawName, "\\", "/")
	cleaned = strings.TrimPrefix(cleaned, "./")
	if cleaned == "" || strings.HasPrefix(cleaned, "/") || strings.Contains(cleaned, ":") {
		return "", fmt.Errorf("unsafe archive path %q", rawName)
	}
	norm := path.Clean(cleaned)
	if norm == "." || norm == ".." || strings.HasPrefix(norm, "../") {
		return "", fmt.Errorf("archive path traversal detected: %q", rawName)
	}
	full := filepath.Join(destDir, filepath.FromSlash(norm))
	rel, err := filepath.Rel(destDir, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("archive path escapes destination: %q", rawName)
	}
	return full, nil
}

func extractZip(archivePath, destDir string, limit int64) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer zr.Close()

	var total int64
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in archive: %s", f.Name)
		}
		target, err := safeExtractPath(destDir, f.Name)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		n, writeErr := writeExtractedFile(target, rc, f.Mode().Perm(), limit-total)
		closeErr := rc.Close()
		if err := errors.Join(writeErr, closeErr); err != nil {
			return err
		}
		total += n
	}
	return nil
}

func extractTarGz(archivePath, destDir string, limit int64) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			target, err := safeExtractPath(destDir, hdr.Name)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			mode := os.FileMode(hdr.Mode).Perm()
			if mode == 0 {
				mode = 0644
			}
			n, err := writeExtractedFile(target, tr, mode, limit-total)
			if err != nil {
				return err
			}
			total += n
		default:
			return fmt.Errorf("refusing unsupported tar entry type %d for %s", hdr.Typeflag, hdr.Name)
		}
	}
	return nil
}

func writeExtractedFile(target string, r io.Reader, mode os.FileMode, remaining int64) (int64, error) {
	if remaining <= 0 {
		return 0, errors.New("extracted archive size exceeds safety limit")
	}
	if mode == 0 {
		mode = 0644
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return 0, err
	}
	n, copyErr := io.Copy(out, io.LimitReader(r, remaining+1))
	syncErr := out.Sync()
	closeErr := out.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		return n, err
	}
	if n > remaining {
		return n, errors.New("extracted archive size exceeds safety limit")
	}
	return n, nil
}
