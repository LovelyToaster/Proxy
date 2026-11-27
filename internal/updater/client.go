package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"proxy.local/m0/internal/buildinfo"
	"proxy.local/m0/internal/config"
)

const (
	maxManifestBytes = 1 << 20   // 1 MiB
	maxArchiveBytes  = 128 << 20 // 128 MiB
)

type Options struct {
	Repo           string
	BaseURL        string
	Channel        string
	TargetVersion  string
	Prerelease     bool
	Force          bool
	CurrentVersion string
	GOOS           string
	GOARCH         string
	InstallDir     string
	ConfigPath     string
	HTTPClient     *http.Client
	Progress       io.Writer
	SkipPrecheck   bool
}

type CheckResult struct {
	CurrentVersion     string            `json:"current_version"`
	TargetVersion      string            `json:"target_version"`
	UpdateAvailable    bool              `json:"update_available"`
	DriverUpdateNeeded bool              `json:"driver_update_needed"`
	Reason             string            `json:"reason"`
	Target             string            `json:"target"`
	Prerelease         bool              `json:"prerelease,omitempty"`
	Manifest           ReleaseManifest   `json:"-"`
	Artifact           Artifact          `json:"-"`
	Checksums          map[string]string `json:"-"`
	AssetURLs          map[string]string `json:"-"`
}

type Client struct {
	httpClient *http.Client
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}
	return &Client{httpClient: httpClient}
}

func defaultHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	return &http.Client{
		Transport: transport,
		Timeout:   2 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects during update download")
			}
			if !config.AllowedGeoURL(req.URL) {
				return fmt.Errorf("disallowed update redirect URL: %s", req.URL)
			}
			if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return errors.New("refusing HTTPS to HTTP downgrade redirect")
			}
			return nil
		},
	}
}

func normalizeOptions(opts Options) Options {
	if opts.Repo == "" {
		opts.Repo = config.DefaultUpdateRepo
	}
	if opts.Channel == "" {
		opts.Channel = config.DefaultUpdateChannel
	}
	if opts.CurrentVersion == "" {
		opts.CurrentVersion = buildinfo.Version
	}
	if opts.GOOS == "" {
		opts.GOOS = runtime.GOOS
	}
	if opts.GOARCH == "" {
		opts.GOARCH = runtime.GOARCH
	}
	if opts.InstallDir == "" {
		if exe, err := os.Executable(); err == nil {
			opts.InstallDir = filepath.Dir(exe)
		}
	}
	return opts
}

type githubRelease struct {
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func (c *Client) Check(ctx context.Context, opts Options) (*CheckResult, error) {
	opts = normalizeOptions(opts)
	target := TargetKey(opts.GOOS, opts.GOARCH)

	assetURLs, err := c.resolveAssetURLs(ctx, opts)
	if err != nil {
		return nil, err
	}

	manifestURL, ok := assetURLs["release-manifest.json"]
	if !ok {
		return nil, errors.New("release does not contain release-manifest.json")
	}
	checksumsURL, ok := assetURLs["checksums.txt"]
	if !ok {
		return nil, errors.New("release does not contain checksums.txt")
	}

	checksumsData, err := c.fetchBytes(ctx, checksumsURL, maxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("fetch checksums.txt: %w", err)
	}
	checksums, err := ParseChecksums(strings.NewReader(string(checksumsData)))
	if err != nil {
		return nil, fmt.Errorf("parse checksums.txt: %w", err)
	}

	manifestData, err := c.fetchBytes(ctx, manifestURL, maxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("fetch release-manifest.json: %w", err)
	}
	if expected, exists := checksums["release-manifest.json"]; exists {
		actual := sha256HexBytes(manifestData)
		if !strings.EqualFold(actual, expected) {
			return nil, fmt.Errorf("release-manifest.json SHA-256 mismatch: got %s, expected %s", actual, expected)
		}
	}

	manifest, err := ParseManifest(strings.NewReader(string(manifestData)))
	if err != nil {
		return nil, err
	}
	art, ok := manifest.Artifacts[target]
	if !ok {
		return nil, fmt.Errorf("release %s has no artifact for %s", manifest.Version, target)
	}
	if sum, exists := checksums[art.Archive]; !exists || !strings.EqualFold(sum, art.ArchiveSHA256) {
		return nil, fmt.Errorf("checksum mismatch between checksums.txt and manifest for %s", art.Archive)
	}
	if art.Deb != "" {
		if sum, exists := checksums[art.Deb]; !exists || !strings.EqualFold(sum, art.DebSHA256) {
			return nil, fmt.Errorf("checksum mismatch between checksums.txt and manifest for %s", art.Deb)
		}
	}

	// Fill direct URLs for mirror/base_url mode if only base URL was resolved.
	if base, ok := assetURLs["_base"]; ok {
		assetURLs[art.Archive] = base + "/" + art.Archive
		if art.Deb != "" {
			assetURLs[art.Deb] = base + "/" + art.Deb
		}
		if art.Installer != "" {
			assetURLs[art.Installer] = base + "/" + art.Installer
		}
	}

	swNeeds, err := NeedsUpdate(opts.CurrentVersion, manifest.Version, opts.Force)
	if err != nil {
		return nil, err
	}
	driverNeeds := false
	if opts.GOOS == "windows" {
		driverNeeds = opts.Force || DriverNeedsUpdate(opts.InstallDir, art.Files)
	}

	updateAvail := swNeeds || driverNeeds
	reason := "already up to date"
	switch {
	case opts.Force:
		reason = "forced update requested"
	case swNeeds && driverNeeds:
		reason = "new software version and Windows driver update available"
	case swNeeds:
		reason = "new software version available"
	case driverNeeds:
		reason = "Windows WinDivert driver update or repair required"
	}

	return &CheckResult{
		CurrentVersion:     opts.CurrentVersion,
		TargetVersion:      manifest.Version,
		UpdateAvailable:    updateAvail,
		DriverUpdateNeeded: driverNeeds,
		Reason:             reason,
		Target:             target,
		Prerelease:         manifest.Prerelease,
		Manifest:           manifest,
		Artifact:           art,
		Checksums:          checksums,
		AssetURLs:          assetURLs,
	}, nil
}

func DriverNeedsUpdate(installDir string, manifestFiles map[string]string) bool {
	if installDir == "" {
		return true
	}
	for _, name := range []string{"WinDivert.dll", "WinDivert64.sys"} {
		expected, ok := manifestFiles[name]
		if !ok {
			continue
		}
		actual, present, err := buildinfo.FileSHA256(filepath.Join(installDir, name))
		if err != nil || !present || !strings.EqualFold(actual, expected) {
			return true
		}
	}
	return false
}

func (c *Client) resolveAssetURLs(ctx context.Context, opts Options) (map[string]string, error) {
	if opts.BaseURL != "" {
		base := strings.TrimRight(opts.BaseURL, "/")
		if opts.TargetVersion != "" {
			base = base + "/" + url.PathEscape(opts.TargetVersion)
		}
		return map[string]string{
			"_base":                 base,
			"release-manifest.json": base + "/release-manifest.json",
			"checksums.txt":         base + "/checksums.txt",
		}, nil
	}

	apiBase := "https://api.github.com/repos/" + opts.Repo
	var rel githubRelease
	switch {
	case opts.TargetVersion != "":
		data, err := c.fetchBytes(ctx, apiBase+"/releases/tags/"+url.PathEscape(opts.TargetVersion), maxManifestBytes)
		if err != nil {
			return nil, fmt.Errorf("query GitHub release %s: %w", opts.TargetVersion, err)
		}
		if err := json.Unmarshal(data, &rel); err != nil {
			return nil, fmt.Errorf("decode GitHub release: %w", err)
		}
	case opts.Prerelease || opts.Channel == "prerelease":
		data, err := c.fetchBytes(ctx, apiBase+"/releases?per_page=10", maxManifestBytes)
		if err != nil {
			return nil, fmt.Errorf("query GitHub releases: %w", err)
		}
		var list []githubRelease
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, fmt.Errorf("decode GitHub releases: %w", err)
		}
		found := false
		for _, item := range list {
			if !item.Draft {
				rel = item
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("no published releases found")
		}
	default:
		data, err := c.fetchBytes(ctx, apiBase+"/releases/latest", maxManifestBytes)
		if err != nil {
			return nil, fmt.Errorf("query latest GitHub release: %w", err)
		}
		if err := json.Unmarshal(data, &rel); err != nil {
			return nil, fmt.Errorf("decode GitHub release: %w", err)
		}
	}

	urls := make(map[string]string, len(rel.Assets))
	for _, a := range rel.Assets {
		urls[a.Name] = a.BrowserDownloadURL
	}
	return urls, nil
}

func (c *Client) fetchBytes(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || !config.AllowedGeoURL(parsed) {
		return nil, fmt.Errorf("disallowed update URL: %s", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "proxy-updater/"+buildinfo.Version)
	req.Header.Set("Accept", "application/vnd.github+json, application/octet-stream, */*")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, parsed.Host)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response from %s exceeds limit (%d bytes)", parsed.Host, limit)
	}
	return data, nil
}

func (c *Client) downloadToFile(ctx context.Context, rawURL, dstPath string, limit int64) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || !config.AllowedGeoURL(parsed) {
		return "", fmt.Errorf("disallowed download URL: %s", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "proxy-updater/"+buildinfo.Version)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d downloading %s", resp.StatusCode, filepath.Base(dstPath))
	}
	if resp.ContentLength > limit {
		return "", fmt.Errorf("download size %d exceeds limit %d", resp.ContentLength, limit)
	}
	f, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, limit+1))
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		os.Remove(dstPath)
		return "", err
	}
	if n == 0 || n > limit {
		os.Remove(dstPath)
		return "", fmt.Errorf("invalid downloaded size: %d", n)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sha256HexBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
