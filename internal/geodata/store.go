package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"proxy.local/m0/internal/config"
)

type Dataset struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Source string `json:"source"`
}

type Pair struct {
	GeoIP   Dataset `json:"geoip"`
	GeoSite Dataset `json:"geosite"`
}

type Manifest struct {
	Current  Pair      `json:"current"`
	Previous Pair      `json:"previous"`
	Updated  time.Time `json:"updated_at,omitempty"`
}

type Store struct{ directory string }

func ForConfig(path string) Store { return Store{filepath.Join(filepath.Dir(path), "data")} }

var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var temporary = regexp.MustCompile(`^\.(download|manifest)-[0-9]+$`)

func filename(kind, hash string) string {
	if kind == "geoip" {
		return "geoip-" + hash + ".dat"
	}
	return "geosite-" + hash + ".dat"
}

func (s Store) Read() (Manifest, error) {
	file, err := os.Open(filepath.Join(s.directory, "manifest.json"))
	if os.IsNotExist(err) {
		return Manifest{}, nil
	}
	if err != nil {
		return Manifest{}, err
	}
	defer file.Close()
	var state Manifest
	reader := json.NewDecoder(io.LimitReader(file, 32<<10))
	if err := reader.Decode(&state); err != nil {
		return Manifest{}, err
	}
	var extra any
	if reader.Decode(&extra) != io.EOF {
		return Manifest{}, errors.New("invalid geo manifest trailer")
	}
	for _, pair := range []Pair{state.Current, state.Previous} {
		for kind, item := range map[string]Dataset{"geoip": pair.GeoIP, "geosite": pair.GeoSite} {
			if item != (Dataset{}) && (!digest.MatchString(item.SHA256) || item.File != filename(kind, item.SHA256) || item.Source == "") {
				return Manifest{}, errors.New("invalid geo manifest entry")
			}
		}
	}
	return state, nil
}

func (s Store) Apply(cfg config.Config, state Manifest) config.Config {
	if matches(state.Current.GeoIP, cfg.Geo.GeoIP) {
		cfg.Routing.GeoIPDB = filepath.Join(s.directory, state.Current.GeoIP.File)
	}
	if matches(state.Current.GeoSite, cfg.Geo.GeoSite) {
		cfg.DNS.GeoSiteFile = filepath.Join(s.directory, state.Current.GeoSite.File)
	}
	return cfg
}

func matches(dataset Dataset, source config.DataSource) bool {
	// Keep using the installed local version even if update settings change.
	return dataset.File != ""
}

func (s Store) Stage(ctx context.Context, cfg config.Geo, before Manifest, dialer net.Dialer) (Manifest, error) {
	if cfg.GeoIP.URL == "" && cfg.GeoSite.URL == "" {
		return before, errors.New("no geo data sources configured")
	}
	if err := os.MkdirAll(s.directory, 0700); err != nil {
		return before, err
	}
	next := before.Current
	var err error
	if cfg.GeoIP.URL != "" {
		next.GeoIP, err = s.fetch(ctx, "geoip", cfg.GeoIP, 256<<20, dialer)
		if err != nil {
			return before, fmt.Errorf("GeoIP download: %w", err)
		}
	}
	if cfg.GeoSite.URL != "" {
		next.GeoSite, err = s.fetch(ctx, "geosite", cfg.GeoSite, 64<<20, dialer)
		if err != nil {
			return before, fmt.Errorf("GEOSITE download: %w", err)
		}
	}
	if next == before.Current {
		return before, nil
	}
	return Manifest{Current: next, Updated: time.Now()}, nil
}

func (s Store) fetch(ctx context.Context, kind string, source config.DataSource, limit int64, dialer net.Dialer) (Dataset, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return Dataset{}, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialer.DialContext
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || !config.AllowedGeoURL(req.URL) ||
			(via[0].URL.Scheme == "https" && req.URL.Scheme != "https") {
			return errors.New("disallowed geo download redirect")
		}
		return nil
	}}
	response, err := client.Do(request)
	if err != nil {
		var networkError *url.Error
		if errors.As(err, &networkError) {
			err = networkError.Err
		}
		return Dataset{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > limit {
		return Dataset{}, fmt.Errorf("invalid download status or size: %d", response.StatusCode)
	}
	file, err := os.CreateTemp(s.directory, ".download-*")
	if err != nil {
		return Dataset{}, err
	}
	defer os.Remove(file.Name())
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, limit+1))
	if err != nil || size == 0 || size > limit {
		file.Close()
		if err != nil {
			return Dataset{}, err
		}
		return Dataset{}, errors.New("invalid downloaded data size")
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return Dataset{}, err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if source.SHA256 != "" && !strings.EqualFold(actual, source.SHA256) {
		return Dataset{}, errors.New("SHA-256 mismatch")
	}
	name := filename(kind, actual)
	if err := replaceFile(file.Name(), filepath.Join(s.directory, name)); err != nil {
		return Dataset{}, err
	}
	return Dataset{name, actual, source.URL}, nil
}

func (s Store) Commit(state Manifest) error {
	file, err := os.CreateTemp(s.directory, ".manifest-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := errors.Join(json.NewEncoder(file).Encode(state), file.Sync(), file.Close()); err != nil {
		return err
	}
	return replaceFile(file.Name(), filepath.Join(s.directory, "manifest.json"))
}

// Prune removes only versioned artifacts owned by the geo store.
func (s Store) Prune(state Manifest) {
	keep := map[string]bool{
		state.Current.GeoIP.File: true, state.Current.GeoSite.File: true,
	}
	entries, _ := os.ReadDir(s.directory)
	for _, entry := range entries {
		name := entry.Name()
		if keep[name] || entry.IsDir() {
			continue
		}
		if temporary.MatchString(name) {
			os.Remove(filepath.Join(s.directory, name))
			continue
		}
		if (name == "GeoIP.mmdb" || name == "geoip.dat") && state.Current.GeoIP.File != "" || name == "geosite.dat" && state.Current.GeoSite.File != "" {
			os.Remove(filepath.Join(s.directory, name))
			continue
		}
		for _, kind := range []string{"geoip", "geosite"} {
			base := strings.TrimPrefix(name, kind+"-")
			hash, _, _ := strings.Cut(base, ".")
			if digest.MatchString(hash) && name == filename(kind, hash) {
				os.Remove(filepath.Join(s.directory, name))
			}
		}
	}
}

// Remove only legacy artifacts belonging to a dataset successfully replaced in
// the new data store. Unrelated files and unupdated dataset kinds stay intact.
func (s Store) PruneLegacy(runtime string, state Manifest) {
	directory := filepath.Join(runtime, "geo")
	if filepath.Clean(directory) == filepath.Clean(s.directory) {
		return
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		for kind, current := range map[string]Dataset{"geoip": state.Current.GeoIP, "geosite": state.Current.GeoSite} {
			if current.File == "" {
				continue
			}
			name := entry.Name()
			prefix := kind + "-"
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			hash, ext, _ := strings.Cut(strings.TrimPrefix(name, prefix), ".")
			if digest.MatchString(hash) && (ext == "dat" || kind == "geoip" && ext == "mmdb") {
				os.Remove(filepath.Join(directory, name))
			}
		}
	}
}
