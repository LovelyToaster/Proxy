package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed static/*
var staticFS embed.FS

// AssetHandler returns an http.Handler that serves embedded static assets with ETag validation.
func AssetHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	etags := buildAssetETags(sub)
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			name := strings.TrimPrefix(r.URL.Path, "/")
			if name == "" {
				name = "index.html"
			}
			if etag, ok := etags[name]; ok {
				w.Header().Set("ETag", etag)
				w.Header().Set("Cache-Control", "no-cache")
				if matchETag(r.Header.Get("If-None-Match"), etag) {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
		}
		fileServer.ServeHTTP(w, r)
	})
}

func buildAssetETags(sub fs.FS) map[string]string {
	etags := make(map[string]string)
	_ = fs.WalkDir(sub, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, readErr := fs.ReadFile(sub, path)
		if readErr != nil {
			return nil
		}
		sum := sha256.Sum256(data)
		etags[path] = `"` + hex.EncodeToString(sum[:8]) + `"`
		return nil
	})
	return etags
}

func matchETag(header, target string) bool {
	if header == "" {
		return false
	}
	for _, part := range strings.Split(header, ",") {
		candidate := strings.TrimSpace(part)
		if candidate == "*" || candidate == target || strings.TrimPrefix(candidate, "W/") == target {
			return true
		}
	}
	return false
}
