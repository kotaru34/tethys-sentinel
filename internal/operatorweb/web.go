package operatorweb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
)

const (
	archiveSHA256     = "9ae64c375e26d76d101cbdfe3db916296ff39237a5fc67bef4bf7aff99cef711"
	maxArchiveFile    = 4 << 20
	maxArchiveTotal   = 8 << 20
	maxArchiveEntries = 64
)

//go:embed operator-dist.b64.01 operator-dist.b64.02 operator-dist.b64.03 operator-dist.b64.04 operator-dist.b64.05 operator-dist.b64.06 operator-dist.b64.07 operator-dist.b64.08
var archiveParts embed.FS

type asset struct {
	body        []byte
	contentType string
	etag        string
}

type Handler struct {
	assets map[string]asset
}

func New() (*Handler, error) {
	archive, err := decodeArchive()
	if err != nil {
		return nil, err
	}
	assets, err := unpackArchive(archive)
	if err != nil {
		return nil, err
	}
	return &Handler{assets: assets}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestPath := r.URL.Path
	if requestPath == "/index.html" {
		requestPath = "/"
	}
	if requestPath == "" || requestPath[0] != '/' || path.Clean(requestPath) != requestPath || strings.Contains(requestPath, "\\") {
		http.NotFound(w, r)
		return
	}
	item, ok := h.assets[requestPath]
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", item.contentType)
	w.Header().Set("ETag", item.etag)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(item.body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(item.body)
	}
}

func decodeArchive() ([]byte, error) {
	var encoded strings.Builder
	for _, name := range []string{
		"operator-dist.b64.01",
		"operator-dist.b64.02",
		"operator-dist.b64.03",
		"operator-dist.b64.04",
		"operator-dist.b64.05",
		"operator-dist.b64.06",
		"operator-dist.b64.07",
		"operator-dist.b64.08",
	} {
		part, err := archiveParts.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read embedded operator archive part %s: %w", name, err)
		}
		encoded.WriteString(strings.TrimSpace(string(part)))
	}
	archive, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil {
		return nil, fmt.Errorf("decode embedded operator archive: %w", err)
	}
	sum := sha256.Sum256(archive)
	if hex.EncodeToString(sum[:]) != archiveSHA256 {
		return nil, errors.New("embedded operator archive digest mismatch")
	}
	return archive, nil
}

func unpackArchive(archive []byte) (map[string]asset, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open embedded operator archive: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	assets := make(map[string]asset)
	entries := 0
	total := int64(0)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read embedded operator archive: %w", err)
		}
		entries++
		if entries > maxArchiveEntries {
			return nil, errors.New("embedded operator archive has too many entries")
		}

		entryName := hdr.Name
		if hdr.Typeflag == tar.TypeDir {
			entryName = strings.TrimSuffix(entryName, "/")
		}
		clean := path.Clean(entryName)
		if clean != entryName || clean == "." || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "../") || (clean != "dist" && !strings.HasPrefix(clean, "dist/")) {
			return nil, fmt.Errorf("embedded operator archive contains unsafe path %q", hdr.Name)
		}
		if hdr.Typeflag == tar.TypeDir {
			if clean != "dist" && clean != "dist/assets" {
				return nil, fmt.Errorf("embedded operator archive contains unexpected directory %q", hdr.Name)
			}
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return nil, fmt.Errorf("embedded operator archive contains non-regular entry %q", hdr.Name)
		}
		if hdr.Size < 0 || hdr.Size > maxArchiveFile {
			return nil, fmt.Errorf("embedded operator archive file %q has invalid size", hdr.Name)
		}
		total += hdr.Size
		if total > maxArchiveTotal {
			return nil, errors.New("embedded operator archive exceeds total size limit")
		}

		urlPath, contentType, ok := archiveAsset(clean)
		if !ok {
			return nil, fmt.Errorf("embedded operator archive contains unexpected file %q", hdr.Name)
		}
		if _, exists := assets[urlPath]; exists {
			return nil, fmt.Errorf("embedded operator archive contains duplicate path %q", urlPath)
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxArchiveFile+1))
		if err != nil {
			return nil, fmt.Errorf("read embedded operator asset %q: %w", hdr.Name, err)
		}
		if int64(len(body)) != hdr.Size {
			return nil, fmt.Errorf("embedded operator asset %q size mismatch", hdr.Name)
		}
		sum := sha256.Sum256(body)
		assets[urlPath] = asset{
			body:        body,
			contentType: contentType,
			etag:        `"sha256-` + hex.EncodeToString(sum[:]) + `"`,
		}
	}

	if _, ok := assets["/"]; !ok {
		return nil, errors.New("embedded operator archive is missing dist/index.html")
	}
	if len(assets) < 3 {
		return nil, errors.New("embedded operator archive is incomplete")
	}
	return assets, nil
}

func archiveAsset(name string) (string, string, bool) {
	if name == "dist/index.html" {
		return "/", "text/html; charset=utf-8", true
	}
	if !strings.HasPrefix(name, "dist/assets/") {
		return "", "", false
	}
	assetName := strings.TrimPrefix(name, "dist")
	switch path.Ext(name) {
	case ".js":
		return assetName, "text/javascript; charset=utf-8", true
	case ".css":
		return assetName, "text/css; charset=utf-8", true
	default:
		return "", "", false
	}
}
