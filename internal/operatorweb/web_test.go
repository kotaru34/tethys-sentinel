package operatorweb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedOperatorUI(t *testing.T) {
	handler, err := New()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		method      string
		path        string
		wantStatus  int
		contentType string
		bodyNeedle  string
	}{
		{http.MethodGet, "/", http.StatusOK, "text/html; charset=utf-8", "Tethys Sentinel"},
		{http.MethodGet, "/index.html", http.StatusOK, "text/html; charset=utf-8", "/assets/index-Bma5TWeK.js"},
		{http.MethodGet, "/assets/index-Bma5TWeK.js", http.StatusOK, "text/javascript; charset=utf-8", "REVOKE ALL"},
		{http.MethodGet, "/assets/index-CLfZQTNe.css", http.StatusOK, "text/css; charset=utf-8", ".authority-banner"},
		{http.MethodHead, "/assets/index-Bma5TWeK.js", http.StatusOK, "text/javascript; charset=utf-8", ""},
		{http.MethodGet, "/does-not-exist", http.StatusNotFound, "", ""},
		{http.MethodPost, "/", http.StatusMethodNotAllowed, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
			}
			if tt.contentType != "" && rr.Header().Get("Content-Type") != tt.contentType {
				t.Fatalf("content-type=%q", rr.Header().Get("Content-Type"))
			}
			if tt.bodyNeedle != "" && !strings.Contains(rr.Body.String(), tt.bodyNeedle) {
				t.Fatalf("body does not contain %q", tt.bodyNeedle)
			}
			if tt.method == http.MethodHead && rr.Body.Len() != 0 {
				t.Fatalf("HEAD returned %d body bytes", rr.Body.Len())
			}
		})
	}
}

func TestUnpackArchiveRejectsUnsafeEntries(t *testing.T) {
	for _, tt := range []struct {
		name     string
		entry    string
		typeflag byte
	}{
		{"traversal", "dist/../escape.js", tar.TypeReg},
		{"symlink", "dist/assets/link.js", tar.TypeSymlink},
		{"unexpected file", "dist/secrets.txt", tar.TypeReg},
	} {
		t.Run(tt.name, func(t *testing.T) {
			archive := testArchive(t, tt.entry, tt.typeflag)
			if _, err := unpackArchive(archive); err == nil {
				t.Fatal("unsafe archive entry was accepted")
			}
		})
	}
}

func testArchive(t *testing.T, name string, typeflag byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("test")
	hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: typeflag}
	if typeflag == tar.TypeSymlink {
		hdr.Size = 0
		hdr.Linkname = "../../etc/passwd"
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.Size > 0 {
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
