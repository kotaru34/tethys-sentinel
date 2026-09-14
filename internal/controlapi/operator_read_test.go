package controlapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/operatorview"
)

type fakeOperatorReader struct {
	overview operatorview.Overview
	err      error
	seen     operatorview.ListOptions
}

func (f *fakeOperatorReader) Overview(context.Context) (operatorview.Overview, error) {
	return f.overview, f.err
}
func (f *fakeOperatorReader) Grants(_ context.Context, options operatorview.ListOptions) (operatorview.GrantPage, error) {
	f.seen = options
	return operatorview.GrantPage{}, f.err
}
func (f *fakeOperatorReader) Grant(context.Context, string) (operatorview.GrantView, bool, error) {
	return operatorview.GrantView{}, false, f.err
}
func (f *fakeOperatorReader) Approvals(_ context.Context, options operatorview.ListOptions) (operatorview.ApprovalPage, error) {
	f.seen = options
	return operatorview.ApprovalPage{}, f.err
}
func (f *fakeOperatorReader) Jobs(_ context.Context, options operatorview.ListOptions) (operatorview.JobPage, error) {
	f.seen = options
	return operatorview.JobPage{}, f.err
}
func (f *fakeOperatorReader) Job(context.Context, string) (executionjob.Job, bool, error) {
	return executionjob.Job{}, false, f.err
}
func (f *fakeOperatorReader) Audit(_ context.Context, options operatorview.ListOptions) (operatorview.AuditPage, error) {
	f.seen = options
	return operatorview.AuditPage{}, f.err
}

func TestOperatorReadRequiresAdminAndNoStore(t *testing.T) {
	a := testAPI(t)
	reader := &fakeOperatorReader{}
	h := a.OperatorReadHandler(reader)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/overview", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("without auth status=%d", rr.Code)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("unauthorized Cache-Control=%q", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/v1/overview", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("authorized status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("authorized Cache-Control=%q", got)
	}
}

func TestOperatorReadBoundsListOptions(t *testing.T) {
	a := testAPI(t)
	reader := &fakeOperatorReader{}
	h := a.OperatorReadHandler(reader)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/jobs?limit=999&status=running&cursor=opaque", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if reader.seen.Limit != operatorview.MaxLimit || reader.seen.Status != "running" || reader.seen.Cursor != "opaque" {
		t.Fatalf("unexpected normalized options: %+v", reader.seen)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/v1/jobs?limit=wat", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid limit status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestOperatorReadDoesNotExposeInternalError(t *testing.T) {
	a := testAPI(t)
	reader := &fakeOperatorReader{err: errors.New("postgres://secret-user:secret-password@db/private")}
	h := a.OperatorReadHandler(reader)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/overview", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "secret-password") || strings.Contains(rr.Body.String(), "postgres://") {
		t.Fatalf("internal error leaked: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "operator read failed") {
		t.Fatalf("unexpected generic error: %s", rr.Body.String())
	}
}
