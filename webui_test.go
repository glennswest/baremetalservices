package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The web UI's script must post to the API on its own origin: a fetch to
// :8080 from the page on :80 is cross-origin, and with no CORS headers the
// browser hides the answer, so a wipe that worked showed "Error" (finding
// cd8c1351e130, #41).
func TestWebUIScriptSameOrigin(t *testing.T) {
	if !strings.Contains(webUIScript, "fetch('/api/disks/'") {
		t.Errorf("web UI script does not post to /api/disks/ on its own origin:\n%s", webUIScript)
	}
	for _, bad := range []string{":8080", "http://", "location.hostname"} {
		if strings.Contains(webUIScript, bad) {
			t.Errorf("web UI script still names %q (another origin):\n%s", bad, webUIScript)
		}
	}
	// The answer is shown with its HTTP status; "unknown" only with no answer.
	for _, want := range []string{"r.ok", "r.status", "outcome unknown"} {
		if !strings.Contains(webUIScript, want) {
			t.Errorf("web UI script lacks %q", want)
		}
	}
}

// The web port serves the API's handlers under /api/: what the UI posts
// reaches the same route, and its JSON answer comes back to the page.
func TestWebMuxServesAPI(t *testing.T) {
	web := newWebMux(newAPIMux())
	call := func(method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		web.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec
	}
	decode := func(path string, rec *httptest.ResponseRecorder) APIResponse {
		var r APIResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
			t.Fatalf("%s: not a JSON answer: %v: %s", path, err, rec.Body.String())
		}
		return r
	}

	rec := call(http.MethodGet, "/api/health")
	if rec.Code != http.StatusOK || decode("/api/health", rec).Status != "ok" {
		t.Errorf("/api/health: %d %s", rec.Code, rec.Body.String())
	}
	rec = call(http.MethodGet, "/api/")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/disks/wipe/{dev}") {
		t.Errorf("/api/: %d %s, want the API's endpoint list", rec.Code, rec.Body.String())
	}
	// The UI's two buttons, with sysfs pointed at an empty directory so no
	// name can reach a real disk: a bad name is refused (secure-erase 400;
	// wipe finds no such disk, 404), a missing disk is 404, and the JSON
	// error reaches the page.
	empty := t.TempDir()
	oldBlock, oldClass := sysBlockDir, sysClassBlockDir
	sysBlockDir, sysClassBlockDir = empty, empty
	defer func() { sysBlockDir, sysClassBlockDir = oldBlock, oldClass }()
	for _, c := range []struct {
		path string
		code int
	}{
		{"/api/disks/secure-erase/sda;id", http.StatusBadRequest},
		{"/api/disks/secure-erase/sdz", http.StatusNotFound},
		{"/api/disks/wipe/sda;id", http.StatusNotFound},
		{"/api/disks/wipe/sdz", http.StatusNotFound},
	} {
		rec := call(http.MethodPost, c.path)
		if rec.Code != c.code {
			t.Errorf("POST %s: %d %s, want %d", c.path, rec.Code, rec.Body.String(), c.code)
			continue
		}
		if r := decode(c.path, rec); r.Status != "error" || r.Error == "" {
			t.Errorf("POST %s: %+v, want a JSON error", c.path, r)
		}
	}
	// No CORS headers: the fix is same origin, not opening the API to
	// other sites' scripts.
	if h := call(http.MethodGet, "/api/health").Header().Get("Access-Control-Allow-Origin"); h != "" {
		t.Errorf("Access-Control-Allow-Origin: %q, want none", h)
	}
}
