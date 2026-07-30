package route

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/component/oix"
	C "github.com/metacubex/mihomo/constant"
)

func Test_oixOptionsLifecycle(t *testing.T) {
	restore := isolateoixOptionsTest(t)
	defer restore()

	handler := oixRouter()
	if status, _ := requestoixOptions(t, handler, http.MethodPut, `{}`); status != http.StatusBadRequest {
		t.Fatalf("missing params status = %d, want %d", status, http.StatusBadRequest)
	}
	if status, _ := requestoixOptions(t, handler, http.MethodPut, `{"params":"&mode=fusion"}`); status != http.StatusBadRequest {
		t.Fatalf("invalid mode status = %d, want %d", status, http.StatusBadRequest)
	}

	status, state := requestoixOptions(t, handler, http.MethodPut, `{"params":"&mode=overseas&tfo=false&area=hk&provider=clash"}`)
	if status != http.StatusOK {
		t.Fatalf("update status = %d, want %d", status, http.StatusOK)
	}
	if state.Params != "&mode=overseas&tfo=false&area=hk" || state.Source != "file" {
		t.Fatalf("updated state = %+v", state)
	}

	status, state = requestoixOptions(t, handler, http.MethodDelete, "")
	if status != http.StatusOK {
		t.Fatalf("reset status = %d, want %d", status, http.StatusOK)
	}
	if state.Params != "" || state.Source != "default" {
		t.Fatalf("reset state = %+v", state)
	}
}

func Test_oixOptionsRejectEnvironmentOverride(t *testing.T) {
	restore := isolateoixOptionsTest(t)
	defer restore()
	t.Setenv("OIX_PARAMS", "&mode=premium")

	handler := oixRouter()
	if status, _ := requestoixOptions(t, handler, http.MethodPut, `{"params":"&mode=overseas"}`); status != http.StatusConflict {
		t.Fatalf("update status = %d, want %d", status, http.StatusConflict)
	}
	if status, _ := requestoixOptions(t, handler, http.MethodDelete, ""); status != http.StatusConflict {
		t.Fatalf("reset status = %d, want %d", status, http.StatusConflict)
	}
}

func isolateoixOptionsTest(t *testing.T) func() {
	t.Helper()
	oldHomeDir := C.Path.HomeDir()
	oldToken := oix.CurrentToken()
	C.SetHomeDir(t.TempDir())
	oix.SetToken("")
	t.Setenv("OIX_PARAMS", "")
	return func() {
		C.SetHomeDir(oldHomeDir)
		oix.SetToken(oldToken)
	}
}

func requestoixOptions(t *testing.T, handler http.Handler, method, body string) (int, oix.ParamsState) {
	t.Helper()
	request := httptest.NewRequest(method, "/options", strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	var state oix.ParamsState
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &state); err != nil {
			t.Fatal(err)
		}
	}
	return recorder.Code, state
}
