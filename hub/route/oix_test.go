package route

import (
	"strings"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func Test_oixOptionsRouteRemoved(t *testing.T) {
	handler := oixRouter()
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		request := httptest.NewRequest(method, "/options", strings.NewReader(`{"params":"&tfo=true"}`))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s /options status = %d, want %d", method, recorder.Code, http.StatusNotFound)
		}
	}
}
