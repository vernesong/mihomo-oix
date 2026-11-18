package route

import (
	"io"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/profile/cachefile"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

type countedStorageBody struct {
	io.Reader
	read int
}

func (b *countedStorageBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}

func TestStorageRejectsOversizedBodyBeforeReadingItAll(t *testing.T) {
	for _, valid := range []bool{true, false} {
		payload := strings.Repeat("x", 2<<20)
		if valid {
			payload = `"` + payload + `"`
		}
		body := &countedStorageBody{Reader: strings.NewReader(payload)}
		request := httptest.NewRequest(http.MethodPut, "/oversized", body)
		response := httptest.NewRecorder()
		storageRouter().ServeHTTP(response, request)
		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("valid=%v: status=%d, want 413", valid, response.Code)
		}
		if body.read > (1<<20)+1 {
			t.Fatalf("read %d bytes from oversized request", body.read)
		}
		if got := cachefile.Cache().GetStorage("oversized"); len(got) != 0 {
			t.Fatalf("oversized request was persisted")
		}
	}
}

func TestStorageAcceptsExactLimit(t *testing.T) {
	payload := `"` + strings.Repeat("x", (1<<20)-2) + `"`
	response := httptest.NewRecorder()
	storageRouter().ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/boundary", strings.NewReader(payload)))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want 204", response.Code)
	}
	t.Cleanup(func() { cachefile.Cache().DeleteStorage("boundary") })
	if got := string(cachefile.Cache().GetStorage("boundary")); got != payload {
		t.Fatal("stored payload differs")
	}
}
