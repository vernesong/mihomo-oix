package resource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	stdhttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/common/utils"
)

func TestFetcherParsesOnceAndDiscardsOnlyUnpublishedResources(t *testing.T) {
	for _, failure := range []string{"none", "canceled", "write"} {
		t.Run(failure, func(t *testing.T) {
			server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { _, _ = w.Write([]byte("provider")) }))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "provider.yaml")
			if failure == "write" {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			vehicle := NewHTTPVehicle(server.URL, path, "", nil, time.Second, 100)
			parsed, discarded, published := 0, 0, 0
			var fetcher *Fetcher[string]
			fetcher = NewFetcher("test", 0, vehicle, nil, func(data []byte) (string, error) {
				parsed++
				if failure == "canceled" {
					_ = fetcher.Close()
				}
				return string(data), nil
			}, func(string) { published++ })
			defer fetcher.Close()
			fetcher.SetDiscard(func(string) { discarded++ })
			_, _, err := fetcher.Update()
			if parsed != 1 {
				t.Fatalf("parser called %d times", parsed)
			}
			if failure == "none" {
				if err != nil || published != 1 || discarded != 0 {
					t.Fatalf("err=%v published=%d discarded=%d", err, published, discarded)
				}
				_, _, err = fetcher.Update()
				if err != nil || parsed != 1 {
					t.Fatalf("unchanged candidate reparsed: %d, %v", parsed, err)
				}
			} else if err == nil || published != 0 || discarded != 1 {
				t.Fatalf("err=%v published=%d discarded=%d", err, published, discarded)
			}
		})
	}
}

func TestVehicleRejectsOversizeAndInvalidDataWithoutMetadata(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { _, _ = w.Write([]byte("invalid")) }))
	defer server.Close()
	for _, limit := range []int64{3, 100} {
		vehicle := NewHTTPVehicle(server.URL, filepath.Join(t.TempDir(), "provider"), "", nil, time.Second, limit)
		metadata := 0
		vehicle.SetInRead(func(_ *http.Response) { metadata++ })
		_, _, err := vehicle.ReadValidated(context.Background(), utils.HashType{}, func([]byte) error { return errors.New("bad provider") })
		if err == nil || metadata != 0 {
			t.Fatalf("err=%v metadata=%d", err, metadata)
		}
	}
}

func TestFileParserCancellationDiscardsCandidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	var fetcher *Fetcher[string]
	published, discarded := 0, 0
	fetcher = NewFetcher("test", 0, NewFileVehicle(path), nil, func(data []byte) (string, error) { _ = fetcher.Close(); return string(data), nil }, func(string) { published++ })
	fetcher.SetDiscard(func(string) { discarded++ })
	_, _, err := fetcher.Update()
	if !errors.Is(err, context.Canceled) || published != 0 || discarded != 1 {
		t.Fatalf("err=%v published=%d discarded=%d", err, published, discarded)
	}
}

func TestReadValidatedDoesNotTrustUnvalidatedDiskHash(t *testing.T) {
	body := []byte("invalid cached data")
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { _, _ = w.Write(body) }))
	defer server.Close()
	vehicle := NewHTTPVehicle(server.URL, "unused", "", nil, time.Second, 100)
	_, _, err := vehicle.ReadValidated(context.Background(), utils.MakeHash(body), func([]byte) error { return errors.New("invalid data") })
	if err == nil {
		t.Fatal("matching unvalidated disk hash bypassed validation")
	}
}

func TestUntrustedCachedDataCannotBypassValidationWith304(t *testing.T) {
	body := []byte("invalid cached data")
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
			w.WriteHeader(304)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	vehicle := NewHTTPVehicle(server.URL, "unused", "", http.Header{"If-None-Match": {`"old-bad"`}}, time.Second, 100)
	calls := 0
	_, _, err := vehicle.ReadValidated(context.Background(), utils.MakeHash(body), func([]byte) error { calls++; return errors.New("invalid data") })
	if err == nil || calls != 1 {
		t.Fatalf("err=%v validation calls=%d", err, calls)
	}
}

func TestConfiguredConditionCannotSelectAnUnrecoverable304(t *testing.T) {
	body := []byte("complete provider")
	for _, trusted := range []bool{false, true} {
		t.Run(fmt.Sprint(trusted), func(t *testing.T) {
			server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
					w.WriteHeader(304)
					return
				}
				_, _ = w.Write(body)
			}))
			defer server.Close()
			header := http.Header{"If-None-Match": {`"unrelated"`}, "If-Modified-Since": {time.Now().UTC().Format(stdhttp.TimeFormat)}}
			vehicle := NewHTTPVehicle(server.URL, "unused", "", header, time.Second, 100)
			var validate func([]byte) error
			if trusted {
				validate = func([]byte) error { return nil }
			}
			data, hash, err := vehicle.ReadValidated(context.Background(), utils.MakeHash([]byte("cached provider")), validate, trusted)
			if err != nil || string(data) != string(body) || !hash.Equal(utils.MakeHash(body)) {
				t.Fatalf("data=%q hash=%v err=%v", data, hash, err)
			}
			if header.Get("If-None-Match") == "" || header.Get("If-Modified-Since") == "" {
				t.Fatal("read mutated caller headers")
			}
		})
	}
}

type failedBundleFile struct{ fs.File }

func (f failedBundleFile) Read(p []byte) (int, error) {
	n, _ := f.File.Read(p)
	return n, io.ErrUnexpectedEOF
}

func TestInitialRejectsPartialBundleReadsBeforeParsing(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		_, _ = w.Write([]byte("complete provider"))
	}))
	defer server.Close()
	bundle := fstest.MapFS{"provider": {Data: []byte("partial provider")}}
	path := filepath.Join(t.TempDir(), "provider.yaml")
	vehicle := NewHTTPVehicle(server.URL, path, "", nil, time.Second, 100)
	calls := 0
	fetcher := NewFetcher("test", 0, vehicle, func() (fs.File, error) {
		file, err := bundle.Open("provider")
		return failedBundleFile{file}, err
	}, func(data []byte) (string, error) {
		calls++
		if string(data) != "complete provider" {
			t.Errorf("parser received partial data: %q", data)
		}
		return string(data), nil
	}, nil)
	defer fetcher.Close()
	contents, err := fetcher.Initial()
	if err != nil || contents != "complete provider" || calls != 1 {
		t.Fatalf("contents=%q err=%v parser calls=%d", contents, err, calls)
	}
	persisted, err := os.ReadFile(path)
	if err != nil || string(persisted) != contents {
		t.Fatalf("persisted=%q err=%v", persisted, err)
	}
}
