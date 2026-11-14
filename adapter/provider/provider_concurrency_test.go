package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
)

func TestProxySubscriptionMetadataConcurrentUpdate(t *testing.T) {
	const childEnv = "MIHOMO_TEST_SUBSCRIPTION_METADATA_CHILD"
	if os.Getenv(childEnv) != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestProxySubscriptionMetadataConcurrentUpdate$", "-test.count=1")
		command.Env = append(os.Environ(), childEnv+"=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("isolated metadata: %v\n%s", err, output)
		}
		return
	}
	C.SetHomeDir(t.TempDir())
	defer cachefile.Cache().Close()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("subscription-userinfo", fmt.Sprintf("upload=1; download=%d; total=100; expire=1000", requests.Add(1)))
		_, _ = w.Write([]byte("valid"))
	}))
	defer server.Close()
	provider, err := NewProxySetProvider("fixture", 0, nil, func([]byte) ([]C.Proxy, error) { return nil, nil }, resource.NewHTTPVehicle(server.URL, filepath.Join(C.Path.HomeDir(), "provider"), "", nil, time.Second, 1024), NewHealthCheck(nil, "", 0, 0, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	var work sync.WaitGroup
	var finished atomic.Bool
	work.Go(func() {
		defer finished.Store(true)
		for range 30 {
			if err := provider.Update(); err != nil {
				t.Error(err)
			}
		}
	})
	work.Go(func() {
		for !finished.Load() {
			data, err := provider.MarshalJSON()
			if err != nil {
				t.Error(err)
				continue
			}
			var snapshot providerForApi
			if err := json.Unmarshal(data, &snapshot); err != nil {
				t.Error(err)
			}
			if info := snapshot.SubscriptionInfo; info != nil && (info.Upload != 1 || info.Total != 100) {
				t.Error("invalid metadata snapshot")
			}
		}
	})
	work.Wait()
	data, err := provider.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var snapshot providerForApi
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	if info := snapshot.SubscriptionInfo; info == nil || info.Download != 30 {
		t.Fatalf("last metadata not published: %+v", info)
	}
}

func TestInlineProviderMetadataConcurrentUpdate(t *testing.T) {
	provider, err := NewInlineProvider("fixture", nil, func([]byte) ([]C.Proxy, error) { return nil, nil }, NewHealthCheck(nil, "", 0, 0, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	var work sync.WaitGroup
	work.Go(func() {
		for range 1000 {
			if err := provider.Update(); err != nil {
				t.Error(err)
			}
		}
	})
	work.Go(func() {
		for range 1000 {
			data, err := provider.MarshalJSON()
			if err != nil {
				t.Error(err)
				continue
			}
			var snapshot providerForApi
			if err := json.Unmarshal(data, &snapshot); err != nil {
				t.Error(err)
			}
			if snapshot.UpdatedAt.IsZero() || snapshot.Name != "fixture" {
				t.Error("invalid inline provider metadata")
			}
		}
	})
	work.Wait()
}
